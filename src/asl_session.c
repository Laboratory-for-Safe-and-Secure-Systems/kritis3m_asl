
#include <errno.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include "asl.h"
#include "asl_logging.h"
#include "asl_pkcs11.h"
#include "asl_psk.h"
#include "asl_types.h"

#include "wolfssl/options.h"

#include "wolfssl/error-ssl.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"

#define ERROR_OUT(error_code, ...)                                                                 \
        {                                                                                          \
                asl_log(ASL_LOG_LEVEL_ERR, __VA_ARGS__);                                           \
                ret = error_code;                                                                  \
                goto cleanup;                                                                      \
        }

#if defined(_WIN32) && defined(_MSC_VER)

#include <winsock2.h>

static int take_timestamp(struct timespec* ts)
{
        __int64 wintime;

        GetSystemTimeAsFileTime((FILETIME*) &wintime);

        wintime -= 116444736000000000i64;          // 1jan1601 to 1jan1970
        ts->tv_sec = wintime / 10000000i64;        // seconds
        ts->tv_nsec = wintime % 10000000i64 * 100; // nano-seconds

        return 0;
}

#else

static int take_timestamp(struct timespec* ts)
{
        return clock_gettime(CLOCK_MONOTONIC, ts);
}

#endif

#if defined(HAVE_SECRET_CALLBACK)
/* Callback function for TLS v1.3 secrets for use with Wireshark */
static int wolfssl_secret_callback(WOLFSSL* ssl, int id, const uint8_t* secret, int secretSz, void* ctx)
{
        /* In case of an error, we abort silently to make sure the handshake
         * is not aborted. */

        int i;
        const char* str = NULL;
        uint8_t random[32];
        int randomSz;
        FILE* fp = NULL;

        if (ctx == NULL)
                goto done;

        /* Open keylog file */
        fp = fopen((const char*) ctx, "a");
        if (fp == NULL)
                goto done;

        /* Get Client random (for both client and server roles) */
        randomSz = (int) wolfSSL_get_client_random(ssl, random, sizeof(random));
        if (randomSz <= 0)
                goto done;

        switch (id)
        {
        case CLIENT_EARLY_TRAFFIC_SECRET:
                str = "CLIENT_EARLY_TRAFFIC_SECRET";
                break;
        case EARLY_EXPORTER_SECRET:
                str = "EARLY_EXPORTER_SECRET";
                break;
        case CLIENT_HANDSHAKE_TRAFFIC_SECRET:
                str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
                break;
        case SERVER_HANDSHAKE_TRAFFIC_SECRET:
                str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
                break;
        case CLIENT_TRAFFIC_SECRET:
                str = "CLIENT_TRAFFIC_SECRET_0";
                break;
        case SERVER_TRAFFIC_SECRET:
                str = "SERVER_TRAFFIC_SECRET_0";
                break;
        case EXPORTER_SECRET:
                str = "EXPORTER_SECRET";
                break;
        default:
                str = "UNKNOWN";
                break;
        }

        /* Write random */
        fprintf(fp, "%s ", str);
        for (i = 0; i < (int) randomSz; i++)
                fprintf(fp, "%02x", random[i]);
        fprintf(fp, " ");

        /* Write secret */
        for (i = 0; i < secretSz; i++)
                fprintf(fp, "%02x", secret[i]);
        fprintf(fp, "\n");

done:
        if (fp != NULL)
                fclose(fp);

        return 0;
}
#endif /* HAVE_SECRET_CALLBACK */

/* Create a new session for the endpoint.
 *
 * Parameters are a pointer to a configured endpoint and the socket fd of the underlying
 * network connection.
 *
 * Return value is a pointer to the newly created session or NULL in case of an error
 * (error message is logged to the console).
 */
asl_session* asl_create_session(asl_endpoint* endpoint, int socket_fd)
{
        int ret = 0;

        if (endpoint == NULL)
                return NULL;

        /* Create a new session object */
        asl_session* new_session = malloc(sizeof(asl_session));
        if (new_session == NULL)
                ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for new WolfSSL session");

        /* Create a new TLS session */
        new_session->wolfssl_session = wolfSSL_new(endpoint->wolfssl_context);
        if (new_session->wolfssl_session == NULL)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to create a new WolfSSL session");

        /* Initialize the remaining attributes */
        new_session->state = CONNECTION_STATE_NOT_CONNECTED;
        new_session->endpoint = endpoint;
        new_session->handshake_metrics.tx_bytes = 0;
        new_session->handshake_metrics.rx_bytes = 0;

#ifndef NO_PSK
        wolfSSL_set_psk_callback_ctx(new_session->wolfssl_session, new_session);
#endif

        /* Store the socket fd */
        wolfSSL_set_fd(new_session->wolfssl_session, socket_fd);

#if defined(WOLFSSL_USER_IO)
        /* Store a pointer to our session object to get access to the metrics from
         * the read and write callback. This must be done AFTER the call to
         * wolfSSL_set_fd() as this method overwrites the ctx variables.
         */
        wolfSSL_SetIOReadCtx(new_session->wolfssl_session, new_session);
        wolfSSL_SetIOWriteCtx(new_session->wolfssl_session, new_session);
#endif

#if defined(HAVE_SECRET_CALLBACK)
        if (endpoint->keylog_file != NULL && *endpoint->keylog_file != '\0')
        {
                /* required for getting random used */
                wolfSSL_KeepArrays(new_session->wolfssl_session);

                /* optional logging for wireshark */
                wolfSSL_set_tls13_secret_cb(new_session->wolfssl_session,
                                            wolfssl_secret_callback,
                                            (void*) endpoint->keylog_file);
        }
#endif

        return new_session;

cleanup:
        asl_free_session(new_session);

        return NULL;
}

/* Perform the TLS handshake for a newly created session.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged
 * to the console). In case the handshake is not done yet and you have to call the method
 * again when new data from the peer is present, ASL_WANT_READ is returned.
 */
int asl_handshake(asl_session* session)
{
        int ret = -1;

        if (session == NULL)
                return ASL_ARGUMENT_ERROR;

        /* Obtain handshake metrics */
        if (session->state == CONNECTION_STATE_NOT_CONNECTED)
        {
                session->state = CONNECTION_STATE_HANDSHAKE;

                /* Get start time */
                if (take_timestamp(&session->handshake_metrics.start_time) != 0)
                        asl_log(ASL_LOG_LEVEL_WRN, "Error starting handshake timer");
        }

        while (ret != 0)
        {
                ret = wolfSSL_negotiate(session->wolfssl_session);

                if (ret == WOLFSSL_SUCCESS)
                {
                        session->state = CONNECTION_STATE_CONNECTED;

                        /* Get end time */
                        if (take_timestamp(&session->handshake_metrics.end_time) != 0)
                                asl_log(ASL_LOG_LEVEL_WRN, "Error stopping handshake timer");

#ifdef HAVE_SECRET_CALLBACK
                        wolfSSL_FreeArrays(session->wolfssl_session);
#endif

                        ret = ASL_SUCCESS;
                        break;
                }
                else
                {
                        ret = wolfSSL_get_error(session->wolfssl_session, ret);

                        if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                ret = ASL_WANT_READ;
                                break;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                /* Unable to write data, indicate to higher layers */
                                ret = ASL_WANT_WRITE;
                                break;
                        }
                        else
                        {
                                char errMsg[WOLFSSL_MAX_ERROR_SZ];
                                wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

                                asl_log(ASL_LOG_LEVEL_ERR, "TLS handshake failed: %s", errMsg);
                                ret = ASL_INTERNAL_ERROR;
                                break;
                        }
                }
        }

        return ret;
}

/* Receive new data from the TLS peer.
 *
 * Returns the number of received bytes on success, negative error code on failure
 * (error message is logged to the console). In case we have not received enough data
 * to decode the TLS record, ASL_WANT_READ is returned. In that case, you have to call
 * the method again when new data from the peer is present.
 */
int asl_receive(asl_session* session, uint8_t* buffer, int max_size)
{
        uint8_t* tmp = buffer;
        int bytes_read = 0;

        if (session == NULL)
        {
                return ASL_ARGUMENT_ERROR;
        }

        while (1)
        {
                int ret = wolfSSL_read(session->wolfssl_session, tmp, max_size - bytes_read);

                if (ret <= 0)
                {
                        ret = wolfSSL_get_error(session->wolfssl_session, ret);

                        if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                /* Unable to write data, indicate to higher layers */
                                bytes_read = ASL_WANT_WRITE;
                                break;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                /* No more data, we have to asynchronously wait for new */
                                bytes_read = ASL_WANT_READ;
                                break;
                        }
                        else if ((ret == WOLFSSL_ERROR_ZERO_RETURN) || (ret == WOLFSSL_ERROR_SYSCALL) ||
                                 (ret == SOCKET_PEER_CLOSED_E) || (ret == SOCKET_ERROR_E))
                        {
                                bytes_read = ASL_CONN_CLOSED;
                                break;
                        }
                        else
                        {
                                char errMsg[WOLFSSL_MAX_ERROR_SZ];
                                wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

                                asl_log(ASL_LOG_LEVEL_ERR, "wolfSSL_read returned %d: %s", ret, errMsg);
                                bytes_read = ASL_INTERNAL_ERROR;
                                break;
                        }
                }

                /* It is technically possible to call asl_receive() and asl_send() without
                 * performing the TLS handshake via asl_handshake(). Although this is
                 * discouraged, we do not prevent it. However, we have to properly handle
                 * internal state here, mainly to free any handshake buffers. As soon as
                 * wolfssl_read() or wolfssl_write() return a successful return code, we are
                 * sure to finished the TLS handshake. Hence, we can update the state here
                 * safely.
                 */
                if (session->state != CONNECTION_STATE_CONNECTED)
                {
                        session->state = CONNECTION_STATE_CONNECTED;

#ifdef HAVE_SECRET_CALLBACK
                        wolfSSL_FreeArrays(session->wolfssl_session);
#endif
                }

                tmp += ret;
                bytes_read += ret;

                break;
        }

        return bytes_read;
}

/* Send data to the TLS remote peer.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged
 * to the console). In case we cannot write the data in one call, ASL_WANT_WRITE is
 * returned, indicating that you have to call the method again (with the same data!) once
 * the socket is writable again.
 */
int asl_send(asl_session* session, uint8_t const* buffer, int size)
{
        uint8_t const* tmp = buffer;
        int ret = ASL_SUCCESS;

        if (session == NULL)
        {
                return ASL_ARGUMENT_ERROR;
        }

        while (size > 0)
        {
                ret = wolfSSL_write(session->wolfssl_session, tmp, size);

                if (ret > 0)
                {
                        /* We successfully sent data */
                        size -= ret;
                        tmp += ret;
                        ret = ASL_SUCCESS;

                        /* It is technically possible to call asl_receive() and asl_send()
                         * without performing the TLS handshake via asl_handshake().
                         * Although this is discouraged, we do not prevent it. However, we
                         * have to properly handle internal state here, mainly to free any
                         * handshake buffers. As soon as wolfssl_read() or wolfssl_write()
                         * return a successful return code, we are sure to finished the TLS
                         * handshake. Hence, we can update the state here safely.
                         */
                        if (session->state != CONNECTION_STATE_CONNECTED)
                        {
                                session->state = CONNECTION_STATE_CONNECTED;

#ifdef HAVE_SECRET_CALLBACK
                                wolfSSL_FreeArrays(session->wolfssl_session);
#endif
                        }
                }
                else
                {
                        ret = wolfSSL_get_error(session->wolfssl_session, ret);

                        if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                /* We have to first receive data from the peer. In this case,
                                 * we discard the data and continue reading data from it. */
                                ret = ASL_WANT_READ;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                /* We have more to write, but obviously the socket can't
                                 * handle it right now. */
                                ret = ASL_WANT_WRITE;
                        }
                        else if ((ret == WOLFSSL_ERROR_SYSCALL) || (ret == SOCKET_PEER_CLOSED_E) ||
                                 (ret == SOCKET_ERROR_E))
                        {
                                ret = ASL_CONN_CLOSED;
                        }
                        else
                        {
                                if (ret != 0)
                                {
                                        char errMsg[WOLFSSL_MAX_ERROR_SZ];
                                        wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

                                        asl_log(ASL_LOG_LEVEL_ERR,
                                                "wolfSSL_write returned %d: %s",
                                                ret,
                                                errMsg);
                                }
                                ret = ASL_INTERNAL_ERROR;
                        }

                        break;
                }
        }

        return ret;
}

/* Get the peer certificate (in DER encoding).
 *
 * The peer certificate is copied into the provided buffer. The buffer must be large enough
 * to hold the certificate (on entry, *size must contain the buffer size). The size in bytes
 * of the certificate is stored in *size.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged
 * to the console).
 */
int asl_get_peer_certificate(asl_session* session, uint8_t* buffer, size_t* size)
{
#ifdef KEEP_PEER_CERT
        int ret = 0;
        WOLFSSL_X509* cert = NULL;
        uint8_t const* der_buf = NULL;
        int der_size = 0;

        if ((session == NULL) || (buffer == NULL) || (size == NULL))
                return ASL_ARGUMENT_ERROR;

        /* Get the certificate */
        cert = wolfSSL_get_peer_certificate(session->wolfssl_session);
        if (cert == NULL)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to get peer certificate");

        /* Get underlying buffer and size */
        der_buf = wolfSSL_X509_get_der(cert, &der_size);

        if (*size < der_size)
                ERROR_OUT(ASL_ARGUMENT_ERROR, "Buffer too small for certificate");

        /* Copy the certificate into the buffer */
        memcpy(buffer, der_buf, der_size);
        *size = der_size;

        return ASL_SUCCESS;

cleanup:
        if (cert != NULL)
                wolfSSL_X509_free(cert);

        return ret;
#else
        asl_log(ASL_LOG_LEVEL_ERR, "Peer certificate retrieval is disabled");
        return ASL_INTERNAL_ERROR;
#endif
}

/* Get metics of the handshake. */
asl_handshake_metrics asl_get_handshake_metrics(asl_session* session)
{
        asl_handshake_metrics metrics = {.duration_us = 0.0, .tx_bytes = 0, .rx_bytes = 0};

        if (session != NULL)
        {
                struct timespec* start_time = &session->handshake_metrics.start_time;
                struct timespec* end_time = &session->handshake_metrics.end_time;

                metrics.duration_us = (end_time->tv_sec - start_time->tv_sec) * 1000000.0 +
                                      (end_time->tv_nsec - start_time->tv_nsec) / 1000.0;
                metrics.tx_bytes = session->handshake_metrics.tx_bytes;
                metrics.rx_bytes = session->handshake_metrics.rx_bytes;
        }

        return metrics;
}

/* Close the connection of the active session */
void asl_close_session(asl_session* session)
{
        if (session != NULL)
        {
                wolfSSL_shutdown(session->wolfssl_session);
                session->state = CONNECTION_STATE_NOT_CONNECTED;
        }
}

/* Free ressources of a session. */
void asl_free_session(asl_session* session)
{
        if (session != NULL)
        {
                if (session->wolfssl_session != NULL)
                        wolfSSL_free(session->wolfssl_session);

                free(session);
        }
}

/* Access to the internal WolfSSL API */
#if defined(KRITIS3M_ASL_INTERNAL_API)

/* Get the internal WolfSSL session object */
WOLFSSL* asl_get_wolfssl_session(asl_session* session)
{
        if (session == NULL)
                return NULL;

        return session->wolfssl_session;
}

#endif
