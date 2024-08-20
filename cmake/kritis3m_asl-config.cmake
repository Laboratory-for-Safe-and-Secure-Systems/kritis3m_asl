include(CMakeFindDependencyMacro)

get_filename_component(SELF_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

find_dependency(Threads)
find_dependency(liboqs)
find_dependency(wolfssl)

include(${SELF_DIR}/kritis3m_asl-export.cmake)
