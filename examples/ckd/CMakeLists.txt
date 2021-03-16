cmake_minimum_required(VERSION 3.16)

add_executable(ckd app.cxx)
target_link_libraries(ckd mbedtls hdwallet)
add_dependencies(ckd hdwallet)
