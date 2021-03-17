cmake_minimum_required(VERSION 3.16)

add_executable(ckd main.c)
target_link_libraries(ckd mbedtls hdw)
add_dependencies(ckd hdw)
