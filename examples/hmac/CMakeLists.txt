cmake_minimum_required(VERSION 3.16)

add_executable(app app.cxx)
target_link_libraries(app mbedtls)
