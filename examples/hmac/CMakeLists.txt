cmake_minimum_required(VERSION 3.16)

set(app hmac)

add_executable(${app} main.cxx)
target_link_libraries(${app} mbedtls)
