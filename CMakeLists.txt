cmake_minimum_required(VERSION 3.16)

project(hdw-c C)

option(ENABLE_TESTING "enable testing" Off)

set(CMAKE_C_STANDARD 11)

include(FetchContent)
include(cmake/vendor.cmake)

include_directories(${mbedtlsDir}/include)

include_directories(${PROJECT_SOURCE_DIR}/include)

add_subdirectory(src)

if(WITH_EXAMPLE)
  add_subdirectory(examples)
endif()

if(WITH_TEST) 
  add_subdirectory(tests)
endif()

