cmake_minimum_required(VERSION 3.16)

project(hdwallet-c CXX)

option(ENABLE_TESTING "enable testing" Off)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
include(cmake/vendor.cmake)

include_directories(${mbedtlsDir}/include)
link_directories(${mbedtlsBinDir}/library)

include_directories(${PROJECT_SOURCE_DIR}/include/hdw)
include_directories(${PROJECT_SOURCE_DIR}/include/internal)

add_subdirectory(src)

add_subdirectory(examples)

if(ENABLE_TESTING) 
  add_subdirectory(tests)
endif()

