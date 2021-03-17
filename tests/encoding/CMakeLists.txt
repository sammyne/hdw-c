cmake_minimum_required(VERSION 3.16)

set(app encoding)

add_executable(${app} main.cxx)
target_link_libraries(${app} mbedtls hdw)
add_dependencies(${app} hdw)

add_custom_target(test_${app} ALL
  COMMAND ./${app}
  DEPENDS ${app}
  COMMENT "testing ${app}"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)