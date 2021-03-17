cmake_minimum_required(VERSION 3.16)

file(GLOB srcs *.c)

add_library(hdw STATIC ${srcs})

add_custom_target(world
  COMMAND echo "srcs '${srcs}'"
)