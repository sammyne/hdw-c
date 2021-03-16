cmake_minimum_required(VERSION 3.16)

file(GLOB srcs *.cxx)

add_library(hdwallet STATIC ${srcs})

add_custom_target(world
  COMMAND echo "srcs '${srcs}'"
)