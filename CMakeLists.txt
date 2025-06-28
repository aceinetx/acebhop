cmake_minimum_required(VERSION 3.10)
project("acebhop")

set(CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "./*.cc")

add_library("acebhop" SHARED ${SOURCES})