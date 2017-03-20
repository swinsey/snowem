cmake_minimum_required(VERSION 3.0)
project(videocall)

include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

SET(CMAKE_C_COMPILER ${CMAKE_CXX_COMPILER})

#file(GLOB sources_include include/*.h)
file(GLOB sources *.c *.h)

add_library(videocall SHARED ${sources})

# Just for example add some compiler flags.
target_compile_options(videocall PUBLIC -g -Wall)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(videocall PUBLIC . ../../ ../../core ../../ice ../../jsoncpp)


target_link_libraries(videocall PUBLIC
)

install(TARGETS videocall DESTINATION bin)
set(CPACK_PACKAGE_NAME "videocall")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)

