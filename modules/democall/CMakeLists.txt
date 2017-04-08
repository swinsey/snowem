cmake_minimum_required(VERSION 3.0)
project(democall)

include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

SET(CMAKE_C_COMPILER ${CMAKE_CXX_COMPILER})

#file(GLOB sources_include include/*.h)
file(GLOB sources *.c *.h)

add_library(democall SHARED ${sources})

# Just for example add some compiler flags.
target_compile_options(democall PUBLIC -g -Wall)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(democall PUBLIC . ../../ ../../core ../../ice ../../jsoncpp)


target_link_libraries(democall PUBLIC
)

install(TARGETS democall DESTINATION bin)
set(CPACK_PACKAGE_NAME "videocall")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)

