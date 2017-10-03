cmake_minimum_required(VERSION 3.0) # setting this is required
project(snowem)            # this sets the project name

include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

#add_subdirectory(cicero)
add_subdirectory(cice)
add_subdirectory(wslay)
add_subdirectory(modules/videocall)
#add_subdirectory(modules/democall)

SET(CMAKE_C_COMPILER ${CMAKE_CXX_COMPILER})

## file globbing ##############################################################
#file(GLOB sources_include include/*.h)
file(GLOB sources 
       core/*.c core/*.cpp core/*.h 
       ice/*.c ice/*.h 
       #modules/*.c modules/*.h 
       jsoncpp/*.cpp jsoncpp/json/*.h
       websocket/*.c websocket/*.h)
file(GLOB c_sources core/*.c ice/*.c websocket/*.c)
SET_SOURCE_FILES_PROPERTIES(${c_source} PROPERTIES LANGUAGE CXX)

## target definitions #########################################################
#add_executable(example ${sources} ${data})
add_executable(snowem ${sources})

# Just for example add some compiler flags.
target_compile_options(snowem PUBLIC -g -Wall)
#add_definitions(-DBASE_FILE_NAME="$(<F)")

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(snowem PUBLIC . jsoncpp core ice modules)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindDL.cmake)
if (${DL_FOUND})
   target_include_directories(snowem PUBLIC ${DL_INCLUDE_DIRS})
   MESSAGE(STATUS "dl include: ${DL_INCLUDE_DIRS}")
   MESSAGE(STATUS "dl lib: ${DL_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR "DL not found")
endif ()

find_package(OpenSSL)
if (${OPENSSL_FOUND})
   target_include_directories(snowem PUBLIC ${OPENSSL_INCLUDE_DIR})
else (${OPENSSL_FOUND})
   MESSAGE(FATAL_ERROR OpenSSL not found)
endif (${OPENSSL_FOUND})

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindLibEvent.cmake)
if (${EVENT_FOUND})
   target_include_directories(snowem PUBLIC ${EVENT_INCLUDE_DIRS})
   MESSAGE(STATUS "libevent include: ${EVENT_INCLUDE_DIRS}")
   MESSAGE(STATUS "libevent lib:  ${EVENT_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR EVENT not found)
endif ()


include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSofiaSipUa.cmake)
if (${SOFIASIPUA_FOUND})
   target_include_directories(snowem PUBLIC ${SOFIASIPUA_INCLUDE_DIR})
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SOFIASIPUA_CPPFLAGS}")
else (${SOFIASIPUA_FOUND})
   MESSAGE(FATAL_ERROR SofiaSipUa Not Found)
endif (${SOFIASIPUA_FOUND})


include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSRTP.cmake)
if (${SRTP_FOUND})
   target_include_directories(snowem PUBLIC ${SRTP_INCLUDE_DIRS})
   MESSAGE(STATUS "srtp include: ${SRTP_INCLUDE_DIRS}")
   MESSAGE(STATUS "srtp lib: ${SRTP_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR SRTP not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindJansson.cmake)
if (${JANSSON_FOUND})
   target_include_directories(snowem PUBLIC ${JANSSON_INCLUDE_DIRS})
   MESSAGE(STATUS "jansson include: ${JANSSON_INCLUDE_DIRS}")
   MESSAGE(STATUS "jansson lib:  ${JANSSON_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR JANSSON not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindNettle.cmake)
if (${NETTLE_FOUND})
   target_include_directories(snowem PUBLIC ${NETTLE_INCLUDE_DIRS})
   MESSAGE(STATUS "nettle include: ${NETTLE_INCLUDE_DIRS}")
   MESSAGE(STATUS "nettle lib: ${NETTLE_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR NETTLE not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindConfig.cmake)
if (${CONFIG_FOUND})
   target_include_directories(snowem PUBLIC ${CONFIG_INCLUDE_DIRS})
   MESSAGE(STATUS "libconfig include: ${CONFIG_INCLUDE_DIRS}")
   MESSAGE(STATUS "libconfig lib: ${CONFIG_LIBRARIES}")
else ()
   MESSAGE(FATAL_ERROR LIBCONFIG not found)
endif ()




#include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindFFmpeg.cmake)
#if (${FFMPEG_FOUND})
#   target_include_directories(snowem PUBLIC ${FFMPEG_INCLUDE_DIR})
#else (${FFMPEG_FOUND})
#   MESSAGE(FATAL_ERROR FFMPEG not found)
#endif (${FFMPEG_FOUND})


target_link_libraries(snowem PUBLIC
  cice
  wslay
  ${DL_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${EVENT_LIBRARIES}
  ${EVENT_OPENSSL_LIBRARIES}
  ${SOFIASIPUA_LIBRARIES}
  ${SRTP_LIBRARIES}
  ${JANSSON_LIBRARIES}
  ${NETTLE_LIBRARIES}
  ${CONFIG_LIBRARIES}
)

## packaging ##################################################################
# All install commands get the same destination. this allows us to use paths
# relative to the executable.
install(TARGETS snowem DESTINATION bin)

# Now comes everything we need, to create a package
# there are a lot more variables you can set, and some
# you need to set for some package types, but we want to
# be minimal here.
set(CPACK_PACKAGE_NAME "snowem")
set(CPACK_PACKAGE_VERSION "1.0.0")

# We don't want to split our program up into several incomplete pieces.
set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)

