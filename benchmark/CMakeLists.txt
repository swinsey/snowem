cmake_minimum_required(VERSION 3.0)
project(robot)

include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

add_subdirectory(cicero)
add_subdirectory(wslay)

#SET(CMAKE_C_COMPILER ${CMAKE_CXX_COMPILER})

#file(GLOB sources_include include/*.h)
file(GLOB sources benchmark.cpp wsclient.cpp wsclient.h validation.c validation.h 
                  dtls.h dtls.cpp util.h util.c ../jsoncpp/*.cpp ../jsoncpp/json/*.h
                  sdp.c sdp.h)
#file(GLOB sources worked.c validation.c validation.h)

add_executable(robot ${sources})

# Just for example add some compiler flags.
target_compile_options(robot PUBLIC -g -Wall)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(robot PUBLIC . ../../ ../../core ../../ice ../../jsoncpp)
include_directories(${Boost_INCLUDE_DIR})

find_package(OpenSSL)
if (${OPENSSL_FOUND})
   target_include_directories(robot PUBLIC ${OPENSSL_INCLUDE_DIR})
   MESSAGE(STATUS OPENSSLLib ${OPENSSL_LIBRARIES})
else (${OPENSSL_FOUND})
   MESSAGE(FATAL_ERROR OpenSSL not found)
endif (${OPENSSL_FOUND})

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindNettle.cmake)
if (${NETTLE_FOUND})
   target_include_directories(robot PUBLIC ${NETTLE_INCLUDE_DIRS})
   MESSAGE(STATUS NETTLEDir ${NETTLE_INCLUDE_DIRS})
   MESSAGE(STATUS NETTLELib ${NETTLE_LIBRARIES})
else ()
   MESSAGE(FATAL_ERROR NETTLE not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindLibEvent.cmake)
if (${EVENT_FOUND})
#   target_include_directories(robot PUBLIC ${EVENT_INCLUDE_DIRS} ${EVENT_OPENSSL_INCLUDE_DIR})
   MESSAGE(STATUS EVENTDir ${EVENT_INCLUDE_DIRS})
   MESSAGE(STATUS EVENTLib ${EVENT_LIBRARIES})
  MESSAGE(STATUS OPENSSLEVENTLib ${EVENT_OPENSSL_LIBRARIES})
else ()
   MESSAGE(FATAL_ERROR EVENT not found)
endif ()
target_include_directories(robot PUBLIC ${CMAKE_SOURCE_DIR}/include ../jsoncpp)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSRTP.cmake)
if (${SRTP_FOUND})
   target_include_directories(robot PUBLIC ${SRTP_INCLUDE_DIRS})
   MESSAGE(STATUS SRTPDir ${SRTP_INCLUDE_DIRS})
   MESSAGE(STATUS SRTPLib ${SRTP_LIBRARIES})
else ()
   MESSAGE(FATAL_ERROR SRTP not found)
endif ()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSofiaSipUa.cmake)
if (${SOFIASIPUA_FOUND})
   target_include_directories(robot PUBLIC ${SOFIASIPUA_INCLUDE_DIR})
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SOFIASIPUA_CPPFLAGS}")
else (${SOFIASIPUA_FOUND})
   MESSAGE(FATAL_ERROR SofiaSipUa Not Found)
endif (${SOFIASIPUA_FOUND})




find_package(Boost COMPONENTS system random regex thread chrono REQUIRED)

target_link_libraries(robot PUBLIC
  cicero
  wslay
  ${OPENSSL_LIBRARIES}
  ${NETTLE_LIBRARIES}
  ${SRTP_LIBRARIES}
  ${SOFIASIPUA_LIBRARIES}
  #${EVENT_LIBRARIES}
  #${EVENT_OPENSSL_LIBRARIES}
  ${CMAKE_SOURCE_DIR}/lib/libevent.a
  ${CMAKE_SOURCE_DIR}/lib/libevent_openssl.a
)

install(TARGETS robot DESTINATION bin)
set(CPACK_PACKAGE_NAME "ice robot")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_MONOLITHIC_INSTALL 1)
include(CPack)

