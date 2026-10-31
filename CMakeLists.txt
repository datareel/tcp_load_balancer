# DRLB TCP load balancer. The Makefile is the main build; this file is
# for IDEs and out of tree builds:
#   cmake -S . -B build-cmake && cmake --build build-cmake
cmake_minimum_required(VERSION 3.16)
project(drlb_server VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

file(GLOB DRLB_SOURCES src/*.cpp)
add_executable(drlb_server ${DRLB_SOURCES})
target_compile_options(drlb_server PRIVATE -Wall -Wextra)
target_link_libraries(drlb_server PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(drlb_server PRIVATE stdc++fs) # GCC 8 (RHEL 8)
endif()

install(TARGETS drlb_server RUNTIME DESTINATION sbin)
install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink drlb_server \$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/sbin/drlb_ssl_server)")
