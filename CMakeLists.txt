cmake_minimum_required(VERSION 3.10)
include(FindPackageHandleStandardArgs)

project(sucks)
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_SOURCE_DIR}")
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

find_package(LIBSSH REQUIRED)
find_package(LIBCONFIG REQUIRED)

file(GLOB SOURCES "*.c")

include_directories(
    ${LIBSSH_INCLUDE_DIRS}
    ${LIBCONFIG_INCLUDE_DIRS}
)

link_libraries(
    ${LIBSSH_LIBRARIES}
    ${LIBCONFIG_LIBRARIES}
)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config.cfg
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_executable(sucks ${SOURCES})