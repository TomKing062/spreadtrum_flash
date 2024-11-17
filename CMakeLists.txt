cmake_minimum_required(VERSION 3.20)

project(spd_dump C CXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

option(WITH_LIBUSB "Build with USB1.0" ON)

# Default build type is Release
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)

set(spd_dump_srcs
    "common.c"
    "spd_dump.c"
)

if (WITH_LIBUSB) 
    set(LibUSB_LIBRARIES "usb-1.0")
endif ()

# Generate GITVER.h
execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    OUTPUT_VARIABLE GIT_VER
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND git rev-parse HEAD
    OUTPUT_VARIABLE GIT_SHA1
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Git branch: ${GIT_VER}")
message(STATUS "Git SHA1: ${GIT_SHA1}")

set(CONFIG_FILE_CONTENT "
#pragma once

#define GIT_VER \"${GIT_VER}\"
#define GIT_SHA1 \"${GIT_SHA1}\"
")

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/GITVER.h "${CONFIG_FILE_CONTENT}")

# Include generated GITVER.h dir
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(${PROJECT_NAME} ${spd_dump_srcs})
target_compile_options(${PROJECT_NAME}
    PRIVATE
    "-O2"
    "-Wall"
    "-Wextra"
    "-Wformat"
    "-Wno-unused"
    "-std=c99"
    "-pedantic"
    "-Wno-unused"
)
target_link_options(${PROJECT_NAME}
    PRIVATE
    "-s"
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
    "m"
)

if (WITH_LIBUSB)
    target_compile_definitions(
        ${PROJECT_NAME}
        PRIVATE
        "USE_LIBUSB"
    )
    target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        ${LibUSB_LIBRARIES}
    )
endif ()