cmake_minimum_required(VERSION 3.1.0)

# gmlite version
set(GMLITE_VERSION_MAJOR 0)
set(GMLITE_VERSION_MINOR 1)
set(GMLITE_VERSION_PATCH 0)
set(GMLITE_VERSION "${GMLITE_VERSION_MAJOR}.${GMLITE_VERSION_MINOR}.${GMLITE_VERSION_PATCH}")

# TODO : use SMX_NO_ASM macro in source code
option(SM2_NO_ASM "don't use sm2 assembly code" OFF)
option(SM3_NO_ASM "don't use sm3 assembly code" OFF)
option(SM4_NO_ASM "don't use sm4 assembly code" OFF)
option(SM9_NO_ASM "don't use sm9 assembly code" OFF)
option(PAIRING_NO_ASM "don't use pairing assembly code" OFF)
option(ENABLE_STATIC "build static library" ON)
option(ENABLE_SHARED "build shared library" ON)
option(GML_NO_SM9 "don't compile sm9" OFF)
if(${ENABLE_STATIC} STREQUAL "OFF")
    unset(${ENABLE_STATIC})
endif()

if(${ENABLE_SHARED} STREQUAL "OFF")
    unset(${ENABLE_SHARED})
endif()

if((NOT ENABLE_STATIC) AND (NOT ENABLE_SHARED))
    message(FATAL_ERROR "static or shared or both")  
endif()

# default : release
if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

# Disable in-source builds
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message("BUILD_DIR : ${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed.")
endif("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")

include(CheckTypeSize)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckCSourceRuns)

# debug and release
if(NOT CMAKE_CONFIGURATION_TYPES)
    get_property(HAVE_MULTI_CONFIG_GENERATOR GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
    # Set default configuration types for multi-config generators
    if(HAVE_MULTI_CONFIG_GENERATOR)
        set(CMAKE_CONFIGURATION_TYPES "Release;Debug")
    endif()
endif()

# directory path
set(PROJECT_ABS_TOP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
message("ABS_SOURCE_DIR : ${CMAKE_CURRENT_SOURCE_DIR}")
set(GMLITE_DIR ${PROJECT_ABS_TOP_DIR}/gmlite)
message("GMLITE dir : ${GMLITE_DIR}")

find_program(PERL perl)
if(NOT PERL)
    message(FATAL_ERROR "perl not found")
endif()
message("${PERL}")

project(gmlite LANGUAGES C ASM)

set(CMAKE_C_FLAGS "-Wall")
# c compiler
if (CMAKE_C_COMPILER MATCHES ".*clang")
  # using regular Clang or AppleClang

elseif (CMAKE_C_COMPILER_ID STREQUAL "GNU")
  # using GCC

elseif (CMAKE_C_COMPILER_ID STREQUAL "Intel")
  # using Intel C++

elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
  # using Visual Studio C++
    ENABLE_LANGUAGE(ASM_MASM)
endif()

# thread
find_package(Threads)
if(CMAKE_USE_PTHREADS_INIT)
    set(HAVE_PTHREAD 1)
elseif(CMAKE_USE_WIN32_THREADS_INIT)
    set(HAVE_WIN32_THREAD 1)
else()
    set(HAVE_NO_THREAD 1)
endif()

# ARCH
message("host : ${CMAKE_HOST_SYSTEM_PROCESSOR}")
if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "AMD64")
    set(x86_64 1)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86")
    set(x86 1)
endif()

# asm
if(MSVC)
    message("MSVC")
    set(FLAVOUR masm)
    add_definitions("/W3 /D_CRT_SECURE_NO_WARNINGS /wd4005 /wd4820 /wd4996 /wd4267 /wd4244 /wd4477 /nologo")
else()
    if(CYGWIN OR MINGW)
        set(FLAVOUR mingw64)
    else()
        set(FLAVOUR )
    endif()
endif()

# bits
math(EXPR BITS "8*${CMAKE_SIZEOF_VOID_P}")

# sizeof long
check_type_size("long" LONG_SIZE)
if(BITS EQUAL 32)
    message(FATAL_ERROR "32 bit OS is not supported now :(")  
    set(THIRTY_TWO_BIT 1)   # config, 32bit 
elseif((BITS EQUAL 64) AND (LONG_SIZE EQUAL 8)) 
    set(SIXTY_FOUR_BIT_LONG 1)   # config, 64bit, sizeof(long) = 8
else()
    set(SIXTY_FOUR_BIT 1)   # config, 64bit, sizeof(long) = 4
endif()

# lib subfix
if(WIN32)
    set(OUTPUT_DIRECTORY_STATIC ${PROJECT_ABS_TOP_DIR}/bin/$<CONFIG>/static)
    set(OUTPUT_DIRECTORY_SHARED ${PROJECT_ABS_TOP_DIR}/bin/$<CONFIG>/shared)
    if(NOT DEFINED CMAKE_DEBUG_POSTFIX)
        set(CMAKE_DEBUG_POSTFIX "_d")
    endif()
else()
    set(OUTPUT_DIRECTORY ${PROJECT_ABS_TOP_DIR}/bin/$<CONFIG>)
endif()

check_include_files(immintrin.h HAVE_IMMINTRIN_H)
check_include_files(alloca.h HAVE_ALLOCA_H)
check_include_files(sys/mman.h HAVE_SYS_MMAN_H)

# endianess 
include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
    set(ORDER 0) # config
else()
    set(ORDER 1) # config
endif()
set(ENDIANESS "O.O") # config

enable_testing()
add_subdirectory(gmlite)
add_subdirectory(speed)
add_subdirectory(test)