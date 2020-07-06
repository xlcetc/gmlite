cmake_minimum_required(VERSION 3.1.0)

# header file directory
include_directories(${PROJECT_ABS_TOP_DIR}/)
include_directories(${PROJECT_ABS_TOP_DIR}/include/)
include_directories(${GMLITE_DIR}/include/)

SET(TEST_HEADER
    ${PROJECT_ABS_TOP_DIR}/test/test.h
)

set(TEST_SRC
    simple_thread.h
    simple_thread.c
    test.c
    ${TEST_HEADER}
)

add_executable(modinv_test modinv_test.c ${TEST_SRC})
add_test(MODINV_TEST modinv_test)

add_executable(padding_test padding_test.c ${TEST_SRC})
add_test(PADDING_TEST padding_test)

add_executable(pairing_test pairing_test.c ${TEST_SRC})
add_test(PAIRING_TEST pairing_test)

add_executable(secure_mem_test secure_mem_test.c ${TEST_SRC})
add_test(SECURE_MEMORY_TEST secure_mem_test)

add_executable(sm2_test sm2_test.c ${TEST_SRC})
add_test(SM2_TEST sm2_test)

add_executable(sm3_test sm3_test.c ${TEST_SRC})
add_test(SM3_TEST sm3_test)

add_executable(sm4_test sm4_test.c ${TEST_SRC})
add_test(SM4_TEST sm4_test)

add_executable(sm9_test sm9_test.c ${PROJECT_ABS_TOP_DIR}/gmlite/sm9/sm9_lib.c ${TEST_SRC})
add_test(SM9_TEST sm9_test)

set(static_lib gmlite_static)
set(shared_lib gmlite_shared)

# dependency
# prefer shared library
if(ENABLE_SHARED)
    set(dep_lib ${shared_lib})
    target_compile_definitions(modinv_test PRIVATE GML_BUILD_SHARED)
    target_compile_definitions(padding_test PRIVATE GML_BUILD_SHARED)
    target_compile_definitions(pairing_test PRIVATE GML_BUILD_SHARED)
    target_compile_definitions(secure_mem_test PRIVATE GML_BUILD_SHARED)
    target_compile_definitions(sm2_test PRIVATE GML_BUILD_SHARED)
    target_compile_definitions(sm3_test PRIVATE GML_BUILD_SHARED)
    target_compile_definitions(sm4_test PRIVATE GML_BUILD_SHARED)
    target_compile_definitions(sm9_test PRIVATE GML_BUILD_SHARED)
elseif(ENABLE_STATIC)
    set(dep_lib ${static_lib})
    target_compile_definitions(modinv_test PRIVATE GML_BUILD_STATIC)
    target_compile_definitions(padding_test PRIVATE GML_BUILD_STATIC)
    target_compile_definitions(pairing_test PRIVATE GML_BUILD_STATIC)
    target_compile_definitions(secure_mem_test PRIVATE GML_BUILD_STATIC)
    target_compile_definitions(sm2_test PRIVATE GML_BUILD_STATIC)
    target_compile_definitions(sm3_test PRIVATE GML_BUILD_STATIC)
    target_compile_definitions(sm4_test PRIVATE GML_BUILD_STATIC)
    target_compile_definitions(sm9_test PRIVATE GML_BUILD_STATIC)
else()
    message(FATAL_ERROR "no library compiled")
endif()

set(test_DEP ${dep_lib})
if(HAVE_PTHREAD)
    list(APPEND test_DEP pthread)
endif()

target_link_libraries(modinv_test ${test_DEP})
target_link_libraries(padding_test ${test_DEP})
target_link_libraries(pairing_test ${test_DEP})
target_link_libraries(secure_mem_test ${test_DEP})
target_link_libraries(sm2_test ${test_DEP})
target_link_libraries(sm3_test ${test_DEP})
target_link_libraries(sm4_test ${test_DEP})
target_link_libraries(sm9_test ${test_DEP})