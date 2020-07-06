cmake_minimum_required(VERSION 3.1.0)

check_function_exists(mmap HAVE_MMAP)
check_function_exists(mprotect HAVE_MPROTECT)
check_function_exists(mlock HAVE_MLOCK)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(explicit_memset HAVE_EXPLICIT_MEMSET)
check_function_exists(posix_memalign HAVE_POSIX_MEMALIGN)
check_function_exists(getpid HAVE_GETPID)
check_function_exists(getgid HAVE_GETGID)
check_function_exists(getuid HAVE_GETUID)
check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)

if(x86_64)
    if(MSVC)
        set(SM2ASM_x86_64 ${GMLITE_DIR}/ec/sm2_z256-x86_64.asm)
        set(SM3ASM_x86_64 ${GMLITE_DIR}/sm3/sm3-x86_64.asm)
        set(MONT_x86_64 ${GMLITE_DIR}/bn/x86_64-mont.asm)
        set(MONT5_x86_64 ${GMLITE_DIR}/bn/x86_64-mont5.asm)
        set(FP256_x86_64 ${GMLITE_DIR}/pairing/fp256-x86_64.asm)
    else()
        set(SM2ASM_x86_64 ${GMLITE_DIR}/ec/sm2_z256-x86_64.s)
        set(SM3ASM_x86_64 ${GMLITE_DIR}/sm3/sm3-x86_64.s)
        set(MONT_x86_64 ${GMLITE_DIR}/bn/x86_64-mont.s)
        set(MONT5_x86_64 ${GMLITE_DIR}/bn/x86_64-mont5.s)
        set(FP256_x86_64 ${GMLITE_DIR}/pairing/fp256-x86_64.s)
    endif()
endif()

message("C COMPILER   : ${CMAKE_C_COMPILER}")
message("ASM_COMPILER : ${CMAKE_ASM_COMPILER}")

# if compiler is gcc or clang, use sm3avx.S and sm3avx2.S
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    set(SM3_USE_GNU_ASM 1) # config
    set(SM3ASM 
        ${GMLITE_DIR}/sm3/asm/sm3_compress_avx.S)
        # ${GMLITE_DIR}/sm3/asm/sm3_compress_avx2.S)
# if compile in msvc, use sm3 c code
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
    set(SM3_MASM 1) # config
    set(SM3ASM)
else()
    set(SM3ASM)
endif()

# generate sm3 assembly code
add_custom_command (
    OUTPUT ${SM3ASM_x86_64}
    COMMAND ${PERL} ${GMLITE_DIR}/sm3/asm/sm3-x86_64.pl ${CMAKE_C_COMPILER} ${FLAVOUR} ${SM3ASM_x86_64}
)

# generate sm2 assembly code
add_custom_command (
    OUTPUT ${SM2ASM_x86_64}
    COMMAND ${PERL} ${GMLITE_DIR}/ec/asm/ecp_sm2z256-x86_64.pl ${CMAKE_C_COMPILER} ${FLAVOUR} ${SM2ASM_x86_64}
)

# generate bn_mul_mont assembly code
add_custom_command (
    OUTPUT ${MONT_x86_64} ${MONT5_x86_64}
    COMMAND ${PERL} ${GMLITE_DIR}/bn/asm/x86_64-mont.pl ${CMAKE_C_COMPILER} ${FLAVOUR} ${MONT_x86_64}
    COMMAND ${PERL} ${GMLITE_DIR}/bn/asm/x86_64-mont5.pl ${CMAKE_C_COMPILER} ${FLAVOUR} ${MONT5_x86_64}
)

# generate fp256 assembly code
add_custom_command (
    OUTPUT ${FP256_x86_64}
    COMMAND ${PERL} ${GMLITE_DIR}/pairing/asm/fp256-x86_64.pl ${CMAKE_C_COMPILER} ${FLAVOUR} ${FP256_x86_64}
)

# generate config.h
configure_file(${PROJECT_ABS_TOP_DIR}/config.h.in ${PROJECT_ABS_TOP_DIR}/config.h @ONLY)

# source file
set(BN_SRC
    ${MONT_x86_64}
    ${MONT5_x86_64}
    ${GMLITE_DIR}/bn/bn_add.c
    # ${GMLITE_DIR}/bn/bn_asm.c
    ${GMLITE_DIR}/bn/asm/x86_64-gcc.c
    ${GMLITE_DIR}/bn/bn_ctx.c
    ${GMLITE_DIR}/bn/bn_div.c
    ${GMLITE_DIR}/bn/bn_gcd.c
    ${GMLITE_DIR}/bn/bn_intern.c
    ${GMLITE_DIR}/bn/bn_lib.c
    ${GMLITE_DIR}/bn/bn_mod.c
    ${GMLITE_DIR}/bn/bn_mont.c
    ${GMLITE_DIR}/bn/bn_mul.c
    ${GMLITE_DIR}/bn/bn_print.c
    ${GMLITE_DIR}/bn/bn_rand.c
    ${GMLITE_DIR}/bn/bn_shift.c
    ${GMLITE_DIR}/bn/bn_sm2p256.c
    ${GMLITE_DIR}/bn/bn_sqr.c
    ${GMLITE_DIR}/bn/bn_word.c
)

set(EC_SRC
    ${GMLITE_DIR}/ec/ec_curve.c
    ${GMLITE_DIR}/ec/ec_kdf.c
    ${GMLITE_DIR}/ec/ec_lib.c
    ${GMLITE_DIR}/ec/ec_mult.c
    ${GMLITE_DIR}/ec/ecp_mont.c
    ${GMLITE_DIR}/ec/ecp_sm2p256.c
    ${GMLITE_DIR}/ec/ecp_sm2z256.c
    ${GMLITE_DIR}/ec/ecp_smpl.c
)

set(PAIRING_SRC
    ${FP256_x86_64}
    ${GMLITE_DIR}/pairing/final_expo.c
    ${GMLITE_DIR}/pairing/fp.c
    ${GMLITE_DIR}/pairing/fp2.c
    ${GMLITE_DIR}/pairing/fp6.c
    ${GMLITE_DIR}/pairing/fp12.c
    ${GMLITE_DIR}/pairing/G1.c
    ${GMLITE_DIR}/pairing/G2.c
    ${GMLITE_DIR}/pairing/optate.c
    ${GMLITE_DIR}/pairing/pairing.c
)

set(RAND_SRC
    ${GMLITE_DIR}/rand/prng.c
    ${GMLITE_DIR}/rand/rand.c
    ${GMLITE_DIR}/rand/sys_rand.c
)

set(SM2_SRC
    ${GMLITE_DIR}/sm2/sm2.c
    ${GMLITE_DIR}/sm2/sm2_enc.c
    ${GMLITE_DIR}/sm2/sm2_kmeth.c
    ${GMLITE_DIR}/sm2/sm2_sign.c
    ${SM2ASM_x86_64}
)

set(SM3_SRC
    ${GMLITE_DIR}/sm3/sm3.c
    ${GMLITE_DIR}/sm3/sm3_c.c
    # ${GMLITE_DIR}/sm3/sm3_avx.c
    # ${GMLITE_DIR}/sm3/sm3_avx2.c
    # ${SM3ASM}
    ${SM3ASM_x86_64}
)

set(SM4_SRC
    ${GMLITE_DIR}/sm4/sm4.c
)

set(SM9_SRC
    ${GMLITE_DIR}/sm9/sm9_kmeth.c
    ${GMLITE_DIR}/sm9/sm9_lib.c
    ${GMLITE_DIR}/sm9/sm9_sign.c
    ${GMLITE_DIR}/sm9/sm9.c
)

set(SMX_SRC
    ${BN_SRC}
    ${EC_SRC}
    ${PAIRING_SRC}
    ${SM2_SRC}
    ${SM3_SRC}
    ${SM4_SRC}
    ${SM9_SRC}
)

set(GMLITE_LCL_HEADER
    ${PROJECT_ABS_TOP_DIR}/config.h
)

set(GMLITE_HEADER
    ${GMLITE_LCL_HEADER}
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/bn.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/common.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/cpuid.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/crypto.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/ec.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/gm_typ.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/pairing.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/sm2.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/sm3.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/sm4.h
    ${PROJECT_ABS_TOP_DIR}/include/gmlite/sm9.h
)

set(GMLITE_SRC
    ${GMLITE_HEADER}
    gmlite_init.c
    common.c
    mem.c
    mem_sec.c
    cpuid.c
    ${RAND_SRC}
    ${SMX_SRC}
)

# header file directory
include_directories(${PROJECT_ABS_TOP_DIR}/)
include_directories(${PROJECT_ABS_TOP_DIR}/include/)
include_directories(${GMLITE_DIR}/include/)
include_directories(${GMLITE_DIR}/include/internal/)

if(ENABLE_STATIC)
    # build static object
    add_library(gmlite_static_object OBJECT ${GMLITE_SRC})
    target_compile_definitions(gmlite_static_object PRIVATE GML_BUILD_STATIC)
    #
    add_library(gmlite_static STATIC $<TARGET_OBJECTS:gmlite_static_object>)
    target_compile_definitions(gmlite_static PRIVATE GML_BUILD_STATIC)
    # output directory
    if(WIN32)
        set_target_properties(gmlite_static PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY_STATIC})
    else()
        set_target_properties(gmlite_static PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})
    endif()
    # rename
    set_target_properties(gmlite_static PROPERTIES OUTPUT_NAME "gmlite")
    # install library
    INSTALL(TARGETS gmlite_static ARCHIVE DESTINATION lib)
endif()

if(ENABLE_SHARED)
    # build shared object
    add_library(gmlite_shared_object OBJECT ${GMLITE_SRC})
    target_compile_definitions(gmlite_shared_object PRIVATE GML_BUILD_SHARED)
    # PIC
    set_property(TARGET gmlite_shared_object PROPERTY POSITION_INDEPENDENT_CODE 1)
    
    #
    add_library(gmlite_shared SHARED $<TARGET_OBJECTS:gmlite_shared_object>)
    target_compile_definitions(gmlite_shared PRIVATE GML_BUILD_SHARED)
    # output directory
    # TODO : LIBRARY_OUTPUT_DIRECTORY does not work in msvc
    if(WIN32)
        set_target_properties(gmlite_shared PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY_STATIC})
    else()
        set_target_properties(gmlite_shared PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIRECTORY})
    endif()
    # rename
    set_target_properties(gmlite_shared PROPERTIES OUTPUT_NAME "gmlite")
    # install library
    INSTALL(TARGETS gmlite_shared LIBRARY DESTINATION lib)
endif()

# install headers
INSTALL(DIRECTORY ${PROJECT_ABS_TOP_DIR}/include/gmlite DESTINATION include)
INSTALL(FILES ${PROJECT_ABS_TOP_DIR}/config.h DESTINATION include/gmlite)

