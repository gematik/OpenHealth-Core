cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 23)

project(crypto)

# enable_testing()

### OpenSSL

include(cmake/openssl.cmake)

### Base library

add_library(oh_crypto_base STATIC
        src/errors.hpp
        src/capi.hpp
        src/ec.cpp
        src/ec.hpp
        src/hash.cpp
        src/hash.hpp
        src/mac.cpp
        src/mac.hpp
        src/cipher.cpp
        src/cipher.hpp
        src/mlkem.cpp
        src/mlkem.hpp
        src/core.cpp
        src/core.hpp
)
target_link_libraries(oh_crypto_base PRIVATE OpenSSL::Crypto)


if (NOT CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set_target_properties(oh_crypto_base PROPERTIES POSITION_INDEPENDENT_CODE ON)

    find_package(JNI)

    add_library(oh_crypto SHARED ${PROJECT_ROOT_DIR}/crypto-jvm-swig/build/generated/sources/jni/crypto.cpp)
    target_include_directories(oh_crypto PRIVATE src)
    target_link_libraries(oh_crypto PRIVATE oh_crypto_base OpenSSL::Crypto JNI::JNI)
else ()
    # Build the lib as a wasm module using Emscripten
    add_executable(oh_crypto src/ems_wrapper.cpp)

    # Link required libraries
    target_link_libraries(oh_crypto PRIVATE oh_crypto_base OpenSSL::Crypto)
    target_link_libraries(oh_crypto PRIVATE oh_crypto_base embind)

    # Set target link options
    target_link_options(oh_crypto PRIVATE
        -fwasm-exceptions
        -sINITIAL_MEMORY=33554432   # 32 MB
        -sALLOW_MEMORY_GROWTH=1
        -sMODULARIZE=1
        -sENVIRONMENT=node,web
        -sEXPORT_ES6=1
        -sUSE_ES6_IMPORT_META=1
        -sFILESYSTEM=0
        -sEXPORTED_RUNTIME_METHODS=ccall
    )

    # Emit TS type definitions (requires a previous run of `npm install` in the emscripten root directory)
    target_link_options(oh_crypto PRIVATE "SHELL:--emit-tsd oh_crypto.d.ts")

    # Set the export name for the module
    target_link_options(oh_crypto PRIVATE -sEXPORT_NAME=CryptoModule)

    # Apply release-specific optimizations
    if (CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(oh_crypto PRIVATE -Oz -flto)
    endif ()
endif ()

#add_subdirectory(test)