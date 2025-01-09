cmake_minimum_required(VERSION 3.27)

set(CMAKE_CXX_STANDARD 23)

project(openssl)

find_package(OpenSSL REQUIRED)

add_executable(openssl ${BASE_SOURCES}
        src/wrapper.cpp
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
)
target_link_libraries(openssl PRIVATE OpenSSL::Crypto embind)

#target_compile_options(openssl PRIVATE -DEMSCRIPTEN_HAS_UNBOUND_TYPE_NAMES=0 -fno-rtti)
#target_link_options(openssl PRIVATE --emit-symbol-map)
#target_link_options(openssl PRIVATE -fno-rtti)
target_link_options(openssl PRIVATE -fwasm-exceptions)

target_link_options(openssl PRIVATE -sINITIAL_MEMORY=33554432) # 32mb
target_link_options(openssl PRIVATE -sALLOW_MEMORY_GROWTH=1)
#target_link_options(openssl PRIVATE -sABORT_ON_WASM_EXCEPTIONS=1)
target_link_options(openssl PRIVATE -sMODULARIZE=1)
target_link_options(openssl PRIVATE -sENVIRONMENT=node,web)

target_link_options(openssl PRIVATE -sEXPORT_ES6=1)
target_link_options(openssl PRIVATE -sUSE_ES6_IMPORT_META=1)

target_link_options(openssl PRIVATE -sFILESYSTEM=0)

#target_link_options(openssl PRIVATE -sEXPORTED_RUNTIME_METHODS=emval_handles,ccall,cwrap)
target_link_options(openssl PRIVATE -sEXPORTED_RUNTIME_METHODS=ccall)

# Emit TS type definitions; requires a previous run of `npm install` inside emscripten root dir
target_link_options(openssl PRIVATE "SHELL:--emit-tsd openssl.d.ts")

target_link_options(openssl PRIVATE -sEXPORT_NAME=OpenSSLModule)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(openssl PRIVATE -Oz -flto)
endif ()