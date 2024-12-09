cmake_minimum_required(VERSION 3.27)

set(CMAKE_CXX_STANDARD 23)

project(wasm_test)

find_package(OpenSSL REQUIRED)

#get_target_property(BASE_SOURCES base INTERFACE_SOURCES)

add_executable(wasm_test ${BASE_SOURCES} wrapper.cpp)
target_link_libraries(wasm_test PRIVATE OpenSSL::Crypto)

#target_link_libraries(wasm_test base)
#target_link_libraries(wasm_test embind)

set(EXPORTED_FUNCTIONS_LIST
        _EVP_CIPHER_CTX_new
        _EVP_CIPHER_CTX_free
        _EC_GROUP_new_by_curve_name
        _EC_GROUP_free
        _BN_new
        _BN_free
        _BN_hex2bn
        _BN_bn2hex
        _EC_POINT_new
        _EC_POINT_free
        _EC_POINT_hex2point
        _EC_POINT_point2hex
        _EC_POINT_mul
        _EC_POINT_cmp
        _CRYPTO_free
)

list(JOIN EXPORTED_FUNCTIONS_LIST "," JOINED_FUNCTIONS)
set(EXPORTED_FUNCTIONS "-sEXPORTED_FUNCTIONS=${JOINED_FUNCTIONS}")

target_link_options(wasm_test PRIVATE -sINITIAL_MEMORY=33554432) # 32mb
target_link_options(wasm_test PRIVATE -sALLOW_MEMORY_GROWTH=1)
target_link_options(wasm_test PRIVATE -sABORT_ON_WASM_EXCEPTIONS=1)
#target_link_options(wasm_test PRIVATE "SHELL:--post-js api.js")
#target_link_options(wasm_test PRIVATE -sMODULARIZE=0 -sENVIRONMENT=web -sFILESYSTEM=0)
target_link_options(wasm_test PRIVATE -sMODULARIZE=1)
target_link_options(wasm_test PRIVATE -sWASM_ASYNC_COMPILATION=1)
target_link_options(wasm_test PRIVATE -sASSERTIONS=1)

target_link_options(wasm_test PRIVATE -sENVIRONMENT=web)
target_link_options(wasm_test PRIVATE -sEXPORT_ES6=1)
target_link_options(wasm_test PRIVATE -sUSE_ES6_IMPORT_META=1)
target_link_options(wasm_test PRIVATE -sFILESYSTEM=0)
target_link_options(wasm_test PRIVATE -sEXPORTED_RUNTIME_METHODS=ccall,cwrap)
target_link_options(wasm_test PRIVATE ${EXPORTED_FUNCTIONS})
#target_link_options(wasm_test PRIVATE -sEXPORT_NAME=WasmTestModule)
#target_link_options(wasm_test PRIVATE "SHELL:-lnodefs.js")
#target_link_options(wasm_test PRIVATE "SHELL:--emit-tsd interface.d.ts")
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(wasm_test PRIVATE -Oz -flto -dead_strip)
else ()
#    target_link_options(wasm_test PRIVATE "SHELL:-s BINARYEN_ASYNC_COMPILATION=0")
endif ()