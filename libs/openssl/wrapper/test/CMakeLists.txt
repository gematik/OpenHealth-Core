cmake_minimum_required(VERSION 3.27)

project(test)

enable_testing()

find_package(Catch2 3 REQUIRED)

add_executable(openssl_test src/test.cpp)
target_link_options(openssl_test PRIVATE -fwasm-exceptions)
target_link_libraries(openssl_test PRIVATE openssl_base embind Catch2::Catch2WithMain)
target_link_libraries(openssl_test PRIVATE -sALLOW_MEMORY_GROWTH=1)
target_link_libraries(openssl_test PRIVATE -sABORT_ON_WASM_EXCEPTIONS=0)

add_test(NAME tests COMMAND openssl_test)

# Custom Node.js test
#add_test(NAME RunNodeTest COMMAND node src/test.js)

#
#target_compile_options(test PRIVATE -fexperimental-library)
##target_compile_options(test PRIVATE -fsanitize=leak)
##target_link_options(test PRIVATE -fsanitize=leak)
#target_link_options(test PRIVATE -sUSE_ZLIB=1)
##target_link_options(test PRIVATE "SHELL:--embed-file assets/")
#target_link_options(test PRIVATE -sDISABLE_EXCEPTION_CATCHING=0)
#target_link_options(test PRIVATE -sBINARYEN_ASYNC_COMPILATION=0)
#target_link_options(test PRIVATE -sINITIAL_MEMORY=33554432) # 32mb
#target_link_options(test PRIVATE -sALLOW_MEMORY_GROWTH=1)
#target_link_options(test PRIVATE -sABORT_ON_WASM_EXCEPTIONS=0)
#target_link_options(test PRIVATE "SHELL:-lnodefs.js")
#target_link_options(test PRIVATE "SHELL:--pre-js ${PROJECT_SOURCE_DIR}/simd.js")
#
#target_link_libraries(test embind)
#target_link_libraries(test doctest::doctest)
