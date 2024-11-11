if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(OPENSSL_TARGET "linux-x86_64")

elseif (CMAKE_SYSTEM_NAME STREQUAL "Android")
    if (CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
        set(OPENSSL_TARGET "android-arm")
    elseif (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
        set(OPENSSL_TARGET "android-arm64")
    elseif (CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
        set(OPENSSL_TARGET "android-x86")
    elseif (CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
        set(OPENSSL_TARGET "android-x86_64")
    else ()
        message(FATAL_ERROR "Unsupported Android architecture: ${CMAKE_ANDROID_ARCH_ABI}")
    endif ()

elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    #    if(CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
    #        set(OPENSSL_TARGET "darwin64-arm64-cc") # macOS ARM target
    #    elseif(CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
    #        set(OPENSSL_TARGET "darwin64-x86_64-cc") # macOS Intel target
    #    else()
    #        message(FATAL_ERROR "Unsupported macOS architecture: ${CMAKE_OSX_ARCHITECTURES}")
    #    endif()
    set(OPENSSL_TARGET "darwin64-arm64-cc") # macOS ARM target

elseif (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(OPENSSL_TARGET "ios64-cross") # iOS target

elseif (CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set(OPENSSL_TARGET "wasm32-wasi") # Emscripten target

else ()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif ()

include(ExternalProject)
set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-src)
set(OPENSSL_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-build-${OPENSSL_TARGET})
set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-${OPENSSL_TARGET})
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
set(OPENSSL_CONFIG_PARAMS "
    no-asm \
    no-async \
    no-egd \
    no-ktls \
    no-module \
    no-posix-io \
    no-secure-memory \
    no-shared \
    no-sock \
    no-stdio \
    no-thread-pool \
    no-threads \
    no-ui-console \
    no-docs \
    "
)
if (CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    # Emscripten requires special configuration not transparently handled by cmake
    set(OPENSSL_CONFIGURE_COMMAND
            emconfigure bash -c "
            env \
                CROSS_COMPILE=\"\" \
                ${OPENSSL_SOURCE_DIR}/Configure \
                --prefix=${OPENSSL_INSTALL_DIR} \
                ${OPENSSL_CONFIG_PARAMS}
    ${OPENSSL_TARGET}"
    )
else ()
    set(OPENSSL_CONFIGURE_COMMAND
            bash -c "${OPENSSL_SOURCE_DIR}/Configure \
            --prefix=${OPENSSL_INSTALL_DIR} \
            ${OPENSSL_CONFIG_PARAMS}
    ${OPENSSL_TARGET}"
    )
endif ()

ExternalProject_Add(
        OpenSSL
        SOURCE_DIR ${OPENSSL_SOURCE_DIR}
        BINARY_DIR ${OPENSSL_BINARY_DIR}
        GIT_REPOSITORY https://github.com/openssl/openssl.git
        GIT_TAG 8fabfd81094d1d9f8890df4bee083aa6f77d769d
        CONFIGURE_COMMAND
        ${OPENSSL_CONFIGURE_COMMAND}
        UPDATE_COMMAND ""
        BUILD_COMMAND make -j14
        BUILD_IN_SOURCE 0
        # required, otherwise ninja fails
        BUILD_BYPRODUCTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a
        TEST_COMMAND ""
        INSTALL_COMMAND make install
        INSTALL_DIR ${OPENSSL_INSTALL_DIR}
        # git apply fails if the patch was already applied
        PATCH_COMMAND
        git apply --check ${CMAKE_CURRENT_SOURCE_DIR}/patches/openssl.patch &&
        git apply ${CMAKE_CURRENT_SOURCE_DIR}/patches/openssl.patch || echo "Patch already applied"
)

file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})

add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
set_property(TARGET OpenSSL::Crypto PROPERTY IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
add_dependencies(OpenSSL::Crypto OpenSSL)
