MAKEFILE_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
#GIT_HASH_OPENSSL := 98acb6b02839c609ef5b837794e08d906d965335
GIT_HASH_OPENSSL := f60adc4057bbd3b19683dfe72124fc3cf5210a0d
SRC_DIR_OPENSSL := $(MAKEFILE_DIR)/../ems_source_$(GIT_HASH_OPENSSL)
SRC_DIR_WRAPPER := $(MAKEFILE_DIR)/../ems_wrapper
BUILD_DIR_WRAPPER := $(SRC_DIR_WRAPPER)/build
NPM_LIB_DIR_WRAPPER := $(SRC_DIR_WRAPPER)/../npm/lib
OPENSSL_REPO := https://github.com/openssl/openssl.git
NPROCESSORS := $(shell getconf NPROCESSORS_ONLN 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)

.PHONY: checkout_openssl configure_openssl build_openssl install_openssl clean_openssl \
	create_wrapper_build_dir configure_ems_openssl_wrapper build_ems_openssl_wrapper copy_ems_wrapper_to_npm

all: install_openssl copy_ems_wrapper_to_npm

clean: clean_openssl clean_ems_wrapper

.check_emscripten_installed:
	@if ! command -v emconfigure > /dev/null 2>&1; then \
		echo "Emscripten not found. 'source emsdk_env.sh' first."; \
		exit 1; \
	fi

## OpenSSL

$(SRC_DIR_OPENSSL)/.git:
	git clone $(OPENSSL_REPO) --single-branch --depth 1 --no-checkout $(SRC_DIR_OPENSSL)
	git -C $(SRC_DIR_OPENSSL) fetch origin $(GIT_HASH_OPENSSL)
	git -C $(SRC_DIR_OPENSSL) checkout -q $(GIT_HASH_OPENSSL)
	@for patch in $(MAKEFILE_DIR)/../ems_patches/*.patch; do \
		git -C $(SRC_DIR_OPENSSL) apply "$$patch"; \
	done
	touch $(SRC_DIR_OPENSSL)/.git

checkout_openssl: $(SRC_DIR_OPENSSL)/.git

configure_openssl: .check_emscripten_installed checkout_openssl
	cd $(SRC_DIR_OPENSSL) && emconfigure bash $(MAKEFILE_DIR)/configure.sh

build_openssl: .check_emscripten_installed configure_openssl
	cd $(SRC_DIR_OPENSSL) && make -j$(NPROCESSORS)

install_openssl: build_openssl
	cd $(SRC_DIR_OPENSSL) && make install

clean_openssl:
	rm -rf $(SRC_DIR_OPENSSL)

## Emscripten OpenSSL Wrapper

.create_wrapper_build_dir:
	mkdir -p $(BUILD_DIR_WRAPPER)

configure_ems_openssl_wrapper: .check_emscripten_installed .create_wrapper_build_dir
	emcmake cmake -DCMAKE_BUILD_TYPE=Release -B$(BUILD_DIR_WRAPPER) -S$(SRC_DIR_WRAPPER)

build_ems_openssl_wrapper: configure_ems_openssl_wrapper
	cmake --build $(BUILD_DIR_WRAPPER) --parallel $(NPROCESSORS)

## NPM Package

copy_ems_wrapper_to_npm: build_ems_openssl_wrapper
	mkdir -p $(NPM_LIB_DIR_WRAPPER)
	cp $(BUILD_DIR_WRAPPER)/openssl.d.ts $(NPM_LIB_DIR_WRAPPER)/openssl.d.ts
	cp $(BUILD_DIR_WRAPPER)/openssl.js $(NPM_LIB_DIR_WRAPPER)/openssl.js
	cp $(BUILD_DIR_WRAPPER)/openssl.wasm $(NPM_LIB_DIR_WRAPPER)/openssl.wasm

clean_ems_wrapper:
	rm -rf $(BUILD_DIR_WRAPPER) && rm -rf $(NPM_LIB_DIR_WRAPPER)