MAKEFILE_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
GIT_HASH_OPENSSL := 98acb6b02839c609ef5b837794e08d906d965335
SRC_DIR_OPENSSL := $(MAKEFILE_DIR)/../openssl_ems_source_$(GIT_HASH_OPENSSL)
OPENSSL_REPO := https://github.com/openssl/openssl.git
NPROCESSORS := $(shell getconf NPROCESSORS_ONLN 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)

.PHONY: checkout configure build install clean

all: checkout configure build install

checkout:
	git clone $(OPENSSL_REPO) --single-branch --depth 1 --no-checkout $(SRC_DIR_OPENSSL)
	git -C $(SRC_DIR_OPENSSL) fetch origin $(GIT_HASH_OPENSSL)
	git -C $(SRC_DIR_OPENSSL) checkout -q $(GIT_HASH_OPENSSL)
	git -C $(SRC_DIR_OPENSSL) apply $(MAKEFILE_DIR)/../openssl_ems_patches/configuration.patch

.check_emscripten_installed:
	@if ! command -v emconfigure > /dev/null 2>&1; then \
		echo "Emscripten not found. 'source emsdk_env.sh' first."; \
		exit 1; \
	fi

configure: .check_emscripten_installed
	cd $(SRC_DIR_OPENSSL) \
	emconfigure bash $(MAKEFILE_DIR)/configure.sh

build: .check_emscripten_installed
	cd $(SRC_DIR_OPENSSL) \
	make -j$(NPROCESSORS)

install:
	cd $(SRC_DIR_OPENSSL) \
	make install

clean:
	rm -rf $(SRC_DIR_OPENSSL)