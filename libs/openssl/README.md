# Native OpenSSL Library

# WebAssembly with Emscripten (EMS)

`npm/` - the actual npm package
`_ems_build_scripts/` - includes scripts to checkout OpenSSL and build it for the WASM platform
`_ems_wrapper/` - glue code for the usage with JS

## Build

`make -C /PATH/TO/_ems_build_scripts/ all`

This command will finally copy the build output to the lib dir in `npm/lib`.

## Wrapper

### Usage with Clion

1. Set the environment variable `$EMSDK_ENV` to the path where `emsdk_env.sh` is located.
2. Configure clion to use `$EMSDK_ENV` as its environment source path
3. and `_ems_wrapper/.config/clion-cmake.sh` as the cmake command.
