// TypeScript bindings for emscripten-generated code.  Automatically generated at compile time.
declare namespace RuntimeExports {
    let HEAPF32: any;
    let HEAPF64: any;
    let HEAP_DATA_VIEW: any;
    let HEAP8: any;
    let HEAPU8: any;
    let HEAP16: any;
    let HEAPU16: any;
    let HEAP32: any;
    let HEAPU32: any;
    let HEAP64: any;
    let HEAPU64: any;
}
interface WasmModule {
}

export interface ClassHandle {
  isAliasOf(other: ClassHandle): boolean;
  delete(): void;
  deleteLater(): this;
  isDeleted(): boolean;
  clone(): this;
}
export interface ems_BIGNUM_ptr extends ClassHandle {
}

export interface ems_BIGNUM_ref extends ClassHandle {
}

export interface ems_EVP_CIPHER_CTX_ptr extends ClassHandle {
}

export interface ems_EC_GROUP_ptr extends ClassHandle {
}

export interface ems_EC_POINT_ptr extends ClassHandle {
}

interface EmbindModule {
  ems_BIGNUM_ptr: {};
  ems_BIGNUM_ref: {};
  ems_ref(_0: ems_BIGNUM_ptr): ems_BIGNUM_ref;
  ems_EVP_CIPHER_CTX_ptr: {};
  ems_EVP_CIPHER_CTX_new(): ems_EVP_CIPHER_CTX_ptr;
  ems_EC_GROUP_ptr: {};
  ems_EC_POINT_ptr: {};
  ems_EC_POINT_new(_0: ems_EC_GROUP_ptr): ems_EC_POINT_ptr;
  ems_Abc_new(_0?: ems_BIGNUM_ref): void;
  ems_EC_GROUP_new_by_curve_name(_0: number): ems_EC_GROUP_ptr;
  ems_EC_POINT_mul(_0: ems_EC_GROUP_ptr, _1: ems_EC_POINT_ptr, _2: ems_BIGNUM_ref | undefined, _3: ems_EC_POINT_ptr, _4: ems_BIGNUM_ptr): number;
}

export type MainModule = WasmModule & typeof RuntimeExports & EmbindModule;
export default function MainModuleFactory (options?: unknown): Promise<MainModule>;
