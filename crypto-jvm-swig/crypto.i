// Copyright 2025 gematik GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

%module Crypto

%rename("%(lowercamelcase)s", %$not %$isclass) "";
%rename("%(camelcase)s", %$isclass) "";

%include <std_unique_ptr.i>
%include <std_string.i>
%include <std_unique_ptr.i>
%include <std_vector.i>
%include <swiginterface.i>

%{
#include "core.hpp"
#include "cipher.hpp"
#include "ec.hpp"
#include "hash.hpp"
#include "mac.hpp"
#include "mlkem.hpp"
%}

%exception {
    try {
        $action
    }
    catch (const std::exception& e) {
        SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, e.what());
        return $null;
    }
}

%typemap(javainterfaces) SWIGTYPE "ClassHandle";
%typemap(javacode) SWIGTYPE %{
  @Override
  public synchronized void jniFreeMemory() {
    delete();
  }
%}

%apply signed char { uint8_t };
%apply const signed char & { const uint8_t & };
%typedef std::vector<uint8_t> uint8_vector;
%template(Uint8Vector) std::vector<uint8_t>;

%unique_ptr(cipher::aes_cipher)
%unique_ptr(ec::ec_point)
%unique_ptr(ec::ec_keypair)
%unique_ptr(ec::ecdh)
%unique_ptr(hash::hash_generator)
%unique_ptr(mac::cmac)
%unique_ptr(kem::mlkem_encapsulation)
%unique_ptr(kem::mlkem_decapsulation)

// %typemap(javadestruct, methodname="delete", methodmodifiers="@Override public synchronized", parameters="") SWIGTYPE "";

// %typemap(javadestruct, methodname="delete", methodmodifiers="@Override public synchronized", parameters="") SWIGTYPE {
//     if (swigCPtr != 0) {
//       if (swigCMemOwn) {
//         swigCMemOwn = false;
//         $jnicall;
//       }
//       swigCPtr = 0;
//     }
// }

%ignore ec::convert_private_key_to_der;
%ignore ec::convert_public_key_to_der;
%ignore ec::convert_private_key_from_der;
%ignore ec::convert_public_key_from_der;
%ignore ec::ossl_unique_ptr;

%include "core.hpp"
%include "cipher.hpp"
%include "ec.hpp"
%include "hash.hpp"
%include "mac.hpp"
%include "mlkem.hpp"
