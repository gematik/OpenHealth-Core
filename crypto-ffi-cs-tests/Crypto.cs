using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptoOpenSslTests
{
    public static class CryptoOpenSsl
    {
        private const string LibraryName = "crypto_openssl_ffi";

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr crypto_openssl_sha256(string data);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr crypto_openssl_aes_encrypt(string data, string key, string iv);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr crypto_openssl_aes_decrypt(string encryptedData, string key, string iv);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr crypto_openssl_rsa_sign(string data, string privateKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_openssl_rsa_verify(string data, string signature, string publicKey);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr crypto_openssl_get_last_error();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void crypto_openssl_free_string(IntPtr ptr);

        private static string PtrToString(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return null;

            try
            {
                return Marshal.PtrToStringAnsi(ptr);
            }
            finally
            {
                crypto_openssl_free_string(ptr);
            }
        }

        public static string Sha256(string data)
        {
            var resultPtr = crypto_openssl_sha256(data);
            return PtrToString(resultPtr);
        }

        public static string AesEncrypt(string data, string key, string iv)
        {
            var resultPtr = crypto_openssl_aes_encrypt(data, key, iv);
            return PtrToString(resultPtr);
        }

        public static string AesDecrypt(string encryptedData, string key, string iv)
        {
            var resultPtr = crypto_openssl_aes_decrypt(encryptedData, key, iv);
            return PtrToString(resultPtr);
        }

        public static string RsaSign(string data, string privateKey)
        {
            var resultPtr = crypto_openssl_rsa_sign(data, privateKey);
            return PtrToString(resultPtr);
        }

        public static bool RsaVerify(string data, string signature, string publicKey)
        {
            return crypto_openssl_rsa_verify(data, signature, publicKey) == 1;
        }

        public static string GetLastError()
        {
            var resultPtr = crypto_openssl_get_last_error();
            return PtrToString(resultPtr);
        }
    }
}