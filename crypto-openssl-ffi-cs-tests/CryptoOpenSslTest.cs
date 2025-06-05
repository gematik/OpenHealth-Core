using System;
using Xunit;

namespace CryptoOpenSslTests
{
    public class CryptoOpenSslTests
    {
        [Fact]
        public void TestSha256()
        {
            string data = "Hello, world!";
            string hash = CryptoOpenSsl.Sha256(data);

            Assert.NotNull(hash);
            Assert.Contains("sha256:", hash);
        }

        [Fact]
        public void TestAesEncryptAndDecrypt()
        {
            string data = "Sensitive information";
            string key = "0123456789abcdef0123456789abcdef";
            string iv = "0123456789abcdef";

            string encrypted = CryptoOpenSsl.AesEncrypt(data, key, iv);
            Assert.NotNull(encrypted);

            string decrypted = CryptoOpenSsl.AesDecrypt(encrypted, key, iv);

            Assert.Contains("decrypted:", decrypted);
        }

        [Fact]
        public void TestRsaSignAndVerify()
        {
            string data = "Data to sign";
            string privateKey = "-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----";
            string publicKey = "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----";

            string signature = CryptoOpenSsl.RsaSign(data, privateKey);
            Assert.NotNull(signature);

            bool isValid = CryptoOpenSsl.RsaVerify(data, signature, publicKey);

            Assert.True(isValid);
        }
    }
}