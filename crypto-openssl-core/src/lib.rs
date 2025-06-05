extern crate openssl;

use openssl::symm::{Cipher, Crypter, Mode};
use openssl::hash::{Hasher, MessageDigest};

// Encrypt plaintext using AES-256-CBC.
pub fn encrypt_aes_256_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_256_cbc();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut count = encrypter.update(plaintext, &mut ciphertext)?;
    count += encrypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);
    Ok(ciphertext)
}

// Decrypt ciphertext using AES-256-CBC.
pub fn decrypt_aes_256_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_256_cbc();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = decrypter.update(ciphertext, &mut plaintext)?;
    count += decrypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count);
    Ok(plaintext)
}

// Compute SHA-256 digest of data.
pub fn sha256_digest(data: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(data)?;
    Ok(hasher.finish()?.to_vec())
}