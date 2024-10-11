//! Cipher
use chacha20poly1305::{
    aead::Aead, ChaCha20Poly1305, KeyInit, Nonce
};
use rand::RngCore;
use rand_core::OsRng;


pub fn encrypt(data: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    // let key = Key::from_slice(secret);
    let nonce = Nonce::from_slice(&[0u8; 12]);

    // Encrypt the plaintext
    let cipher = ChaCha20Poly1305::new_from_slice(secret).unwrap();
    // cipher.encrypt(nonce, plaintext.as_ref()).expect("encryption failure!");
    let ciphertext = cipher.encrypt(nonce, data).expect("encryption failure!");
    // println!("{:?}", ciphertext);
    return ciphertext;
}

pub fn decrypt(data: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    let nonce = Nonce::from_slice(&[0u8; 12]);
    // Encrypt the plaintext
    let cipher = ChaCha20Poly1305::new_from_slice(secret).unwrap();
    let text = cipher.decrypt(nonce, data).expect("decryption failure!");
    // println!("{:?}", text);
    return text;
}

#[test]
pub fn test_encrypt() {
    let secret = [2u8; 32];
    let data = [1u8; 32];
    let result = encrypt(&data, &secret);
    // assert_eq!(result, "encrypted");

    let decrypted = decrypt(&result, &secret);
    assert_eq!(decrypted, data);
}

// Generate a random initialization vector of the given size in bytes
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut iv = vec![0u8; size];
    OsRng.fill_bytes(&mut iv);
    iv
}
