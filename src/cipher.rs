//! Cipher
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead}, ChaCha20Poly1305, Key, KeyInit, Nonce
};
use rand_core::OsRng;


pub fn encrypt(data: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    // let key = Key::from_slice(secret);
    let nonce = Nonce::from_slice(&[0u8; 12]);

    // Encrypt the plaintext
    let cipher = ChaCha20Poly1305::new_from_slice(secret).unwrap();
    // cipher.encrypt(nonce, plaintext.as_ref()).expect("encryption failure!");
    let ciphertext = cipher.encrypt(nonce, data).expect("encryption failure!");
    println!("{:?}", ciphertext);
    return ciphertext;
}

pub fn decrypt(data: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    let nonce = Nonce::from_slice(&[0u8; 12]);
    // Encrypt the plaintext
    let cipher = ChaCha20Poly1305::new_from_slice(secret).unwrap();
    let text = cipher.decrypt(nonce, data).expect("decryption failure!");
    println!("{:?}", text);
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

// /// Encrypt data with AES CBC using the supplied secret
// pub fn main() {
//     let key = GenericArray::from([0u8; 32]);
//     let mut block = GenericArray::from([42u8; 16]);

//     // Initialize cipher
//     let cipher: Aes256 = Aes256::new(&key);

//     let block_copy = block.clone();

//     // Encrypt block in-place
//     cipher.encrypt_block(&mut block);

//     // And decrypt it back
//     cipher.decrypt_block(&mut block);
//     assert_eq!(block, block_copy);

//     // Implementation supports parallel block processing. Number of blocks
//     // processed in parallel depends in general on hardware capabilities.
//     // This is achieved by instruction-level parallelism (ILP) on a single
//     // CPU core, which is differen from multi-threaded parallelism.
//     let mut blocks = [block; 100];
//     cipher.encrypt_blocks(&mut blocks);

//     for block in blocks.iter_mut() {
//         cipher.decrypt_block(block);
//         assert_eq!(block, &block_copy);
//     }

//     // `decrypt_blocks` also supports parallel block processing.
//     cipher.decrypt_blocks(&mut blocks);

//     for block in blocks.iter_mut() {
//         cipher.encrypt_block(block);
//         assert_eq!(block, &block_copy);
//     }
// }

// Generate a random initialization vector of the given size in bytes
// pub fn generate_random(size: usize) -> Result<Vec<u8>, Error> {
//     let mut iv = vec![0u8; size];
//     OsRng.fill_bytes(&mut iv).map_err(|_| Error::RandomGenerationFailed)?;
//     Ok(iv)
// }
