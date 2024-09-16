use rand::Rng;// For generating random noise

// Constants for LWE
const DELTA: u64 = 1 << 24; // Scaling Factor
const NOISE_BOUND: u64 = 10; // Upper bound for noise
const LWE_DIMENSION: usize = 12; // LWE dimension (lenght of the secret key)

// Function to generate a random matrix (public key)
fn generate_public_matrix(rows: usize, cols: usize) -> Vec<Vec<u64>> {
    let mut rng = rand::thread_rng();
    let mut matrix = vec![vec![0u64; cols]; rows]; // Random integers for matrix elements

    for i in 0..rows {
        for j in 0..cols {
            matrix[i][j] = rng.gen_range(0..100);
        }
    }

    matrix
} 

// Function to perform mattrix-vector mutiplication
fn matrix_vector_multiply(matrix: &[Vec<u64>], vector: &[i64]) -> Vec<u64> {
    let mut result = vec![0u64; matrix.len()];

    for i in 0..matrix.len() {
        for j in 0..vector.len() {
            result[i] = result[i].wrapping_add(matrix[i][j].wrapping_mul(vector[j] as u64));
        }
    }

    result
}

// Function to convert a string into a vector of ASCII values
fn string_to_ascii(msg: &str) -> Vec<u8> {
    msg.bytes().collect()
}

// Function to add noise to the value
fn add_noise(value: u64) -> u64 {
    let mut rng = rand::thread_rng();
    let noise: u64 = rng.gen_range(0..NOISE_BOUND);
    value + noise
}

// Function to generate and LWE secret key
fn generate_secret_key(n: usize) -> Vec<i64> {
    let mut rng = rand::thread_rng();
    let mut secret_key = Vec::new();

    for _ in 0..n {
        let s_i: i64 = rng.gen_range(-5..5);
        secret_key.push(s_i);
    }

    secret_key
}

// Function to add encrypt the message using LWE encryption and the secret key
fn lwe_encrypt(msg: &str, secret_key: &[i64], public_matrix: &[Vec<u64>]) -> Vec<u64> {
    let ascii_values = string_to_ascii(msg);
    let mut ciphertext = Vec::new();

    // The mask corresponds to matrix_vector_result 
    let matrix_vector_result = matrix_vector_multiply(public_matrix, secret_key);
    println!("Length is {}", matrix_vector_result.len());

    let mut count: u8 = 0;

    // for loop basically corresponds to body
    for (i, &m) in ascii_values.iter().enumerate() {
        let m = m as u64;

        let plaintext = DELTA * m;

        // let noised_ciphertext = matrix_vector_result[i % matrix_vector_result.len()] + plaintext;

        let noised_ciphertext = matrix_vector_result[i % matrix_vector_result.len()].wrapping_add(plaintext);

        ciphertext.push(add_noise(noised_ciphertext));

        count += 1;
    }

    println!("Count is {}", count);

    ciphertext
}

// Function to decrypt the LWE ciphertext using the secret key
fn lwe_decrypt(ciphertext: &[u64], secret_key: &[i64], public_matrix: &[Vec<u64>]) -> String {
    let mut decrypted_bytes = Vec::new();

    let matrix_vector_result = matrix_vector_multiply(public_matrix, secret_key);

    for (i, &c) in ciphertext.iter().enumerate() {

        //  let plaintext_approx = (c - matrix_vector_result[i % matrix_vector_result.len()]) / DELTA;

        let diff = c.wrapping_sub(matrix_vector_result[i % matrix_vector_result.len()]);
        let plaintext_approx = diff / DELTA;
        decrypted_bytes.push(plaintext_approx as u8);
    }

    String::from_utf8(decrypted_bytes).unwrap()
}

fn main() {

    // Generate the secret key
    let secret_key = generate_secret_key(LWE_DIMENSION);
    println!("LWE Secret Key is {:?}", secret_key);

    // Generate public matrix
    let public_matrix = generate_public_matrix(LWE_DIMENSION, LWE_DIMENSION);
    println!("Public Matrix is {:?}", public_matrix);

    let msg = "My name is Brooklyn";
    println!("Original message is {}", msg);

    // Encrypting the message
    let ciphertext = lwe_encrypt(msg, &secret_key, &public_matrix);
    println!("Encrypted message (ciphertext) is {:?}", ciphertext);

    // Decrypting ciphertext
    let decrypted_ciphertext = lwe_decrypt(&ciphertext, &secret_key, &public_matrix);
    println!("Decrypted ciphertext is {:?}", decrypted_ciphertext);
}