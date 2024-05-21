Cryptography is a big part of cyber! To better gain a grasp on how AES, one of the most widely adopted and secure symmetric encryption algorithms used for securing data, I decided to begin on this project! I have completed work on coding 128 AES encryption system in C++

AES-128 Encryption Key Expansion
 Goal: This project aims to implement the key expansion process for AES-128 encryption.
 
 
 AES (Advanced Encryption Standard) is a widely used symmetric key encryption algorithm that operates on blocks of data. AES 128-bit, as the name suggests, uses a 128-bit key for encryption and decryption. Here's a summary of how AES 128-bit works:
 
  1. Key Expansion:
  - The 128-bit encryption key is used to generate a set of round keys through a key expansion process.
      - The key expansion involves a series of mathematical operations that create a set of round keys used in the encryption and decryption processes.
 
  2. Initial Round
      - The plaintext (data to be encrypted) is divided into a 16-byte block.
     - The initial round involves the bitwise XOR operation, where each byte of the block is combined with the corresponding byte of the round key (Round 0).
 
   3. Main Rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey):
      - AES consists of multiple rounds (10 rounds for AES-128).
      - In each round, the following operations are performed:
        a. SubBytes: Each byte of the block is replaced with a corresponding byte from the S-box (a fixed substitution table).
        b. ShiftRows: The bytes in each row of the block are shifted left by varying amounts.
        c. MixColumns: Each column is transformed using a mathematical operation that provides diffusion.
        d. AddRoundKey: The round key for the current round is XORed with the block.
 
   4. Final Round (SubBytes, ShiftRows, AddRoundKey):
      - The final round is similar to the main rounds but does not include the MixColumns step.
 
   5. Output:
     - After the final round, the processed block is the ciphertext.
 
   AES is highly secure and widely used due to its resistance to various cryptographic attacks. It provides confidentiality, ensuring that unauthorized parties cannot read the original data without the correct key.
