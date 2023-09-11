Cryptography is a big part of cyber! To better gain a grasp on how AES, one of the most widely adopted and secure symmetric encryption algorithms used for securing data, I decided to begin on this project! I am currently working on coding 128 AES encryption system in C++

Due to the complex nature of this project, I am working on this in sections. 

Work Completed so Far: 

Header Includes: The program begins with several #include statements, importing the necessary C++ libraries for input/output, string manipulation, random number generation, and data structures like vectors.

Constants: The program defines two important constants:

sBox: A substitution box used in the AES algorithm for byte substitution during encryption. It's a 16x16 matrix of hexadecimal values.
roundConstants: An array of round constants used in key expansion.
Function Declarations: Several functions are declared before main() to improve code organization and readability.

main() Function:

The program starts by getting a 16-byte input message from the user using the getInputMessage() function.

Then, it generates a random 128-bit AES key in binary form using generateAESKey().

The binary key is converted to a hexadecimal string using keyToHex().

The hex key is converted to a 4x4 matrix using hexKeyToMatrix(), which lays out the key for later use.

extractColumnsAsWords() is used to extract columns from the key matrix and store them as words.

rotateWordLeft() function is applied to each word, rotating them one position to the left.

substituteByte() is used to perform S-box substitution on each byte in the rotated words.

applyRoundConstant() applies the round constant to the words.


Next sections that will worked on: 
Encryption Rounds: AES encryption consists of multiple rounds, each of which applies a set of transformations to the data--> implement following functions including the SubBytes, ShiftRows, MixColumns, and AddRoundKey transformations.
