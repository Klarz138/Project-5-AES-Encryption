/******************************************************************************
 * 
 *░█████╗░███████╗░██████╗░░ ███╗░░██████╗░░█████╗  ░██████╗░██╗████████╗
 *██╔══██╗██╔════╝██╔════╝░ ████║░░╚════██╗██╔══██╗  ██╔══██╗██║╚══██╔══╝
 *███████║█████╗░░╚█████╗░ ██╔██║░░░░███╔═╝╚█████╔╝  ██████╦╝██║░░░██║░░░
 *██╔══██║██╔══╝░░░╚═══██╗ ╚═╝██║░░██╔══╝░░██╔══██╗  ██╔══██╗██║░░░██║░░░
 *██║░░██║███████╗██████╔╝ ███████╗███████╗╚█████╔╝  ██████╦╝██║░░░██║░░░
 *╚═╝░░╚═╝╚══════╝╚═════╝░╚══════╝╚═══════╝░╚════╝░  ╚═════╝░╚═╝░░░╚═╝░░░
 *
 *███████╗███╗░░██╗░█████╗░██████╗░██╗░░░██╗██████╗░████████╗██╗░█████╗░███╗░░██╗
 *██╔════╝████╗░██║██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██║██╔══██╗████╗░██║
 *█████╗░░██╔██╗██║██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░██║██║░░██║██╔██╗██║
 *██╔══╝░░██║╚████║██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░██║██║░░██║██║╚████║
 *███████╗██║░╚███║╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██║╚█████╔╝██║░╚███║
 *╚══════╝╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═╝░╚════╝░╚═╝░░╚══╝
 *
 *░██████╗██╗░░░██╗░██████╗████████╗███████╗███╗░░░███╗
 *██╔════╝╚██╗░██╔╝██╔════╝╚══██╔══╝██╔════╝████╗░████║
 *╚█████╗░░╚████╔╝░╚█████╗░░░░██║░░░█████╗░░██╔████╔██║
 *░╚═══██╗░░╚██╔╝░░░╚═══██╗░░░██║░░░██╔══╝░░██║╚██╔╝██║
 *██████╔╝░░░██║░░░██████╔╝░░░██║░░░███████╗██║░╚═╝░██║
 *╚═════╝░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚══════╝╚═╝░░░░░╚═╝
 * 
 * 
 * AES-128 Encryption Key Expansion
 * Goal: This project aims to implement the key expansion process for AES-128 encryption.
 *
 *
 *  AES (Advanced Encryption Standard) is a widely used symmetric key encryption algorithm that operates on blocks of data. AES 128-bit, as the name suggests, uses a 128-bit key for encryption and decryption. Here's a summary of how AES 128-bit works:
 *
 * 1. Key Expansion:
 *  - The 128-bit encryption key is used to generate a set of round keys through a key expansion process.
 *     - The key expansion involves a series of mathematical operations that create a set of round keys used in the encryption and decryption processes.
 *
 * 2. Initial Round
 *     - The plaintext (data to be encrypted) is divided into a 16-byte block.
 *    - The initial round involves the bitwise XOR operation, where each byte of the block is combined with the corresponding byte of the round key (Round 0).
 *
 *  3. Main Rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey):
 *     - AES consists of multiple rounds (10 rounds for AES-128).
 *     - In each round, the following operations are performed:
 *       a. SubBytes: Each byte of the block is replaced with a corresponding byte from the S-box (a fixed substitution table).
 *       b. ShiftRows: The bytes in each row of the block are shifted left by varying amounts.
 *       c. MixColumns: Each column is transformed using a mathematical operation that provides diffusion.
 *       d. AddRoundKey: The round key for the current round is XORed with the block.
 *
 *  4. Final Round (SubBytes, ShiftRows, AddRoundKey):
 *     - The final round is similar to the main rounds but does not include the MixColumns step.
 *
 *  5. Output:
 *    - After the final round, the processed block is the ciphertext.
 *
 *  AES is highly secure and widely used due to its resistance to various cryptographic attacks. It provides confidentiality, ensuring that unauthorized parties cannot read the original data without the correct key.
 *
 *
 *
 *  Last Date Worked On: Saturday, 10/21/23
 *****************************************************************************/

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

// Declaring sBox which will be used later in encryption
const unsigned char sBox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
     0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
     0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
     0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
     0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
     0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39,
     0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
     0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21,
     0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
     0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
     0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62,
     0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
     0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
     0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
     0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9,
     0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
     0xb0, 0x54, 0xbb, 0x16}};

// Delcaring round constants, which will also later be used in encryption
const unsigned int roundConstants[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

// Declaring fixed array constants, which are used in mix columns step 
// AES Rijndael MixColumns Matrix
const unsigned char mixColumnsMatrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

// Function that prints ASCII art :)
void printArt(); 

// Function to prompt user for response
int welcome();

// Function to provide overview/history about AES
void overviewAES(); 

// Function to provide user with overview of how program works
void overviewProgram();

// Function to get a 16-byte message from the user
string getInputMessage();

// Function to generate a 128-bit AES key as a binary string
string generateAESKey();

// Function to convert a binary key (16 bytes) to a hexadecimal string
string keyToHex(const string &key);

// Function to convery the user's message to a hexadecimal string
string messageToHex(const string& input);

// Function to convert a hexadecimal key into a 4x4 matrix
vector<vector<string>> hexKeyToMatrix(const string &hexKey);

// Function to print a string in hexadecimal format
void printInHexFormat(const string &str);

// Function to extract columns from the 4x4 matrix and store them as words
vector<string> extractColumnsAsWords(const vector<vector<string>> &matrix);

// Function to rotate a word one position to the left cyclically
void rotateWordLeft(string &word);

// Function to perform S-box substitution on a single byte
unsigned char substituteByte(unsigned char byte);

// Function to perform S-box substitution on a vector of strings and return substituted values
vector<string> substituteBytesAndGetValues(vector<string> &words);

// Function to print the rotated word, original word, and the substituted subwords
void printSubstitutedValues(const vector<string> &substitutedValues, const vector<string> &words);

//Function to print values in matrix 
void printMatrix(const vector<vector< string>> &matrix);

// Overloaded function to print a vector of strings in pairs and uppercase
void printMatrix(const vector<string>& strings);

// Function to print a 4x4 matrix
void printMatrix(const vector<vector<unsigned char>> &matrix);

// Function to apply the round constant to a vector of substituted values
vector<string> applyRoundConstantToValues(const vector<string> &substitutedValues, int roundNumber);

// Function to convert an unsigned integer to a hexadecimal string
string toHex(unsigned int value);

// Function to print a hexadecimal string in uppercase with space separators
void printHexInCaps(const string &hexValue);

//Function to xorStrings
string xorStrings(const string &str1, const string &str2);

//Function to perform key round expansion and return 10 subkeys 
vector<string> keyRoundExpansion(const vector<string> &originalWords,
                                 const vector<string> &results,
                                 int roundNumber);

// Function to print key expansion details for a given round
void printKeyExpansionDetails(int roundNumber,
                              const vector<string> &originalWords,
                              const vector<string> &results,
                              const vector<string> &roundWords);

// Function to perform XOR operation on two 4x4 matrices
vector<vector<string>> xorHexMatrices(const vector<vector<string>>& matrix1, const vector<vector<string>>& matrix2);

// Function to perform the SubBytes step in AES encryption
void SubBytes(vector<vector<unsigned char>> &state);

// Function to perform the ShiftRows step in AES encryption
void ShiftRows(vector<vector<unsigned char>> &state);

// Function to multiply two numbers in the Galois Field (GF(256))
unsigned char GMul(unsigned char a, unsigned char b);

// Function to perform the MixColumns step in AES encryption
void MixColumns(vector<vector<unsigned char>> &state);

// Function to XOR ^ the round key with the state matrix
void XORWithRoundKey(vector<vector<unsigned char>>& data, const vector<string>& key);

//Function to do the entirety of encryption --> called in switch stmt
void encryption();

////////////////////////////////////////////////////////////
// START OF MAIN//
///////////////////////////////////////////////////////////
int main() {

    /*
    Main provides a menu-driven interface for AES-128 encryption and information. It includes the following features:
   - Displays an ASCII art title at the beginning. :)
   - Presents a menu to the user to choose from several options.
   - Option 1: Encrypts a 16-byte message using AES-128 encryption.
   - Option 2: Provides an overview of AES-128 encryption.
   - Option 3: Gives information about the program itself.
   - Option 4: Exits the program.
   - Repeats the menu until the user selects the exit option.
    */

    //Displays an ASCII art title.
    printArt();
    cout << "\n\n\t\tWELCOME TO THE AES 128 ENCRYPTION PROGRAM\n";
    cout << "\nThis program fully encrypts a 16-byte message using the Advanced Encryption Standard 128-bit. ";
    cout << "\nTo get started, please select a menu option. After selecting a menu option, you may need to scroll to the top of the screen to see the full results: \n";

   // The user is presented with a menu and prompted to make a choice.
  // The program handles user input, displaying relevant information or performing encryption.
  // The user can return to the menu or exit the program after each action.

int userChoice;

while (true) {
    cout << "\nPlease select a menu option:\n";
    cout << "1.) Encrypt a 16-byte Message\n";
    cout << "2.) Learn about AES 128 bits\n";
    cout << "3.) Learn about the Program\n";
    cout << "4.) Exit";
    cout << "\n\nEnter your choice (1, 2, 3, or 4): ";

    if (cin >> userChoice) {
        if (userChoice == 1) {
            encryption();
        }
        else if (userChoice == 2) {
            overviewAES();
        }
        else if (userChoice == 3) {
            overviewProgram();
        }
        else if (userChoice == 4) {
            cout << "\nExiting the program. Goodbye!\n";
            break;
        }
        else {
            cout << "Invalid choice. Please select a valid option (1, 2, 3, or 4).\n";
        }
    } else {
        cin.clear();  // Clear any error flags.
        cin.ignore(numeric_limits<streamsize>::max(), '\n');  // Ignore any remaining characters in the input buffer.
        cout << "Invalid choice. Please select a valid option (1, 2, 3, or 4).\n";
    }
}



    return 0;
}
/////////////////////////////////////////////////////////
// END OF MAIN
////////////////////////////////////////////////////////

// Function to dislay ASCII art 
void printArt() {
    cout << "    _    _____ ____                                     " << endl;
    cout << "   / \\  | ____/ ___|                                    " << endl;
    cout << "  / _ \\ |  _| \\___ \\                                    " << endl;
    cout << " / ___ \\| |___ ___) |                                   " << endl;
    cout << "/_/___\\_\\_____|____/ ___ _____                          " << endl;
    cout << "/ |___ \\( _ )  | __ )_ _|_   _|                         " << endl;
    cout << "| | __) / _ \\  |  _ \\| |  | |                           " << endl;
    cout << "| |/ __/ (_) | | |_) | |  | |                           " << endl;
    cout << "|_|_____\\___/ _|____/___| |_|_____ _____ ___ ___  _   _ " << endl;
    cout << "| ____| \\ | |/ ___|  _ \\ \\ / /  _ \\_   _|_ _/ _ \\| \\ | |" << endl;
    cout << "|  _| |  \\| | |   | |_) \\ V /| |_) || |  | | | | |  \\ |" << endl;
    cout << "| |___| |\\  | |___|  _ < | | |  __/ | |  | | |_| | |\\  |" << endl;
    cout << "|_____|_| \\_|\\____|_|_\\_\\|_| |_| __ |_| |___\\___/|_| \\_|" << endl;
    cout << "/ ___\\ \\ / / ___|_   _| ____|  \\/  |                    " << endl;
    cout << "\\___ \\\\ V /\\___ \\ | | |  _| | |\\/| |                    " << endl;
    cout << " ___) || |  ___) || | | |___| |  | |                    " << endl;
    cout << "|____/ |_| |____/ |_| |_____|_|  |_|                    " << endl;
}

// Function to provide user menu choices, returns user choice 
int welcome() {
    int choice;
    cout << "\nPlease select a menu option:\n";
    cout << "1.) Encrypt a 16-bit Message\n";
    cout << "2.) Learn about AES 128 bits\n";
    cout << "3.) Learn about the Program\n";
    cout << "4.) Exit";

    cout << "\n\nEnter your choice (1, 2, 3, or 4): ";
    cin >> choice;

    return choice;
}

// Function to display history/info about AES
void overviewAES() {
    cout << "Advanced Encryption Standard (AES) Overview\n";
    cout << "-----------------------------------------\n";
    cout << "History:\n";
    cout << "AES, also known as Rijndael, was established as a federal standard in the United States in 2001. ";
    cout << "It was selected through a competition organized by the National Institute of Standards and Technology (NIST) ";
    cout << "to find a replacement for the aging Data Encryption Standard (DES). Rijndael, designed by Vincent Rijmen ";
    cout << "and Joan Daemen, was chosen as the new encryption standard due to its excellent security and efficiency.\n";
    cout << "\nWorking Principles:\n";
    cout << "AES is a symmetric-key block cipher, which means it uses the same key for both encryption and decryption. ";
    cout << "It operates on fixed-size blocks of data, typically 128 bits (16 bytes), and uses keys of various lengths, ";
    cout << "including 128, 192, or 256 bits. In this program, we implement a key length of 128 bits. AES encryption involves several key components:\n";
    cout << "\n1. SubBytes: Substitutes each byte of the block with a corresponding value from an S-box.";
    cout << "\n2. ShiftRows: Shifts the rows of the block to provide diffusion.";
    cout << "\n3. MixColumns: Applies a matrix operation to columns, providing further diffusion.";
    cout << "\n4. AddRoundKey: XORs the block with a round key derived from the main encryption key.";
    cout << "\n\nAES operates with multiple rounds, each involving these four operations. The number of rounds depends on the key size: 10 rounds for 128-bit keys, 12 rounds for 192-bit keys, and 14 rounds for 256-bit keys. The result of these rounds is a secure and efficient encryption process that is widely used for data protection and security applications.\n";
}

// Function to display info about program 
void overviewProgram()
{
cout << "\nHere's an overview of the key components and steps in the program:";
cout << "\nHeader and Library Includes:";
cout << "\nThe program includes several C++ libraries for handling data, random number generation, and input/output.";

cout << "\n\nConstants: ";
cout << "\nThe program defines several constants used in the AES encryption process:";
cout << "\nsBox: The substitution box used for byte substitution in the encryption.";
cout << "\nroundConstants: Round constants used during key expansion.";
cout << "\nmixColumnsMatrix: A matrix used in the MixColumns step.";

cout << "\n\nInput Functions:";
cout << "\ngetInputMessage(): This function prompts the user to input a 16-byte plaintext message, ensuring that it's exactly 16 bytes long.";
cout << "\ngenerateAESKey(): This function generates a random 128-bit AES key as a binary string.";
cout << "\nkeyToHex(): Converts a binary key to a hexadecimal string.";
cout << "\nMessageToHex(): Converts the user's message to a hexadecimal string.";

cout << "\n\nKey Expansion:";
cout << "\nThe program expands the AES-128 key from the initial key using a series of operations. The key expansion is performed for 10 rounds (since it's AES-128).";
cout << "\nThe key expansion process involves:";
cout << "\nRotating words.";
cout << "\nSubstituting bytes using the S-Box.";
cout << "\nApplying round constants.";
cout << "\nCombining the results to form round keys for each round.";

cout << "\n\nMatrix Operations:";
cout << "\nKey expansion is a crucial step in the AES (Advanced Encryption Standard) algorithm, as it generates a set of round keys from the original secret key. These round keys are used in the encryption and decryption process to perform various operations on the data. In the case of AES-128, the key expansion generates 11 round keys, one for each of the 10 rounds and an initial round key. Here's a detailed breakdown of the key expansion process in AES-128:";

cout << "\n\nInitial Key:";
cout << "\nThe key expansion starts with the original secret key, which is a 128-bit (16-byte) binary key. For example, let's say the original key is 0x2b7e151628aed2a6abf7158809cf4f3c.";

cout << "\n\nRound Constants:";
cout << "\nThe key expansion uses a set of round constants (roundConstants). These are predefined constants used to help ensure that the key schedule is unique for each round. The first round constant is always 0x01, and subsequent round constants are calculated using a simple formula:";
cout << "roundConstants[i] = xtime(roundConstants[i-1]) (where xtime is a multiplication operation in a finite field).";

cout << "\n\nWord Expansion:";
cout << "\nThe 128-bit key is divided into 4 words (32 bits each). So, you have 4 words in the initial key: W[0], W[1], W[2], and W[3].";
cout << "\nFor AES-128, there are a total of 44 words to generate (11 round keys), and this expansion continues until all round keys are computed.";

cout << "\n\nWord Transformation:";
cout << "\nFor each subsequent word W[i], the key expansion applies transformations:";
cout << "\nFor i divisible by 4 (i.e., every 4th word):";
cout << "\nRotate the bytes in the word. This means the first byte moves to the end of the word.";
cout << "\nSubstitute each byte of the word using the S-Box (a predefined substitution box).";
cout << "\nXOR the first byte of the word with the round constant for that round.";
cout << "\nFor i not divisible by 4 (i.e., other words):";
cout << "\nXOR the word with the previous word (i.e., W[i] = W[i-4] ^ W[i-1]).";

cout << "\n\nRound Key Generation:";
cout << "\nAfter the transformations, you have the expanded word W[i]. The 128-bit round key RoundKey[i] for the i-th round is created by combining four words:";
cout << "\nRoundKey[i] = W[4*i] || W[4*i + 1] || W[4*i + 2] || W[4*i + 3]";
cout << "\nIn the case of AES-128, you have 11 round keys, including the initial round key.";
cout << "\nThe key expansion process generates 11 round keys for AES-128 encryption. These round keys are used in the encryption process during each of the 10 rounds. The initial round key is also used in the first round, and the subsequent round keys are used in the respective rounds for XORing with the state.";
cout << "\nThe key expansion process ensures that each round key is unique and not directly related to the original secret key, making the encryption more secure. This process allows AES-128 to provide strong security for the encrypted data.";
cout << "\nThe program uses 4x4 matrices to represent the key, message, and state.";
cout << "\nThe key matrix and message matrix are displayed.";
cout << "\nThe program applies matrix operations for the XOR operation and key expansion.";

cout << "\n\nAES Encryption:";
cout << "\nThe program performs the AES encryption rounds. Each round involves several steps:";
cout << "\nSubBytes: Each byte in the state is replaced with a corresponding byte from the S-Box.";
cout << "\nShiftRows: Bytes in each row are shifted to the left.";
cout << "\nMixColumns: Columns are mixed using matrix multiplication.";
cout << "\nXOR with Round Key: The data is combined with the round-specific subkey.";
cout << "\nThis process is performed for 10 rounds.";

cout << "\n\nOutput:";
cout << "\nThe program displays various intermediate results, including the key, key matrix, message matrix, intermediate state matrices, and the final encrypted message. In total, there are 26 functions to make this program work as intended";
cout << "\nOverall, the program provides an example of how AES-128 encryption is performed, including the key expansion process, various transformations, and matrix operations. It takes user input for the plaintext message and generates a random key to encrypt the message. The encrypted result is displayed in hexadecimal format.";
}


// Function to get a 16-byte message from the user
// Begins by prompting the user to enter a 16-byte message.
// It reads the input provided by the user, including spaces.
// If the input length is not exactly 16 bytes, it continues to prompt the user
// until a valid input is received. Finally, it returns the valid 16-byte input
// message as a string
string getInputMessage() {
  string user_input;

  // Prompt the user for input
  cout << "Please enter a 16-byte plaintext message you would like to have become encrypted: ";

  cin.ignore(); // Clear the newline character left in the input buffer

  // Read the entire line of input, including spaces
  getline(cin, user_input);

  // Continue to prompt until a 16-byte input is provided
  while (user_input.length() != 16) {
    cout << "Your input must be exactly 16 bytes long, including white spaces. Please try again." << endl;

    // Prompt the user for input again
    cout << "Please enter a 16-byte message: ";

    // Read the entire line of input, including spaces
    getline(cin, user_input);
  }

  return user_input;


}

// Function to generate a random 128-bit AES key as a binary string
// Generates a random 128-bit AES key as a binary string.
// It initializes a random number generator and uses it to generate 128 random
// bits (0 or 1). The generated bits are appended to the aesKey string as binary
// digits. The resulting AES key is returned as a binary string.
string generateAESKey() {


    const int keySize = 128; // 128 bits
    string aesKey;

    // Initialize a random number generator
    random_device rd;
    mt19937 gen(rd());

    // Generate 128 random bits (0 or 1) to create the AES key
    for (int i = 0; i < keySize; i++)
    {
        int bit = gen() % 2; // Generate a random bit (0 or 1)
        aesKey += to_string(bit); // Append the bit to the key as a string
    }

//AES PDF Example:
//  string aesKey = //"01010100011010000110000101110100011100110010000//001101101011110010010000001001011011101010110111//001100111001000000100011001110101";

 //Textbook Example:
    // string aesKey = "000011110001010101110001110010010100011111011001111010000101100100001100"
    //  "10110111101011011101011010101111011111110110011110011000";


  return aesKey;
}

// Function to convert a binary key (16 bytes) to a hexadecimal string
// It checks if the binary key length is a multiple of 4 (as 4 bits represent a
// hexadecimal digit). It then iterates through the binary key, converting each
// group of 4 bits to a hexadecimal digit. The resulting hexadecimal digits are
// appended to the hexKey string. The function returns the hexadecimal
// representation of the binary key as a string.
string keyToHex(const string &binaryKey) {
  string hexKey;

  // Ensure the binary key length is a multiple of 4 (4 bits per nibble)
  int remainder = binaryKey.length() % 4;
  if (remainder != 0) {
    cout << "Binary key must have a length that is a multiple of 4." << endl;
    return "";
  }

  // Convert each group of 4 bits to a hexadecimal digit
  for (int i = 0; i < binaryKey.length(); i += 4) {
    string nibble = binaryKey.substr(i, 4);      // Extract 4-bit nibble
    int decimalValue = stoi(nibble, nullptr, 2); // Convert to decimal
    hexKey +=
        "0123456789ABCDEF"[decimalValue]; // Append the corresponding hex digit
  }

  return hexKey;
}

/*
   Function to convert a message (string) to its hexadecimal representation.
   It takes an input string, converts each character to its hexadecimal value,
   and returns the resulting hexadecimal string.
   - The function iterates through each character of the input string.
   - For each character, it extracts its hexadecimal representation using bitwise operations.
   - The resulting hexadecimal characters are organized into pairs and returned as a string.
   Example:
   - Input: "Hello"
   - Output: "68656C6C6F"

   Note: The 'lut' array contains hexadecimal characters for the conversion.
*/
string messageToHex(const string& input) {

    // Create a static lookup table (lut) that contains the hexadecimal characters '0' to 'F'.
    static const char* const lut = "0123456789ABCDEF";

    // Get the length of the input string.
    size_t len = input.length();

    // Create a stringstream (ss) for building the hexadecimal representation.
    // Set the stringstream to output in hexadecimal and uppercase.
    stringstream ss;
    ss << hex << uppercase;

    // Iterate through each character in the input string.
    for (size_t i = 0; i < len; ++i) {

        // Get the current character (c) from the input string.
        const auto& c = input[i];

        // Extract the first 4 bits of the character, convert them to a hexadecimal character,
        // and append it to the stringstream.
        ss << lut[(c >> 4) & 0xF];

        // Extract the last 4 bits of the character, convert them to a hexadecimal character,
        // and append it to the stringstream.
        ss << lut[c & 0xF];
    }

    // Return the hexadecimal representation as a string.
    return ss.str();
}

// Function to convert a hexadecimal key into a 4x4 matrix
// It checks if the input hexKey is exactly 32 characters long (16 bytes).
// It then iterates through the 32 characters of the hexKey, extracting 2
// characters at a time as a byte. The bytes are organized into a 4x4 matrix,
// where each element represents a hexadecimal byte. The resulting matrix is
// returned.
vector<vector<string>> hexKeyToMatrix(const string &hexKey) {
  vector<vector<string>> matrix(4, vector<string>(4));

  // Ensure that the input hexKey is exactly 32 characters (16 bytes)
  if (hexKey.length() != 32) {
    cout << "Hexadecimal key must be exactly 32 characters (16 bytes) long."
         << endl;
    return matrix;
  }

  int rowIndex = 0;
  int colIndex = 0;

  // Loop through the 32 characters of the hexKey
  for (int i = 0; i < 32; i += 2) {
    string byte =
        hexKey.substr(i, 2); // Extract 2 hexadecimal characters as a byte
    matrix[rowIndex][colIndex] = byte;

    // Move to the next row or wrap to the next column
    if (++rowIndex >= 4) {
      rowIndex = 0;
      colIndex++;
    }
  }

  return matrix;
}

/*
   Function to print a given string in a hexadecimal format with spaces between bytes in CAPS.
   - The function iterates through the input string character by character.
   - It extracts two characters at a time, representing a byte.
   - Uppercases all characters in the byte for consistent hexadecimal representation.
   - Adds a space before each byte except the first one.
   - Prints the formatted hexadecimal string.
*/
void printInHexFormat(const string &str) {

    // Loop through the string character by character.
    for (size_t i = 0; i < str.length(); i += 2) {

        // Check if this is not the first byte in the output.
        if (i > 0) {
            cout << ' '; // Add a space before each byte except the first one.
        }

        // Extract a two-character substring representing a byte from the input string.
        string byte = str.substr(i, 2);

        // Convert each character in the byte to uppercase (hexadecimal representation is typically in uppercase).
        for (char &c : byte) {
            c = toupper(c);
        }

        // Print the byte to the console.
        cout << byte;
    }
}

// Function to extract columns from the 4x4 matrix and store them as words
// It initializes an empty vector words to store the extracted words.
// The outer loop iterates through each column in the matrix (0 to 3).
// Inside the outer loop, there is an inner loop that iterates through each row
// in the current column. Within the inner loop, the function concatenates the
// element from the current row in the column to form a word (word). After
// forming a complete word representing a column, it is stored in the words
// vector. The function continues this process for all columns in the matrix.
// Finally, it returns the vector of extracted words, where each word represents
// a column from the matrix.
vector<string> extractColumnsAsWords(const vector<vector<string>> &matrix) {
  vector<string> words;

  // Iterate through each column in the matrix
  for (int col = 0; col < 4; col++) {
    string word;

    // Iterate through each row in the column
    for (int row = 0; row < 4; row++) {
      // Concatenate the element from the current row in the column to form a
      // word
      word += matrix[row][col];
    }

    // Store the formed word representing a column from the matrix
    words.push_back(word);
  }

  // Return the vector of extracted words representing columns
  return words;
}

// Function to rotate a word one position to the left while preserving the byte format
// Takes a reference to a string word as input.
// It rotates the word one position to the left while preserving the byte format.
// The rotation is achieved by extracting substrings from the input word and rearranging them. 
// The updated rotated word is assigned back to the input word 
void rotateWordLeft(string &word) {
  // Rotate the word by one position to the left by rearranging its substrings
  string rotatedWord = word.substr(2) + word.substr(0, 2);
  word = rotatedWord; // Update the input word with the rotated value
}


// Function to perform S-box substitution on a single byte
// Extract the row and column indices from the input byte
// To perform S-box substitution, we need to split the input byte into two
// parts:
// - The upper 4 bits represent the row index in the S-box table.
// - The lower 4 bits represent the column index in the S-box table.
// To get the row index, we shift the byte 4 bits to the right and mask it with
// 0x0F to keep only the upper 4 bits. To get the column index, we simply mask
// the byte with 0x0F to keep the lower 4 bits
// Why 0X0F --> The S-box is organized as a 16x16 grid, where each row and each
// column is indexed from 0x00 to 0x0F (0 to 15 in decimal). When extracting the
// row and column indices from a byte, we want to keep only the lower 4 bits
// (the rightmost 4 bits) for the column index and the upper 4 bits (the
// leftmost 4 bits) for the row index. 0x0F in hexadecimal is equivalent to
// 00001111 in binary. Using 0x0F as a mask with a bitwise AND operation (&)
// allows us to keep only the lower 4 bits while setting the upper 4 bits to
// zero. This effectively extracts the lower 4 bits, which represent the column
// index
// Function to perform S-box substitution on a single byte
unsigned char substituteByte(unsigned char byte) {
  // Extract the row and column indices from the input byte
  unsigned char row = (byte >> 4) & 0x0F; // Upper 4 bits (row)
  unsigned char col = byte & 0x0F;        // Lower 4 bits (col)

  // Perform the S-box substitution and return the result
  return sBox[row][col];
}

// Function to perform S-box substitution on a vector of strings and return substituted values.
vector<string> substituteBytesAndGetValues(vector<string> &words) {
    vector<string> substitutedValues; // Store substituted values here

    // Iterate through each word in the input vector
    for (int i = 0; i < words.size(); i++) {
        string result = ""; // Initialize result as an empty string

        // Iterate through each 8-bit chunk in the current word
        for (int j = 0; j < 4; j++) {
            // Extract an 8-bit chunk (2 characters) from the current word and convert it to an unsigned char.
            unsigned char originalByte = stoi(words[i].substr(j * 2, 2), nullptr, 16);

            // Perform S-box substitution on the extracted byte.
            unsigned char substitutedByte = substituteByte(originalByte);

            // Convert the substituted byte back to a hexadecimal string.
            stringstream ss;
            ss << hex << setw(2) << setfill('0') << (int)substitutedByte;
            string substitutedByteStr = ss.str();

            result += substitutedByteStr; // Append the substituted byte to the result.
        }

        substitutedValues.push_back(result); // Store the substituted value as a string.
    }

  return substitutedValues;
}

// Function to print the rotated word, original word, and the substituted subwords
// This function takes two vectors as input: 'substitutedValues' containing 32-bit substituted values
// and 'words' containing hexadecimal words. It prints information about the rotated word, original word,
// and the substituted subwords for each word in the vectors.
void printSubstitutedValues(const vector<string> &substitutedValues, const vector<string> &words) {
  for (int i = 0; i < words.size(); i++) {
    cout << "\nRotated Word (w[" << i << "]):" << endl;
    cout << "w[" << i << "] = ";
    printInHexFormat(words[i]);
    cout << endl;

       cout << "Substituted Subwords (w[" << i << "]):" << endl;
    string result = substitutedValues[i];

   // Iterate through each of the 4 bytes in the substituted 32-bit value
for (int j = 0; j < 4; j++) {
  string originalByteStr = words[i].substr(j * 2, 2);

  // Print the original byte (in hexadecimal format)
  cout << "Original Byte: ";
  printInHexFormat(originalByteStr);

  string substitutedByteStr = result.substr(j * 2, 2);
  // Convert substituted byte to uppercase
  for (char &c : substitutedByteStr) {
    c = toupper(c);
  }

  // Print the substituted byte (in hexadecimal format) in uppercase
  cout << "  Substituted Byte: " << substitutedByteStr << endl;
}

    // Print values of s-box sub
    cout << "\nResult after applying S-box substitution: ";
    printInHexFormat(result);
    cout << endl;
  }
}

/*
  Function to print a 4x4 matrix of strings.
   - The function iterates through each row and column of the 4x4 matrix.
   - It prints the values at each position in the matrix with a space separator.
*/
void printMatrix(const vector<vector<string>> &matrix) {
    // Loop through rows (4 rows in a 4x4 matrix)
    for (int i = 0; i < 4; i++) {
        // Loop through columns (4 columns in a 4x4 matrix)
        for (int j = 0; j < 4; j++) {
            // Print the value at row i and column j in the matrix.
            cout << matrix[i][j] << " ";
        }
        // Print a new line to separate rows.
        cout << endl;
    }
}

/*
   Overloaded function to print a vector of strings in pairs and uppercase.
   - The function iterates through each string in the input vector.
   - For each string, it processes it in pairs of 2 characters, printing them as hexadecimal bytes in uppercase format.
   - A space separates each pair, and a new line separates the strings.
*/
void printMatrix(const vector<string>& strings) {
    // Loop through each string in the vector.
    for (const string& hexStr : strings) {
        // Loop through the string in pairs of 2 characters.
        for (size_t i = 0; i < hexStr.size(); i += 2) {
            // Print each pair of characters as a hexadecimal byte in uppercase format.
            cout << hex << uppercase << setw(2) << setfill('0') << hexStr.substr(i, 2) << ' ';
        }
        // Print a new line to separate the strings.
        cout << endl;
    }
}

// Function to apply the round constant to a vector of substituted values
// Takes a vector of unsigned integers substitutedValues and an integer
// roundNumber as input. It ensures that the roundNumber is within the valid
// range (0 to 9 for AES-128). For each value in the substitutedValues vector,
// it XORs the value with the corresponding round constant. The results of the
// XOR operations are stored in the results vector, which is then returned.
vector<string> applyRoundConstantToValues(const vector<string>& substitutedValues, int roundNumber) {
    vector<string> results;

    if (roundNumber < 0 || roundNumber >= 10) {
        cout << "Invalid round number. It must be between 0 and 9." << endl;
        return results;
    }

    // Convert the round constant to an unsigned int
    unsigned int roundConstant = roundConstants[roundNumber];

    // Iterate through substituted values
    for (const string& value : substitutedValues) {
        // Ensure that the value and round constant have the same length
        if (value.length() != 8) {
            cout << "Input values must have a length of 8 characters." << endl;
            return results;
        }

        // Convert the value and round constant to unsigned ints
        unsigned int valueInt = stoul(value, nullptr, 16);

        // Perform the XOR operation
        unsigned int resultInt = valueInt ^ roundConstant;

        // Convert the result back to a hexadecimal string
        stringstream ss;
        ss << hex << setw(8) << setfill('0') << resultInt;
        results.push_back(ss.str());
    }

    return results;
}

// Function to convert an int and convert it to hexidecimal
string toHex(unsigned int value) {
    stringstream stream; // Create a stringstream for converting to hexadecimal.
    stream << hex << setw(2) << setfill('0') << value;
    // 'hex' sets the output format to hexadecimal.
    // 'setw(2)' ensures the output is at least two characters wide.
    // 'setfill('0')' fills any extra width with leading zeros.
    // 'value' is converted and appended to the stringstream.

    return stream.str(); // Return the formatted hexadecimal string.
}

// Function to print a hexadecimal string with leading zeros, two characters at a time, with a space 
//inbetween each pair, and in CAPS
void printHexInCaps(const string &hexValue) {
  string hexStr = hexValue;

  // Print the hexadecimal string with space separators
  for (size_t i = 0; i < hexStr.size(); i += 2) {
    cout << hexStr[i] << hexStr[i + 1] << ' ';
  }
}

/*
   Function to perform the XOR operation between two hexadecimal strings.
   Takes in two hexadecimal strings, and returns the XORED result 
   - The function iterates through the input strings in pairs of 2 characters.
   - It extracts two characters from each string, converts them to integers.
   - It performs the XOR operation on the two integers and appends the result as a hexadecimal string.
   - The resulting hexadecimal string represents the XOR result of the input strings.
*/
string xorStrings(const string &str1, const string &str2) {
    string result; // Initialize the result string to store the XOR result.

    // Iterate through the input strings in pairs of 2 characters.
    for (size_t i = 0; i < str1.length(); i += 2) {
        string byte1 = str1.substr(i, 2); // Extract 2 characters from the first string.
        string byte2 = str2.substr(i, 2); // Extract 2 characters from the second string.

        int value1 = stoi(byte1, nullptr, 16); // Convert the first byte to an integer.
        int value2 = stoi(byte2, nullptr, 16); // Convert the second byte to an integer.

        int xorResult = value1 ^ value2; // Perform the XOR operation.

        result += toHex(xorResult); // Convert the XOR result back to a hexadecimal string and append it.
    }

    return result; // Return the final result of the XOR operation.
}

// Function to perform key expansion for a given round and return the new words
// Takes the original words of the key (W0 to W3), the results vector from a
// previous step, and the current round number as input. It calculates the new
// words (W4 to W7) for the current round by XORing the original words with the
// result value and stores them as hexadecimal strings. The function then prints
// the resulting round key and returns it as a vector of strings. The round key
// expansion is an essential step in the AES-128 encryption process, and this
// function helps generate the necessary round keys.
vector<string> keyRoundExpansion(const vector<string> &originalWords,
                                 const vector<string> &results,
                                 int roundNumber) {
  // Ensure that roundNumber is within a valid range (0 to 9 for AES-128)
  if (roundNumber < 0 || roundNumber >= 10) {
    cout << "Invalid round number. It must be between 0 and 9." << endl;
    return {}; // Return an empty vector or handle the error as needed
  }

  // Get the result value from the results vector
  string result = results[3];

  // Calculate the final words (W4 to W7) for the current round by XORing with the result
  string finalW4 = xorStrings(originalWords[0], result);
  string finalW5 = xorStrings(originalWords[1], finalW4);
  string finalW6 = xorStrings(originalWords[2], finalW5);
  string finalW7 = xorStrings(originalWords[3], finalW6);

  // Store the resulting round key as a vector of hexadecimal strings
  vector<string> roundWords;
  roundWords.push_back(finalW4);
  roundWords.push_back(finalW5);
  roundWords.push_back(finalW6);
  roundWords.push_back(finalW7);

 // Print the resulting round key for debugging or display purposes
cout << "\n\nROUNDS " << roundNumber + 1 << " KEY:  ";
for (const string &word : roundWords) {
  printInHexFormat(word);
  cout << ' '; // Add a space after each byte
}

  // Return the resulting round key as a vector of hexadecimal strings
  return roundWords;
}

// Function to print key expansion details for a given round
void printKeyExpansionDetails(int roundNumber,
                              const vector<string> &originalWords,
                              const vector<string> &results,
                              const vector<string> &roundWords) {
  // Print key expansion details
  cout << "\nSubkey Round " << roundNumber + 1 << " Calculations:" << endl;

  // Print the original words (W0 to W3)
  cout << "\nW0:       ";
  printInHexFormat(originalWords[0]);
  cout << "\t|| W1:    ";
 printInHexFormat(originalWords[1]);
  cout << "\t ||  W2:    ";
  printInHexFormat(originalWords[2]);
  cout << "  ||  W3:    ";
  printInHexFormat(originalWords[3]);

  // Print G(W3) and the new words (W4 to W7)
  cout << "\nG(W3):  ^ ";
 printInHexFormat(results[3]);
  cout << "\t|| W4: ^  ";
 printInHexFormat(roundWords[0]);
  cout << "\t ||  W5: ^  ";
  printInHexFormat(roundWords[1]);
  cout << "  ||  W6: ^  ";
 printInHexFormat(roundWords[2]);

  // Print the resulting round key
  cout << "\n         -------------\t||\t  -------------- ||\t  -------------  "
          "||\t  --------------";
  cout << "\nW4:       ";
  printInHexFormat(roundWords[0]);
  cout << "   || W5:    ";
 printInHexFormat(roundWords[1]);
  cout << "    ||  W6:    ";
 printInHexFormat(roundWords[2]);
  cout << "  ||  W7:    ";
  printInHexFormat(roundWords[3]);

  cout << endl;
}

/*
   Function to perform XOR operation on two 4x4 matrices of hexadecimal strings.
   - It iterates through each element of the input matrices.
   - For each element, it extracts two-character hexadecimal values, converts them to integers.
   - It performs the XOR operation on the integers and stores the result as a hexadecimal string with leading zeros.
   - The resulting 4x4 matrix represents the XOR results of the input matrices.
*/
vector<vector<string>> xorHexMatrices(const vector<vector<string>>& matrix1, const vector<vector<string>>& matrix2) {
    vector<vector<string>> result(4, vector<string>(4));

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            // Extract the two-character hexadecimal values
            string hexValue1 = matrix1[i][j];
            string hexValue2 = matrix2[i][j];

            // Perform XOR operation and store the result as a hexadecimal string with leading zeros
            int value1 = stoi(hexValue1, nullptr, 16);
            int value2 = stoi(hexValue2, nullptr, 16);
            int xorResult = value1 ^ value2;

            // Convert the XOR result back to a hexadecimal string with leading zeros.
            stringstream ss;
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << xorResult;
            result[i][j] = ss.str();
        }
    }

    return result;
}

/*
   Function to perform the SubBytes step in AES encryption.
   - The function iterates through each byte in the 4x4 state matrix.
   - For each byte, it extracts the row and column values.
   - It uses these values to look up a substitution value from the S-Box (predefined substitution table).
   - The original byte in the state matrix is replaced with the corresponding S-Box substitution.
*/
void SubBytes(vector<vector<unsigned char>> &state) {
    // Loop through the rows of the 4x4 state matrix
    for (int i = 0; i < 4; i++) {
        // Loop through the columns of the 4x4 state matrix
        for (int j = 0; j < 4; j++) {
           // Extract the current byte from the state matrix.
              unsigned char byte = state[i][j];

          // Extract the row value from the byte (the upper 4 bits) by shifting right by 4 bits and masking with 0x0F (binary 00001111).
              unsigned char row = (byte >> 4) & 0x0F;

         // Extract the column value from the byte (the lower 4 bits) by masking with 0x0F (binary 00001111).
              unsigned char col = byte & 0x0F;

            // Substitute the byte using the S-Box
            state[i][j] = sBox[row][col];
        }
    }
}


/*
   Function to perform the ShiftRows step in AES encryption.
   - The function performs circular shifts on each row (except the first row) of the state matrix.
   - For each row, it temporarily stores the shifted values, updating the row with the shifted values.
   - The number of shifts for each row is determined by the row index.
*/
// Function to perform the ShiftRows step in AES encryption
void ShiftRows(vector<vector<unsigned char>> &state) {
    for (int i = 1; i < 4; i++) {
        // Perform circular shifts for each row
        vector<unsigned char> temp(4);
        for (int j = 0; j < 4; j++) {
            temp[j] = state[i][(j + i) % 4];
        }
        state[i] = temp;
    }
}



/*
   Function to multiply two numbers (a and b) in the Galois Field GF(256) and return results.
   - The function performs multiplication in GF(256) using the irreducible polynomial 0x1B.
   - It iterates through the bits of the second number 'b', checking if each bit is set.
   - If a bit of 'b' is set, it XORs the first number 'a' with the current result 'p'.
   - For each bit iteration, 'a' is left-shifted, and if the leftmost bit is set (overflow), it's XORed with 0x1B.
   - The result 'p' accumulates the XORed values to achieve the multiplication result in GF(256).
   - Essentially, we used finite field arithmeitc operations to get the result. This took a lot of work on paper to solve haha :)
*/
unsigned char GMul(unsigned char a, unsigned char b) {
    unsigned char p = 0; // Initialize the result 'p'.
    unsigned char carry;

    for (int i = 0; i < 8; i++) { // Iterate through the 8 bits of 'b'.
        if (b & 1) {
            // If the least significant bit of 'b' is set, XOR 'a' with 'p'.
            p ^= a;
        }

        carry = a & 0x80; // Check if the leftmost bit of 'a' is set.
        a <<= 1; // Left-shift 'a'.

        if (carry) {
            a ^= 0x1B; // XOR 'a' with 0x1B for irreducible polynomial if the carry bit was set.
        }

        b >>= 1; // Right-shift 'b' to process the next bit.
    }

    return p; // Return the result of the multiplication in GF(256).
}


/*
   Function to perform the MixColumns step in AES encryption.
   - The function applies the MixColumns transformation to the state matrix.
   - It multiplies each column of the state matrix by a predefined MixColumns matrix using the GMul function.
   - The result is stored in a temporary matrix 'result' and then copied back to the 'state' matrix.
*/
void MixColumns(vector<vector<unsigned char>> &state) {
    vector<vector<unsigned char>> result(4, vector<unsigned char>(4, 0)); // Initialize a temporary matrix for the result.

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            // Apply the MixColumns transformation to each column
            for (int k = 0; k < 4; k++) {
                // Multiply the elements using the GMul function and XOR the results.
                result[i][j] ^= GMul(mixColumnsMatrix[i][k], state[k][j]);
            }
        }
    }

    // Copy the result back to the state matrix.
    state = result;
}

/*
   Function to perform the XOR operation of data with a round key.
   - XORs each element in the data matrix with corresponding elements from the round key.
   - The key elements are converted from hexadecimal strings to integers for the XOR operation.
   - The key elements are cycled through as needed to match the data matrix size.
*/
void XORWithRoundKey(vector<vector<unsigned char>>& data, const vector<string>& key) {
    int keyIndex = 0; // Initialize the index for cycling through the key.

    for (int i = 0; i < data.size(); i++) {
        for (int j = 0; j < data[i].size(); j++) {
            // Convert the hexadecimal string from the key to an integer
            int keyByte = stoi(key[keyIndex], nullptr, 16);

            // Perform the XOR operation with the key element and the data element.
            data[i][j] ^= static_cast<unsigned char>(keyByte);

            // Increment the key index and cycle through the key as needed.
            keyIndex = (keyIndex + 1) % key.size();
        }
    }
}


/*
   Function to print a 4x4 matrix of unsigned char values in uppercase hexadecimal format.
   - Iterates through each element of the matrix.
   - It prints each element in uppercase hexadecimal format with leading zeros.
   - The elements are separated by spaces, and each row is printed on a new line.
   - This function is useful for debugging and displaying the state matrix in AES encryption.
*/
void printMatrix(const vector<vector<unsigned char>>& matrix) {
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            // Format and print each matrix element as an uppercase hexadecimal string.
            cout << hex << uppercase << setw(2) << setfill('0') << static_cast<int>(matrix[row][col]) << " ";
        }
        cout << endl; // Start a new line for the next row.
    }
    cout << endl; // Add an extra newline for separation.
}


void encryption()
{

 /*
   * Step 1: Get User Input and Randomly Generate an AES-128 Bit Key in Binary
   *
   * In this step of the AES key expansion process, we first get the user input for 
   * the message they would like encrypted. Next a random AES-128 bit key is
   * generated as a binary string. This key serves as the starting point for
   * the key expansion process, from which round keys are derived.
   *
   * The code snippet below demonstrates this step:
   *
   * - It calls the 'generateAESKey' function to create a random AES-128 bit
   * key. This function returns the key as a binary string.
   *
   * - The generated AES-128 key in binary format is printed to the console to
   *   serve as the initial key for the key expansion process.
   *
   * This random key is essential for ensuring the security of the AES
   * encryption algorithm, as the key expansion process relies on it to create
   * round keys used in encryption.
   */

  // Call the getInputMessage function to get the input
   string message = getInputMessage();

  // Display the message
    cout << "Message: " << message << endl;

  // Generate random AES-128 key as a binary string
  string aesKey = generateAESKey();
  cout << "\nStep 1: Randomly Generate an 128 Bit Key in Binary: ";
  cout << "\nAES-128 Key (Binary): " << aesKey << endl;


  /*
   * Step 2: Convert Binary Key to Hexadecimal
   *
   * In this step of the AES key expansion process, the previously generated
   * binary AES-128 bit key is converted into its hexadecimal representation.
   * The conversion from binary to hexadecimal is commonly performed to make
   * the key more human-readable and facilitate further operations.
   *
   * The code snippet below demonstrates this step:
   *
   * - It calls the 'keyToHex' function to convert the binary AES key into
   *   its corresponding hexadecimal representation.
   *
   * - The resulting AES-128 key in hexadecimal format is printed to the
   * console, using uppercase letters for the hexadecimal digits for clarity.
   *
   * Converting the key to hexadecimal format is useful for visualizing and
   * presenting the key, (128 bits would be pretty hard to read in binary),
   * This also makes the later encyprtion steps much easier to perform on a hex matrix and 
   * math easier to verify. 
   */

  cout << "\nStep 2: Convert Key from Binary into Hex: ";
  cout << "\nAES-128 Key (Hex): ";
  // Convert the binary key to a 32-character hexadecimal key
  string hexKey = keyToHex(aesKey);
  printHexInCaps(hexKey);
  cout << endl;

  /*
   * Step 3: Organize the Hexadecimal Key into a 4x4 Matrix
   *
   * In this step of the AES key expansion process, the AES-128 key in
   * hexadecimal format is organized into a 4x4 matrix. This matrix structure is
   * essential for performing subsequent operations during the key expansion
   * process, such as rotation and substitution.
   *
   * The code snippet below demonstrates this step:
   *
   * - It calls the 'hexKeyToMatrix' function to convert the AES-128 key in
   * hexadecimal format into a 4x4 matrix. Each element in the matrix
   * corresponds to a hexadecimal digit from the key.
   *
   * - The resulting key matrix is printed to the console in a 4x4 format, with
   * 4 rows and 4 columns, making it easier to visualize the organization of the
   * key for subsequent operations.
   *
   * Organizing the key into a matrix is a fundamental step in the AES key
   * expansion process, as it sets the stage for the matrix-based
   * transformations that occur in the subsequent rounds.
   */
  cout << "\nStep 3: Outlay key into a 4X4 Matrix: ";
  cout << "\nAES-128 Key Matrix:" << endl;

  // Convert the hexKey to a 4x4 matrix
  vector<vector<string>> keyMatrix = hexKeyToMatrix(hexKey);

  // Print out the matrix with 4 rows and 4 columns
  printMatrix(keyMatrix);

  /*
   * Step 4: Extract Words (Columns) from the Key Matrix
   *
   * In this step of the AES key expansion process, the key matrix, which was
   * organized in a 4x4 format in the previous step, is dissected to extract
   * columns as individual words. These extracted words are the starting point
   * for generating the round keys.
   *
   * The code snippet below demonstrates this step:
   *
   * - It calls the 'extractColumnsAsWords' function to extract columns from the
   * key matrix and store them as individual words in the 'words' vector.
   *
   * - A copy of the 'words' vector is made and stored in 'originalWord.' This
   * copy will be used later in the key expansion process when XORing the
   * results to form the round keys.
   *
   * - The extracted words (columns) are printed to the console in hexadecimal
   * format. Each word represents one of the columns from the key matrix.
   *
   * Extracting words from the key matrix is a critical step in AES key
   * expansion, as these words serve as the basis for subsequent operations to
   * generate round keys.
   */

  // Display words from matrix in columns
  cout << "\nStep 4: Display Words (columns) from Matrix: ";
  cout << "\nWords (w[0] to w[3]):" << endl;

  // Extract columns as words
  vector<string> words = extractColumnsAsWords(keyMatrix);

  // Make a copy of the words vector, this will be used later when we start ^ing
  // all the results to form the round keys
  vector<string> originalWord(words);

  for (int i = 0; i < 4; i++) {
    cout << "w[" << i << "] = ";
    printHexInCaps(words[i]); // Display in hex format
    cout << endl;
  }

/*
   * Step 5: Left-Cyclically Shift Each Hex Element in the Word
   *
   * In this step of the AES key expansion process, each word in the key
   * expansion undergoes a left-cyclic shift operation by one postion.
   *
   * The code snippet below demonstrates this step:
   *
   * - It iterates through the first four words in the 'words' vector.
   * - For each word, it performs a left-cyclic shift operation using the
   *   'rotateWordLeft' function, which shifts the elements of the word one
   *   position to the left.
   * - The result of the shift is printed to the console in hexadecimal format.
   *
   */

  cout << "\nStep 5: Shift Each Hex Element in the Word 1 Cyclical Position to "
          "the Left: ";
  cout << "\nRotated Words (w[0] to w[3]):" << endl;
  for (int i = 0; i < 4; i++) {
    rotateWordLeft(words[i]); // Rotate the word
    cout << "w[" << i << "] = ";
    printHexInCaps(words[i]); // print the word in hex format
    cout << endl;
  }


/*
   * Step 6 and 7: S-Box Substitution, Round Constant Application, and Printing
   *
   * In this step of the AES key expansion process, the following operations are
   * performed:
   *
   * 1. S-box Substitution: Each word in the key is substituted with
   * corresponding values from the AES S-box (SubBytes operation). This step
   * enhances the cryptographic strength and non-linearity of the key schedule.
   *
   * 2. XOR with Round Constant: The result of the S-box substitution for each
   * word is XORed with the current round's constant value. This round constant
   * varies from one round to the next and is an integral part of the key
   * expansion process.
   *
   * 3. Printing Results: After performing the S-Box substitution and applying
   * the round constant, the results are printed to the console in a
   * human-readable format. This step is essential for visualizing and verifying
   * the key expansion process.
   *
   * The code snippet below demonstrates this step:
   *
   * - It iterates through each word in the key expansion.
   * - For each word, it first performs the S-box substitution (SubBytes) and
   * stores the result in 'substitutedValues'.
   * - It then XORs the substituted value with the current round constant, which
   * is stored in 'roundConstants'.
   * - The result is printed in the form of a bitwise XOR operation.
   *
   * This step finalizes the generation of the round keys for the current round,
   * and the resulting values are stored in 'resultsRound1' for subsequent use.
   * This combined step plays a critical role in the generation of the round
   * keys and provides visibility into the key expansion process.
   *
   * Note: printInHexFormat is used to print these values in uppercase hexadecimal
   * format, with each pair seperated by a space.This function is super helpful, since
   * we do a lot of printing to help visualize what is happening. 
   */

  cout << "\nStep 6: Map Each Hex Value to the Appropriate S-Box Value: ";

  // Call the substituteBytesAndGetValues function to perform S-box substitution
  vector<string> substitutedValues = substituteBytesAndGetValues(words);
  printSubstitutedValues(substitutedValues, words); 


  // Call applyRoundConstantToValues to apply the round constant to the
  // substituted values
  vector<string> resultsRound1 = applyRoundConstantToValues(substitutedValues, 0);

  cout << "\nStep 7.) Results after applying S-box Substitution and Round "
          "Constant:" << endl;
  for (int i = 0; i < substitutedValues.size(); i++) {
    cout << "G(w[" << i << "]) = ";
    printInHexFormat(substitutedValues[i]);

   cout << " ^ 0x" << setw(8) << setfill('0') << hex << roundConstants[0]; // Print round constant
   cout << " = ";
     printInHexFormat(resultsRound1[i]); 
     cout << endl; 

  }

/*
 * AES Key Expansion Process
 *
 * This section of code is responsible for the key expansion process
 *
 * The key expansion process is divided into multiple rounds. In each round, the
 * original key is transformed to create a set of round-specific subkeys. These
 * subkeys are used in the subsequent rounds of encryption.
 *
 * Essentially each involves several steps such as rotating words, substituting bytes, applying round constants,
 * to expand the key properly 
 *
 * Here is a breakdown of the code for each round:
 *
 * ROUND 1:
 * - Initialize roundNumber to 0 to indicate the first round.
 * - Call the keyRoundExpansion function to expand the original key for round 1.
 * - Print key expansion details for round 1 using printKeyExpansionDetails
 *   function.
 *
 * ROUND 2 to ROUND 10:
 * - Repeat the following steps for rounds 2 through 10:
 *   - Update roundNumber to the current round.
 *   - Make a copy of the words from the previous round to work with.
 *   - Rotate the last word in the key left (circular shift).
 *   - Perform S-box substitution using substituteBytesAndGetValues function.
 *   - Apply the round constant to the substituted values using
 *     applyRoundConstantToValues function.
 *   - Expand the key for the current round using keyRoundExpansion function.
 *
 * The process continues for rounds 2 to 10, each time modifying the key to
 * generate a set of subkeys. These subkeys will be used in the encryption
 * process.
 *
 * It's important to note that this code is just a part of a larger cryptographic
 * algorithm, and the key expansion is a crucial step in ensuring the security
 * of the encryption process. This marks about 50% of the project being completed
 */
cout << "\nStep 8.) Key Expansion Results: ";
vector<vector<string>> roundKeys; // Use vector<string> for roundKeys
vector<string> roundWords = keyRoundExpansion(originalWord, resultsRound1, 0);
vector<vector<string>> substitutedValuesRound(11); // 0 is not used

// Perform key expansion for round 0 outside the loop
// Create a vector to store the round 0 key
vector<string> round0Key;

// Iterate through each word in roundWords
for (const string& word : roundWords) {
    // Split each word into 4 two-character segments and add them to round0Key
    for (int j = 0; j < 4; ++j) {
        round0Key.push_back(word.substr(j * 2, 2));
    }
}

// Add round0Key to the list of round keys
roundKeys.push_back(round0Key);

// Print details of key expansion for round 0
// Parameters:
// - 0: Round number
// - originalWord: The original key word
// - resultsRound1: Intermediate results for key expansion
// - roundWords: Round words derived from the original key
printKeyExpansionDetails(0, originalWord, resultsRound1, roundWords);

// Start the loop from round 1
for (int roundNumber = 1; roundNumber < 10; ++roundNumber) {
    // Make a copy of the original words
    vector<string> originalRoundWords = roundWords;

    // Rotate the word left
    rotateWordLeft(roundWords[3]);

    // Perform S-box substitution
    substitutedValuesRound[roundNumber] = substituteBytesAndGetValues(roundWords);

    // Apply the round constant to the round values
    vector<string> resultsRound = applyRoundConstantToValues(substitutedValuesRound[roundNumber], roundNumber);

    // Expand the key for the next round
    roundWords = keyRoundExpansion(originalRoundWords, resultsRound, roundNumber);

    // Convert the roundWords to a vector of round keys and store it
    vector<string> roundKey; // Use vector<string> for roundKey
    for (const string& word : roundWords) {
        for (int j = 0; j < 4; ++j) {
            roundKey.push_back(word.substr(j * 2, 2)); 
        }
    }

    roundKeys.push_back(roundKey);
    // Print key expansion details for the current round
    cout << endl;
    printKeyExpansionDetails(roundNumber, originalRoundWords, resultsRound, roundWords);
}

// Reorder the existing keys to form transposed keys which will be used in last steps of encryption below
for (int i = 0; i < roundKeys.size(); ++i) {
    vector<string> reorderedKey(16);
    for (int j = 0; j < 4; ++j) {
        for (int k = 0; k < 4; ++k) {
            reorderedKey[j + k * 4] = roundKeys[i][k + j * 4];
        }
    }
    roundKeys[i] = reorderedKey;
}

/////////////////END OF ROUND EXPANSION/////////////////////////////////////////////////// 

/*
 * Convert User's Input Message to Hexadecimal Format
 *
 * This section of code is responsible for converting the user's input message
 * to hexadecimal format as part of the AES encryption process.
 *
 * Conversion Process:
 * - Display information about the step in the encryption process.
 * - Show the original user's message.
 * - Convert the message to its hexadecimal representation using the
 *   messageToHex function.
 * - Display the message in hexadecimal format.
 *
 * The conversion to hexadecimal format is a necessary step in AES encryption,
 * as the algorithm works on bytes and requires the input data to be in a specific
 * format for processing.
 *
 * It's essential for understanding the transition from the user's input message to
 * the internal representation used in the encryption process.
 */

//Convert the user's input message to hexadecimal format
    cout << "\n\n------------------------------------------------------------------------------";
    cout << "\n\nStep 9: Convert User's Input Message to Hex: ";
    cout << "\n\nMessage: " << message; 
    cout << "\nUser's Message in Hex: ";
    string hexMessage = messageToHex(message);
    printHexInCaps(hexMessage);
    cout << endl;


/*
 * Steps 10 & 11.) Hexadecimal Key Conversion and State Initialization
 *
 * This section of code includes multiple steps related to the initialization of the AES
 * encryption state and the conversion of a hexadecimal key to a 4x4 matrix.
 *
 * Step 1: Convert the hexKey to a 4x4 matrix
 * - Convert the hexKey (message) to a 4x4 matrix using the hexKeyToMatrix function.
 * - Display the matrix to visualize the hex message in a 4x4 format.
 *
 * Step 2: Initialize the state as a 4x4 matrix from the input message
 * - Create an empty 4x4 matrix called 'state' to represent the AES state.
 *
 * Step 3: XOR the Original Key and Hex Message
 * - XOR the original message (hexMessageMatrix) with the key (keyMatrix) to obtain
 *   a result matrix. This simulates the initial mixing of the key and message.
 * - Display the original message, key, and the XORed result matrix.
 *
 * Step 4: Set the state array to the resultMatrix
 * - Copy the values from the result matrix to the 'state' matrix, converting them to
 *   unsigned characters.
 *
 * These steps are essential in the AES encryption process, as they prepare the initial
 * state and key information for further rounds of encryption.
 */
    // Convert the hexKey to a 4x4 matrix
    vector<vector<string>> hexMessageMatrix = hexKeyToMatrix(hexMessage);
    cout << "\nStep 10.) Display Hex Message as 4X4 Matrix: " << endl;
    printMatrix(hexMessageMatrix);

    // Initialize state as a 4x4 matrix from your input message
   vector<vector<unsigned char>> state(4, vector<unsigned char>(4));


    cout << "\nStep 11.) XORed Original Key and Hex Message: " <<endl;
   vector<vector<string>> resultMatrix = xorHexMatrices(hexMessageMatrix, keyMatrix);

    cout << "Original Mesage: " << endl;
    printMatrix(hexMessageMatrix);

     cout << "\n   ^   " << endl;

    cout << "\nKey: " << endl;
    printMatrix(keyMatrix);

     cout << "\n   =   " << endl;

    cout << "\nXORED Results: " << endl;
    printMatrix(resultMatrix);

// set the state array to the resultMatrix
for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
        // Copy the value from resultMatrix to state
        state[i][j] = static_cast<unsigned char>(stoi(resultMatrix[i][j], nullptr, 16));
    }
}

/*
 * Step 12. AES Encryption Rounds and Result Display
 *
 * This section of code is responsible for performing the AES encryption rounds and displaying the results.
 * It encompasses the following steps:
 *
 * Step 1: SubBytes
 * - In this step, each byte of the input data is replaced with a corresponding byte from a fixed substitution table.
 *
 * Step 2: ShiftRows
 * - This step involves shifting the bytes in each row of the data block to the left.
 * - The first row is not shifted.
 * - The second row is shifted one byte to the left.
 * - The third row is shifted two bytes to the left.
 * - The fourth row is shifted three bytes to the left.
 *
 * Step 3: MixColumns (Excluding the Last Round)
 * - In most rounds (excluding the last round), the columns of the data block are mixed using a fixed matrix multiplication.
 *
 * Step 4: XOR With Round Key
 * - The data is combined with a round-specific subkey by performing an XOR operation.
 *
 * The example loop demonstrates performing the AES encryption rounds (10 rounds in total).
 * Each round includes these steps and involves transformations to the state array.
 *
 * After the final round, the encrypted result is displayed.
 *
 * This section of code represents the core AES encryption process, including the substitution,
 * permutation, and diffusion operations that ensure data security and confidentiality.
 * 
 * AND WITH THAT, EVERYHTING IS COMPLETE AND WORKING AS INTENDED!!!!!!! YAYAYAYAYYAYAYAYAYYAYAYYA :)
 */

cout <<"\nStep 12: Take the State Array, Perform the Following Operations: "
        "\n\ta.) SubBytes: Each byte of the input data is replaced with a corresponding byte from a fixed substitution table"  
        "\n\n\tb.) ShiftRows: The bytes in each row of the data block are shifted to the left- " 
        "\n\t\tThe first row is not shifted"
        "\n\t\tThe second row is shifted one byte to the left"
        "\n\t\tThe third row is shifted two bytes to the left"
        "\n\t\tThe fourth row is shifted three bytes to the left." 
        "\n\n\tc.) MixColumns: The columns of the data block are mixed using a fixed matrix multiplication."
        "\n\n\td.) XOR With Round Key: The data is combined with a round-specific subkey." << endl;
// Example: Perform the AES encryption rounds
for (int round = 0; round < 10; round++) {
    cout << "Round " << round  << ":" << endl;

    cout << "State:" << endl;
    printMatrix(state);

    // Call SubBytes to perform the substitution, print the results
    SubBytes(state);
    cout << "After SubBytes:" << endl;
    printMatrix(state);

    // Call ShiftRows to appropriately shift each row, print the results
    ShiftRows(state);
    cout << "After ShiftRows:" << endl;
    printMatrix(state);

//Call MixColumns for first 9 rounds to perform the mixing, print the results
    if (round < 9) {
        MixColumns(state);
        cout << "After MixColumns:" << endl;
        printMatrix(state);
    }

//Call XORWithRoundKey to perform the ^ operatation, print the results
XORWithRoundKey(state, roundKeys[round]); // XOR with the appropriate round key
 // XOR with the appropriate round key
    cout << "After XORWithRoundKey:" << endl;
    printMatrix(state);
}
    // Print the encrypted result
    cout << "AES Encrypted Message:" << endl;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            // Convert the current state element (byte) to a hexadecimal string representation,
            // ensuring it is represented with two characters and padded with leading zeros if necessary.
            cout << hex << setw(2) << setfill('0') << static_cast<int>(state[j][i]);
        }
    }
    cout << endl;
}
