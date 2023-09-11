#include <iostream>
#include <string>
#include <cstdlib>
#include <random>
#include <vector>
#include <iomanip>

using namespace std;

//Declaring sBox which will used later in encryption 
const unsigned char sBox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x1}
};

const unsigned int roundConstants[10] = {
    0x01000000, 0x2000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

// Function to get a 16-byte message from the user
string getInputMessage();

// Function to generate a 128-bit AES key as a binary string
string generateAESKey();

// Function to convert a binary key (16 bytes) to a hexadecimal string
string keyToHex(const string& key);

// Function to convert a hexadecimal key into a 4x4 matrix
vector<vector<string>> hexKeyToMatrix(const string& hexKey);

// Function to extract columns from the 4x4 matrix and store them as words
vector<string> extractColumnsAsWords(const vector<vector<string>>& matrix);

// Function to rotate a word one position to the left
void rotateWordLeft(string& word);

// Function to perform S-box substitution on a single byte
unsigned char substituteByte(unsigned char byte);


//Function to add in Round Constant
unsigned int applyRoundConstant(unsigned int y1, int roundNumber);
int main() {
    // Call the getInputMessage function to get the input
    string message = getInputMessage();

    // Display the message
    cout << "Message: " << message << endl;

    // Generate random AES-128 key as a binary string
    string aesKey = generateAESKey();
   cout << "\nStep 1: Randomly Generate an 128 Bit Key in Binary: ";
    cout << "\nAES-128 Key (Binary): " << aesKey << endl;

    // Convert the binary key to a 32-character hexadecimal key
    string hexKey = keyToHex(aesKey);
   cout << "\nStep 2: Convert Key from Binary into Hex: ";
  cout << "\nAES-128 Key (Hex): ";
    for (int i = 0; i < hexKey.length(); i += 2) {
    cout << hexKey.substr(i, 2) << " "; // Display two characters at a time with a space
}
cout << endl;
    
    // Convert the hexKey to a 4x4 matrix
    vector<vector<string>> keyMatrix = hexKeyToMatrix(hexKey);

    cout << "\nStep 3: Outlay key into a 4X4 Matrix: ";
    cout << "\nAES-128 Key Matrix:" << endl;

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            cout << keyMatrix[i][j] << " ";
        }
        cout << endl;
    }

    // Extract columns as words
    vector<string> words = extractColumnsAsWords(keyMatrix);
 
  cout << "\nStep 4: Display Words (columns) from Matrix: ";
  cout << "\nWords (w[0] to w[3]):" << endl;
for (int i = 0; i < 4; i++) {
    cout << "w[" << i << "] = ";
    for (int j = 0; j < words[i].size(); j += 2) {
        cout << words[i].substr(j, 2) << " "; // Display two characters at a time with a space
    }
    cout << endl;
}


  
cout << "\nStep 5: Shift Each Hex Element in the Word 1 Cyclical Position to the Left: ";
cout << "\nRotated Words (w[0] to w[3]):" << endl;
for (int i = 0; i < 4; i++) {
    rotateWordLeft(words[i]); // Rotate the word -- lol gotta call that first before it prints right
    cout << "w[" << i << "] = ";
    for (int j = 0; j < words[i].length(); j += 2) {
        cout << words[i].substr(j, 2) << " "; // Display two characters at a time with a space
    }
    cout << endl;
}



  cout << "\nStep 6: Map Each Hex Value to the Appropiate S-Box Value: ";
    // Rotate each word one position to the left
    for (int i = 0; i < 4; i++) {
        cout << "\nRotated Word (w[" << i << "]):" << endl;
        rotateWordLeft(words[i]);
            cout << "w[" << i << "] = ";
    for (int k = 0; k < words[i].size(); k += 2) {
        cout << words[i].substr(k, 2) << " "; // Display two characters at a time with a space
    }

        cout << "\nSubstituted Subwords (w[" << i << "]):" << endl;
            unsigned int result = 0; // Initialize result to 0
        for (int j = 0; j < 4; j++) {
            unsigned char originalByte = stoi(words[i].substr(j * 2, 2), nullptr, 16);
            unsigned char substitutedByte = substituteByte(originalByte);
            result = (result << 8) | substitutedByte; // Append the substituted
            cout << "Original Byte: " << hex << static_cast<int>(originalByte) << " ";
            cout << "Substituted Byte: " << hex << static_cast<int>(substitutedByte) << endl;
        }
        int roundNumber = 0; 
            result = applyRoundConstant(result, roundNumber);

    cout << "\nResult after applying round constant: " << hex << result << endl;
    }

  
    return 0;
}

// Function to get a 16-byte message from the user
string getInputMessage() {
    string user_input;

    // Prompt the user for input
    cout << "Enter a 16-byte message: ";

    // Read the entire line of input, including spaces
    getline(cin, user_input);

    // Continue to prompt until a 16-byte input is provided
    while (user_input.length() != 16) {
        cout << "Input must be exactly 16 bytes long. Try again." << endl;

        // Prompt the user for input again
        cout << "Enter a 16-byte message: ";

        // Read the entire line of input, including spaces
        getline(cin, user_input);
    }

    return user_input;
}

// Function to generate a random 128-bit AES key as a binary string
string generateAESKey() {
    const int keySize = 128; // 128 bits
    string aesKey;

    // Initialize a random number generator
    random_device rd;
    mt19937 gen(rd());

    // Generate 128 random bits (0 or 1) to create the AES key
    for (int i = 0; i < keySize; i++) {
        int bit = gen() % 2; // Generate a random bit (0 or 1)
        aesKey += to_string(bit); // Append the bit to the key as a string
    }

    return aesKey;
}

// Function to convert a binary key (16 bytes) to a hexadecimal string
string keyToHex(const string& binaryKey) {
    string hexKey;

    // Ensure the binary key length is a multiple of 4 (4 bits per nibble)
    int remainder = binaryKey.length() % 4;
    if (remainder != 0) {
        cout << "Binary key must have a length that is a multiple of 4." << endl;
        return "";
    }

    // Convert each group of 4 bits to a hexadecimal digit
    for (int i = 0; i < binaryKey.length(); i += 4) {
        string nibble = binaryKey.substr(i, 4); // Extract 4-bit nibble
        int decimalValue = stoi(nibble, nullptr, 2); // Convert to decimal
        hexKey += "0123456789ABCDEF"[decimalValue]; // Append the corresponding hex digit
    }

    return hexKey;
}

// Function to convert a hexadecimal key into a 4x4 matrix
vector<vector<string>> hexKeyToMatrix(const string& hexKey) {
    vector<vector<string>> matrix(4, vector<string>(4));

    // Ensure that the input hexKey is exactly 32 characters (16 bytes)
    if (hexKey.length() != 32) {
        cout << "Hexadecimal key must be exactly 32 characters (16 bytes) long." << endl;
        return matrix;
    }

    int rowIndex = 0;
    int colIndex = 0;

    // Loop through the 32 characters of the hexKey
    for (int i = 0; i < 32; i += 2) {
        string byte = hexKey.substr(i, 2); // Extract 2 hexadecimal characters as a byte
        matrix[rowIndex][colIndex] = byte;

        // Move to the next row or wrap to the next column
        if (++rowIndex >= 4) {
            rowIndex = 0;
            colIndex++;
        }
    }

    return matrix;
}

// Function to extract columns from the 4x4 matrix and store them as words
vector<string> extractColumnsAsWords(const vector<vector<string>>& matrix) {
    vector<string> words;

    for (int col = 0; col < 4; col++) {
        string word;
        for (int row = 0; row < 4; row++) {
            word += matrix[row][col];
        }
        words.push_back(word);
    }

    return words;
}

// Function to rotate a word one position to the left while preserving the byte format
void rotateWordLeft(string& word) {
    string rotatedWord = word.substr(2) + word.substr(0, 2); // Rotate by one position to the left
    word = rotatedWord;
}

// Function to perform S-box substitution on a single byte
unsigned char substituteByte(unsigned char byte) {
    // Extract the row and column indices from the input byte
    unsigned char row = (byte >> 4) & 0x0F;    // Upper 4 bits
    unsigned char col = byte & 0x0F;           // Lower 4 bits

    // Perform the S-box substitution and return the result
    return sBox[row][col];
}

//Function that performs the round constant onto the word
unsigned int applyRoundConstant(unsigned int y1, int roundNumber) {
    // Ensure that roundNumber is within valid range (0 to 9 for AES-128)
    if (roundNumber < 0 || roundNumber >= 10) {
        cout << "Invalid round number. It must be between 0 and 9." << endl;
        return 0; // Return an appropriate value or handle the error as needed
    }

    // XOR y1 with the corresponding round constant
    unsigned int roundConstant = roundConstants[roundNumber];
    unsigned int result = y1 ^ roundConstant;

    return result;
}
