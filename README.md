[![GitHub RSA Workflow](https://github.com/FaisalBalamash/RSA-implementation-in-Python/actions/workflows/python-package.yml/badge.svg)](https://github.com/FaisalBalamash/RSA-implementation-in-Python/actions/workflows/python-package.yml)

# RSA Encryption and Decryption Program

This Python program implements the RSA (Rivest–Shamir–Adleman) encryption and decryption algorithm. RSA is a widely used public-key cryptosystem that provides secure data transmission and storage.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Key Generation](#key-generation)
- [Encryption](#encryption)
- [Decryption](#decryption)
- [Contributing](#contributing)

## Features

-   Key generation for RSA encryption.
-   File encryption using a recipient's public key.
-   File decryption using a recipient's private key.
-   User-friendly command-line interface for key generation, encryption, and decryption.

## Requirements

To run this program, you need:

-   Python 3.6 or higher.
-   The following Python packages: `sympy`, `tkinter` (usually included with Python).

## Usage

1.  Clone or download this repository to your local machine.
    
2.  Open a terminal or command prompt and navigate to the project directory.
    
3.  Run the program using the following command:
    
    bash
    

1.  `python rsa.py` 
    
2.  Follow the on-screen prompts to choose your desired option:
    
    -   **Generate keys**: Generate RSA public and private keys and save them to `publickey.txt` and `privatekey.txt`.
    -   **Encrypt a file**: Encrypt a plaintext file using a recipient's public key.
    -   **Decrypt a file**: Decrypt a ciphertext file using a recipient's private key.
    -   **Quit**: Exit the program.

## Key Generation

When selecting the "Generate keys" option, the program will generate random prime numbers and use them to create an RSA key pair. The public key will be saved to `publickey.txt`, and the private key will be saved to `privatekey.txt`.

## Encryption

To encrypt a file:

1.  Select the "Encrypt a file" option.
2.  Choose the recipient's public key file.
3.  Select the plaintext file you want to encrypt.
4.  The program will create a `ciphertext.txt` file containing the encrypted data.

## Decryption

To decrypt a file:

1.  Select the "Decrypt a file" option.
2.  Choose the recipient's private key file.
3.  Select the ciphertext file you want to decrypt.
4.  The program will create a `plaintext.txt` file containing the decrypted data.

## Contributing

Contributions to this project are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.
