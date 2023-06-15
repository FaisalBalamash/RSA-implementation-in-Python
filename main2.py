import math
import random
from typing import Tuple
from typing import List
import sympy
import tkinter as tk
from tkinter import filedialog


def getprimes():
    while True:
        # Prompt the user to enter the minimum and maximum values
        min_value = int(input("Enter the minimum value (greater than 1): "))
        max_value = int(input("Enter the maximum value: "))

        # Validate the minimum value
        if min_value <= 1:
            print("Invalid minimum value. Please enter a value greater than 1.")
            continue

        # Generate prime numbers within the given range
        p = sympy.randprime(min_value, max_value)
        q = sympy.randprime(min_value, max_value)

        # Ensure p and q are distinct
        if p != q:
            return p, q
        else:
            print("Generated identical primes. Please try again.")



def extended_gcd(a, b):
    global x, y

    # Base Case
    if (a == 0):
        x = 0
        y = 1
        return b

    # To store results of recursive call
    gcd = extended_gcd(b % a, a)
    x1 = x
    y1 = y

    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1

    return gcd


def modular_inverse(e, phi_n):
    g = extended_gcd(e, phi_n)

    # if gcd = 1 doesn't exist then we can't inverse it.
    if (g != 1):
        print("Inverse doesn't exist")
        exit(1)

    else:
        # phi_n is added to handle negative x
        res = (x % phi_n + phi_n) % phi_n
        return res


def rsa_generate_key(p: int, q: int):
    """Return an RSA key pair generated using primes p and q.

    The return value is a tuple containing two tuples:
      1. The first tuple is the private key, containing (p, q, d).
      2. The second tuple is the public key, containing (n, e).

    Preconditions:
        - p and q are prime
        - p != q
    """
    # Compute the product of p and q
    n = p * q

    # Choose e such that gcd(e, phi_n) == 1.
    phi_n = (p - 1) * (q - 1)

    # Since e is chosen randomly, we repeat the random choice
    # until e is coprime to phi_n.
    e = random.randint(2, phi_n - 1)
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Choose d such that e * d % phi_n = 1.
    # Notice that we're using our modular_inverse from our work in the last chapter!
    d = modular_inverse(e, phi_n)

    return ((p, q, d), (n, e))

def rsa_encrypt():
    print("select public key file")
    selected_public_key_file = select_file()
    public_key = read_public_key(selected_public_key_file)
    n, e = public_key

    print("select plaintext to encrypt")
    selected_plaintext_file = select_file()
    plaintext = read_plaintext(selected_plaintext_file)

    while True:
        # Check if the public key is valid
        if isinstance(n, int) and isinstance(e, int) and n > 0 and e > 0:
            break
        else:
            print("Invalid public key. Please select a valid public key file.")
            print("Select a public key file:")
            selected_public_key_file = select_file()
            public_key = read_public_key(selected_public_key_file)

    # Convert the plaintext file to decimal ASCII values
    decimal_values = convert_to_decimal(plaintext, n)
    print(decimal_values)

    encrypted_values = []

    for value in decimal_values:
        encrypted_value = (value ** e) % n
        encrypted_values.append(encrypted_value)

    #for testing
    print(encrypted_values)

 
    # Save the encrypted values to the ciphertext file
    with open('ciphertext.txt', 'w') as file:
        file.write(''.join(map(str, encrypted_values)))

def read_plaintext(file_path: str) -> str:
    """Read the content of the plaintext file and return it as a string."""
    with open(file_path, 'r') as file:
        plaintext = file.read()
    return plaintext

def convert_to_decimal(text: str, n: int) -> List[int]:
    """Convert the characters in the text to concatenated decimal ASCII values within the range (0, n)."""
    decimal_values = []
    length = len(text)

    # Convert each letter to ASCII value and concatenate in pairs
    for i in range(0, length, 2):
        if i + 1 < length:
            ascii_value_1 = ord(text[i])
            ascii_value_2 = ord(text[i + 1])
            concatenated_decimal = int(str(ascii_value_1).zfill(2) + str(ascii_value_2).zfill(2))
            if 0 < concatenated_decimal < n:
                decimal_values.append(concatenated_decimal)
        else:
            # Handle odd number of characters
            ascii_value = ord(text[i])
            concatenated_decimal = int(str(ascii_value).zfill(2) + '00')
            if 0 < concatenated_decimal < n:
                decimal_values.append(concatenated_decimal)

    return decimal_values





def read_ciphertext(file_path: str) -> List[int]:
    """Read the ciphertext file and return the ciphertext as an integer list."""
    ciphertext = []
    
    with open(file_path, 'r') as file:
        ciphertext_str = file.read().strip()
        
        # Read the ciphertext in groups of four digits
        for i in range(0, len(ciphertext_str), 4):
            chunk = ciphertext_str[i:i+4]
            ciphertext.append(int(chunk))
    
    return ciphertext


##################### Decryption ########################
def rsa_decrypt():
    """Decrypt the given ciphertext using the recipient's private key."""
    print("Select private key file:")
    selected_private_key_file = select_file()
    private_key = read_private_key(selected_private_key_file)

    print("Select ciphertext to decrypt:")
    selected_ciphertext_file = select_file()
    
    while True:
        p, q, d = private_key

        # Check if the private key is valid
        if isinstance(p, int) and isinstance(q, int) and isinstance(d, int) and p > 0 and q > 0 and d > 0:
            break
        else:
            print("Invalid private key. Please select a valid private key file.")
            print("Select a private key file:")
            selected_private_key_file = select_file()
            private_key = read_private_key(selected_private_key_file)

    #int list
    ciphertext = read_ciphertext(selected_ciphertext_file)
    print(ciphertext)

 
    




def read_private_key(selected_private_key_file: str):
    with open(selected_private_key_file, "r") as r:
        contents = r.readline()
        p, q, d = map(int, contents.strip('()\n').split(','))
        return int(p), int(q), int(d)


def generate_keys():
    print("Generating a key pair....\n")
    p, q = getprimes()

    private_key = rsa_generate_key(p, q)[0]
    public_key = rsa_generate_key(p, q)[1]

    # Write private key to a file
    write_private_key(private_key)

    print("Private key generated and saved to privatekey.txt\n")

    # Write public key to a file
    write_public_key(public_key)

    print("Public key generated and saved to publickey.txt\n.\n.\n.")


def select_file() -> str:
    """Prompt the user to select a file and return the selected file path."""
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    return file_path


def read_public_key(selected_public_key_file: str):
    with open(selected_public_key_file, "r") as r:
        contents = r.readline()
        n, e = map(int, contents.strip('()\n').split(','))
        return int(n), int(e)    


def write_public_key(public_key: Tuple[int, int]):
    """Write the public key to a file."""
    with open("publickey.txt", "w") as f:
        f.write(str(public_key))


def write_private_key(private_key: Tuple[int, int, int]):
    """Write the private key to a file."""
    with open("privatekey.txt", "w") as f:
        f.write(str(private_key))


def main():
    print("Welcome to the RSA Algorithm program!")
    while True:
        print("Please select an option:")
        print("1. Generate keys")
        print("2. Encrypt a file")
        print("3. Decrypt a file")
        print("4. Quit")
        choice = input("Enter your choice (1-4): ")

        if choice == "1":
            generate_keys()
        elif choice == "2":
            print("Encryption option selected.")
            rsa_encrypt()
        elif choice == "3":
            print("Decryption option selected.")
            rsa_decrypt()
        elif choice == "4":
            print("Goodbye!")
            break


if __name__ == "__main__":
    main()
