import math
import random
from typing import Tuple
from typing import List
import sympy
import tkinter as tk
from tkinter import filedialog


def getprimes():
    while True:
        # 1st precondition: p and q are prime between 100 and 200
        p = sympy.randprime(1, 999999999999)
        q = sympy.randprime(1, 999999999999)
        # 2nd precondition: p != q
        if (p == q):
            q = sympy.randprime(1, 999999999999)
        return p, q


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

    # Encrypt the decimal values using RSA encryption
    encrypted_values = []
    num_values = len(decimal_values)

    # Process chunks of four decimal values
    for i in range(0, num_values - (num_values % 4), 4):
        values_chunk = decimal_values[i:i+4]  # Get the next four decimal values
        encrypted_chunk = [pow(value, e, n) for value in values_chunk]  # Encrypt the chunk
        encrypted_values.extend(encrypted_chunk)  # Append the encrypted chunk to the result

    # Process remaining decimal values if any
    if num_values % 4 != 0:
        remaining_chunk = decimal_values[num_values - (num_values % 4):]  # Get the remaining decimal values
        encrypted_chunk = [pow(value, e, n) for value in remaining_chunk]  # Encrypt the chunk
        encrypted_values.extend(encrypted_chunk)  # Append the encrypted chunk to the result

    # Save the encrypted values to the ciphertext file
    with open('ciphertext.txt', 'w') as file:
        file.write(''.join(map(str, encrypted_values)))

    return encrypted_values

def read_plaintext(file_path: str) -> str:
    """Read the content of the plaintext file and return it as a string."""
    with open(file_path, 'r') as file:
        plaintext = file.read()
    return plaintext

def convert_to_decimal(text: str, n: int) -> List[int]:
    """Convert the characters in the text to concatenated decimal ASCII values within range (0, n)."""
    decimal_values = []
    length = len(text)

    # Convert every two letters to concatenated decimal ASCII values
    for i in range(0, length, 2):
        if i + 1 < length:
            concatenated_decimal = int(str(ord(text[i])) + str(ord(text[i + 1])))
            if 0 < concatenated_decimal < n:
                decimal_values.append(concatenated_decimal)
        else:
            # Handle odd number of characters
            decimal_value = ord(text[i])
            if 0 < decimal_value < n:
                decimal_values.append(decimal_value)

    return decimal_values




##################### Decryption ########################
def rsa_decrypt(private_key: Tuple[int, int, int], ciphertext: int) -> int:
    """Decrypt the given ciphertext using the recipient's private key.

    Preconditions:
        - private_key is a valid RSA private key (p, q, d)
        - 0 < ciphertext < private_key[0] * private_key[1]
    """
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

    while True:
        # Calculate the maximum valid ciphertext value
        max_ciphertext = p * q - 1

        # Check if the ciphertext is within the valid range
        if 0 < ciphertext < max_ciphertext:
            break
        else:
            print("Invalid ciphertext. Please select a valid ciphertext file.")
            print("Select a ciphertext file:")
            selected_ciphertext_file = select_file()
            ciphertext = read_ciphertext(selected_ciphertext_file)

    # Decryption code here

    return decrypted




def read_private_key():
    with open("privatekey.txt", "r") as r:
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
            rsa_decrypt(read_private_key(), 100)
        elif choice == "4":
            print("Thank you for using the encryption program. Goodbye!")
            break


if __name__ == "__main__":
    main()
