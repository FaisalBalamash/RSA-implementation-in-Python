import math
import random
from typing import Tuple
from typing import List
import sympy
import tkinter as tk
from tkinter import filedialog

def encryption_equation(public_key: Tuple[int, int], plaintext: int) -> int:
    """Encrypt the given plaintext using the recipient's public key.

    Preconditions:
        - public_key is a valid RSA public key (n, e)
        - 0 < plaintext < public_key[0]
    """
    n, e = public_key
    encrypted = (plaintext ** e) % n

    return encrypted

##################### Encryption ########################
def rsa_encrypt():
    while True:
        try:
            print("Select public key file")
            selected_public_key_file = select_file()
            public_key = read_public_key(selected_public_key_file)
            n, e = public_key
            break  # Break the loop if no exception occurs
        except Exception as e:
            print("An error occurred with Public Key path:")
            print("Please try again.")

    while True:
        try:
            print("Select plaintext to encrypt")
            selected_plaintext_file = select_file()
            break  # Break the loop if no exception occurs
        except Exception as e:
            print("An error occurred with Plaintext path:")
            print("Please try again.")


    while True:
        try:
            # Check if the public key is valid
            if isinstance(n, int) and isinstance(e, int) and n > 0 and e > 0:
                break
            else:
                print("Invalid public key. Please select a valid public key file.")
                print("Select a public key file:")
                selected_public_key_file = select_file()
                public_key = read_public_key(selected_public_key_file)
                n, e = public_key
        except Exception as e:
            print("An error occurred.")
            print("Please try again with a valid public key file.")

    try:
        with open(selected_plaintext_file, "r") as f:
            file_contents = f.read()
        decimal_string = ''.join([str(ord(c)).zfill(4) for c in file_contents])

        encrypted_values = []
        i = 0
        while i < len(decimal_string):
            # encryption
            block = decimal_string[i:i+4]
            encrypted_values.append(str(encryption_equation((n, e), int(block))).zfill(8))
            i += 4

        with open("ciphertext.txt", "w") as f:
            f.write(' '.join(encrypted_values))
    except Exception as e:
        print("An error occurred.")
        print("Please try again with a valid plaintext file.")


##################### Decryption ########################
def decryption_equation(private_key: Tuple[int, int, int],  ciphertext: int) -> int:
    """Decrypt the given ciphertext using the recipient's private key.

    Preconditions:
        - private_key is a valid RSA private key (p, q, d)
        - 0 < ciphertext < private_key[0] * private_key[1]
    """
    p, q, d = private_key
    n = p * q

    decrypted = (ciphertext ** d) % n
    return decrypted

def rsa_decrypt():
    """Decrypt the given ciphertext using the recipient's private key."""
    while True:
        try:
            print("Select private key file:")
            selected_private_key_file = select_file()
            private_key = read_private_key(selected_private_key_file)
            p, q, d = private_key
            break  # Break the loop if no exception occurs
        except Exception as e:
            print("An error occurred with Private key path:")
            print("Please try again.")

    while True:
        try:
            print("Select ciphertext to decrypt:")
            selected_ciphertext_file = select_file()
            # Process the selected ciphertext file
            break  # Break the loop if no exception occurs
        except Exception as e:
            print("An error occurred with Ciphertext path:")
            print("Please try again.")

    with open(selected_ciphertext_file) as f:
      encrypted_values = f.read().split()

    plaintext = ""
    for number in encrypted_values:
        #call the rsa decrypt method
        decrypted_block = str(decryption_equation((p, q, d), int(number))).zfill(4)
        for i in range(0, len(decrypted_block), 4):
            plaintext += chr(int(decrypted_block[i:i+4]))

    with open("plaintext.txt", "w") as file:
        file.write(plaintext)

    while True:
        # Check if the private key is valid
        if isinstance(p, int) and isinstance(q, int) and isinstance(d, int) and p > 0 and q > 0 and d > 0:
            break
        else:
            print("Invalid private key. Please select a valid private key file.")
            print("Select a private key file:")
            selected_private_key_file = select_file()
            private_key = read_private_key(selected_private_key_file)


def write_plaintext_to_file(plaintext):
    with open("plaintext.txt", "w") as file:
        file.write(plaintext)


def read_private_key(selected_private_key_file: str):
    with open(selected_private_key_file, "r") as r:
        contents = r.readline()
        p, q, d = map(int, contents.strip('()\n').split(','))
        return int(p), int(q), int(d)

def select_file() -> str:
    """Prompt the user to select a file and return the selected file path."""
    root = tk.Tk()
    root.withdraw()
    root.wm_attributes('-topmost', 1)
    file_path = filedialog.askopenfilename()
    return file_path


def read_public_key(selected_public_key_file: str):
    with open(selected_public_key_file, "r") as r:
        contents = r.readline()
        n, e = map(int, contents.strip('()\n').split(','))
        return int(n), int(e)


def modular_inverse(a: int, m: int) -> int:
    """Return the modular inverse of a modulo m, if it exists.

    Preconditions:
        - a and m are positive integers
        - a and m are coprime
    """
    t, new_t, r, new_r = 0, 1, m, a

    while new_r != 0:
        quotient, remainder = divmod(r, new_r)
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, remainder

    if r > 1:
        raise ValueError("a is not invertible modulo m")
    if t < 0:
        t += m

    return t


def rsa_generate_key(p: int, q: int) -> (Tuple[Tuple[int, int, int], Tuple[int, int]]):
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
    d = modular_inverse(e, phi_n)

    return ((p, q, d), (n, e))


def isPrime(n):
    """Check if a number is prime.

    Preconditions:
        - n is a positive integer
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6

    return True


def generate_primes(min: int, max: int) -> int:
    while True:
        num = random.randint(min, max)
        if isPrime(num):
            return num

def generate_keys():
  p = generate_primes(100, 200)
  q = generate_primes(100, 200)

  private_key, public_key = rsa_generate_key(p, q)

  with open("publickey.txt", "w") as f:
    f.write(f"({public_key[0]}, {public_key[1]})")
  with open("privatekey.txt", "w") as f:
    f.write(f"({private_key[0]}, {private_key[1]}, {private_key[2]})")

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
            print("Private key generated and saved to privatekey.txt\n")
            print("Public key generated and saved to publickey.txt\n.\n.\n.")
        elif choice == "2":
            print("Encryption option selected.")
            print("A filechooser window will pop up to choose the files needed")
            rsa_encrypt()
        elif choice == "3":
            print("Decryption option selected.")
            print("A filechooser window will pop up to choose the files needed")
            rsa_decrypt()
        elif choice == "4":
            print("Goodbye!")
            break


if __name__ == "__main__":
    main()
