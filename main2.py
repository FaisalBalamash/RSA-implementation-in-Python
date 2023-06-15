import math
import random
import sympy
import os
from tkinter import Tk, filedialog

def getprimes():
    while True:
        # 1st precondition: p and q are prime between 100 and 200
        p = sympy.randprime(100, 200)
        q = sympy.randprime(100, 200)
        # 2nd precondition: p != q
        if (p != q):
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

    # Update x and y using results of recursive call
    x = y1 - (b // a) * x1
    y = x1

    return gcd

def modular_inverse(e, phi_n):
    g = extended_gcd(e, phi_n)

    # If gcd = 1 doesn't exist then we can't inverse it.
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

def generate_keys():
    print("Generating a key pair....")
    p, q = getprimes()

    private_key = rsa_generate_key(p, q)[0]
    public_key = rsa_generate_key(p, q)[1]

    # Write private key to a file
    with open("privatekey.txt", "w") as f:
        f.write(str(private_key))

    print("Private key generated and saved to privatekey.txt")

    # Write public key to a file
    with open("publickey.txt", "w") as f:
        f.write(str(public_key))

    print("Public key generated and saved to publickey.txt")

def encrypt():
    root = Tk()
    root.withdraw()
    public_key_file = filedialog.askopenfilename(title="Select Public Key File")
    input_file = filedialog.askopenfilename(title="Select File to Encrypt")

    if os.path.isfile(public_key_file) and os.path.isfile(input_file):
        # Read public key from file
        with open(public_key_file, 'r') as file:
            public_key = eval(file.read())

        # Read plaintext number from input file
        with open(input_file, 'r') as file:
            plaintext = int(file.read())

        # Encrypt the plaintext
        encrypted = rsa_encrypt(public_key, plaintext)

        # Write encrypted number to output file
        output_file = input("Enter the output file path: ")
        with open(output_file, 'w') as file:
            file.write(str(encrypted))

        print("Encryption completed. Encrypted number saved to", output_file)
    else:
        print("Invalid file path.")

def decrypt():
    root = Tk()
    root.withdraw()
    private_key_file = filedialog.askopenfilename(title="Select Private Key File")
    input_file = filedialog.askopenfilename(title="Select File to Decrypt")

    if os.path.isfile(private_key_file) and os.path.isfile(input_file):
        # Read private key from file
        with open(private_key_file, 'r') as file:
            private_key = eval(file.read())

        # Read encrypted number from input file
        with open(input_file, 'r') as file:
            encrypted = int(file.read())

        # Decrypt the encrypted number
        decrypted = rsa_decrypt(private_key, encrypted)

        # Write decrypted number to output file
        output_file = input("Enter the output file path: ")
        with open(output_file, 'w') as file:
            file.write(str(decrypted))

        print("Decryption completed. Decrypted number saved to", output_file)
    else:
        print("Invalid file path.")

def main():
    print("Welcome to the encryption program!")
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
            encrypt()
        elif choice == "3":
            decrypt()
        elif choice == "4":
            print("Thank you for using the encryption program. Goodbye!")
            break

if __name__ == "__main__":
    main()
