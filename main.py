import math
import random
from typing import Tuple
import sympy


def getprimes():
    while True:
        # 1st precondition: p and q are prime between 100 and 200
        p = sympy.randprime(100, 200)
        q = sympy.randprime(100, 200)
        # 2nd precondition: p != q
        if (p == q):
            q = sympy.randprime(100, 200)
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


def rsa_encrypt(public_key: Tuple[int, int], plaintext: int) -> int:
    """Encrypt the given plaintext using the recipient's public key.

    Preconditions:
        - public_key is a valid RSA public key (n, e)
        - 0 < plaintext < public_key[0]
    """
    n, e = public_key

    encrypted = (plaintext ** e) % n

    return encrypted


def rsa_decrypt(private_key: Tuple[int, int, int], ciphertext: int) -> int:
    """Decrypt the given ciphertext using the recipient's private key.

    Preconditions:
        - private_key is a valid RSA private key (p, q, d)
        - 0 < ciphertext < private_key[0] * private_key[1]
    """
    p, q, d = private_key
    n = p * q

    decrypted = (ciphertext ** d) % n

    return decrypted


def read_public_key():
    with open("publickey.txt", "r") as r:
        contents = r.readline()
        n, e = map(int, contents.strip('()\n').split(','))
        return int(n), int(e)


def read_private_key():
    with open("privatekey.txt", "r") as r:
        contents = r.readline()
        p, q, d = map(int, contents.strip('()\n').split(','))
        return int(p), int(q), int(d)


if __name__ == "__main__":
    print("RSA Implementation in Python")
    print("Two random prime numbers are chosen")

    print("Generating a key pair....")
    p, q = getprimes()

    print("Exporting Private Key to privatekey.txt")
    with open("privatekey.txt", "a") as f:
        f.write(f'{rsa_generate_key(p, q)[0]}\n')

    print("Exporting Public Key to publickey.txt")
    with open("publickey.txt", "a") as f:
        f.write(f'{rsa_generate_key(p, q)[1]}\n')

print("Key pair generated!")

print("Encrypting process: ")
ciphertext = rsa_encrypt(read_public_key(), 100)
print(ciphertext)

print("Decrypting process: ")
print(rsa_decrypt(read_private_key(), ciphertext))