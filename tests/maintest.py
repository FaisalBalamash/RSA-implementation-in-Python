import unittest
import main
import math
import random
import sympy

class TestRSA(unittest.TestCase):
    def test_RSA(self):
        self.assertEqual(main.rsa_generate_key(2,7), ((2,7,5), (14,5)))

    def test_inverse_modular(self):
        self.assertEqual(main.modular_inverse(2,7), 4)

    def test_gcd_extended(self):
        self.assertEqual(main.extended_gcd(4, 7), 1)

if __name__ == '__main__':
    unittest.main()
