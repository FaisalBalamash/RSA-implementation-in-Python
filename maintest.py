import unittest
import main

class TestRSA(unittest.TestCase):
    def test_RSA(self):
        self.assertEqual(main.rsa_generate_key(2,7), ((2,7,5), (14,5)))

    def test_inverse_modular(self):
        self.assertEqual(main.modular_inverse(2,7), 4)

if __name__ == '__main__':
    unittest.main()
