import unittest

from Crypto.Util.number import isPrime

from parameters import generate_prime, validate_modulus


class TestPrimeGeneration(unittest.TestCase):

    def test_generate_16_bit_prime(self):
        p = generate_prime(16)
        self.assertEqual(p.bit_length(), 16)
        self.assertTrue(isPrime(p))

    def test_generate_24_bit_prime(self):
        p = generate_prime(24)
        self.assertEqual(p.bit_length(), 24)
        self.assertTrue(isPrime(p))

    def test_generate_32_bit_prime(self):
        p = generate_prime(32)
        self.assertEqual(p.bit_length(), 32)
        self.assertTrue(isPrime(p))

    def test_invalid_bit_length(self):
        for bits in (0, 8, 15, 33, 64):
            with self.subTest(bits=bits):
                with self.assertRaises(ValueError):
                    generate_prime(bits)

    def test_boolean_bit_length(self):
        with self.assertRaises(TypeError):
            generate_prime(True)

    def test_string_bit_length(self):
        with self.assertRaises(TypeError):
            generate_prime("16")

    def test_validate_generated_prime(self):
        p = generate_prime(16)
        self.assertTrue(validate_modulus(p))

    def test_reject_composite(self):
        with self.assertRaises(ValueError):
            validate_modulus(32769)

    def test_reject_boolean_modulus(self):
        with self.assertRaises(TypeError):
            validate_modulus(True)

    def test_reject_string_modulus(self):
        with self.assertRaises(TypeError):
            validate_modulus("65537")

    def test_reject_small_modulus(self):
        with self.assertRaises(ValueError):
            validate_modulus(23)

    def test_allow_classroom_fixture(self):
        self.assertTrue(
            validate_modulus(23, allow_fixture=True)
        )

    def test_reject_invalid_fixture_flag(self):
        with self.assertRaises(TypeError):
            validate_modulus(23, allow_fixture=1)


if __name__ == "__main__":
    unittest.main()