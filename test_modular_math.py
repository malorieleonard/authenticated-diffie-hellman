import unittest

from modular_math import modular_exponentiation


class TestModularExponentiation(unittest.TestCase):

    def test_known_result(self):
        self.assertEqual(
            modular_exponentiation(5, 6, 23), 8
        )

    def test_exponent_zero(self):
        self.assertEqual(
            modular_exponentiation(5, 0, 23), 1
        )

    def test_modulus_one(self):
        self.assertEqual(
            modular_exponentiation(5, 0, 1), 0
        )

    def test_negative_base(self):
        self.assertEqual(
            modular_exponentiation(-5, 3, 23),
            pow(-5, 3, 23)
        )

    def test_negative_exponent(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, -1, 23)

    def test_zero_modulus(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, 0)

    def test_boolean_input(self):
        with self.assertRaises(TypeError):
            modular_exponentiation(True, 6, 23)

    def test_against_python_pow(self):
        for base in range(-10, 11):
            for exponent in range(20):
                for modulus in range(1, 20):
                    self.assertEqual(
                        modular_exponentiation(
                            base, exponent, modulus
                        ),
                        pow(base, exponent, modulus)
                    )


if __name__ == "__main__":
    unittest.main()