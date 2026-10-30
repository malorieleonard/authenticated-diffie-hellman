import unittest

from parameters import factorize, distinct_prime_factors


class TestFactorization(unittest.TestCase):

    def test_factorize_one(self):
        self.assertEqual(factorize(1), [])

    def test_factorize_22(self):
        self.assertEqual(factorize(22), [2, 11])

    def test_factorize_prime(self):
        self.assertEqual(factorize(23), [23])

    def test_repeated_factors(self):
        self.assertEqual(factorize(65536), [2] * 16)

    def test_distinct_factors(self):
        self.assertEqual(
            distinct_prime_factors(65536),
            [2]
        )

    def test_distinct_factors_22(self):
        self.assertEqual(
            distinct_prime_factors(22),
            [2, 11]
        )

    def test_zero(self):
        with self.assertRaises(ValueError):
            factorize(0)

    def test_negative(self):
        with self.assertRaises(ValueError):
            factorize(-10)

    def test_boolean(self):
        with self.assertRaises(TypeError):
            factorize(True)

    def test_string(self):
        with self.assertRaises(TypeError):
            factorize("22")


if __name__ == "__main__":
    unittest.main()