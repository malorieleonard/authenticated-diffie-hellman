import unittest

from parameters import is_generator, find_generator


class TestGenerator(unittest.TestCase):

    def test_valid_generator_23(self):
        self.assertTrue(is_generator(5, 23))

    def test_invalid_generator_23(self):
        self.assertFalse(is_generator(2, 23))

    def test_valid_generator_65537(self):
        self.assertTrue(is_generator(3, 65537))

    def test_find_generator_23(self):
        g = find_generator(23)
        self.assertTrue(is_generator(g, 23))

    def test_find_generator_65537(self):
        g = find_generator(65537)
        self.assertTrue(is_generator(g, 65537))

    def test_generator_out_of_range(self):
        self.assertFalse(is_generator(1, 23))
        self.assertFalse(is_generator(22, 23))

    def test_boolean_generator(self):
        with self.assertRaises(TypeError):
            is_generator(True, 23)

    def test_string_generator(self):
        with self.assertRaises(TypeError):
            is_generator("5", 23)

    def test_composite_modulus(self):
        with self.assertRaises(ValueError):
            is_generator(5, 21)

    def test_find_generator_composite(self):
        with self.assertRaises(ValueError):
            find_generator(21)

    def test_find_generator_boolean(self):
        with self.assertRaises(TypeError):
            find_generator(True)


if __name__ == "__main__":
    unittest.main()