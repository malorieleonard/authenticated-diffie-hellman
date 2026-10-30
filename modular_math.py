def modular_exponentiation(base, exponent, modulus):
    """
    Calculate (base ** exponent) % modulus
    using the square-and-multiply algorithm.
    """

    # Validate inputs
    if type(base) is not int:
        raise TypeError("Base must be an integer")

    if type(exponent) is not int:
        raise TypeError("Exponent must be an integer")

    if type(modulus) is not int:
        raise TypeError("Modulus must be an integer")

    if exponent < 0:
        raise ValueError("Exponent cannot be negative")

    if modulus <= 0:
        raise ValueError("Modulus must be positive")

    # Initialize result
    result = 1 % modulus

    # Reduce base
    base = base % modulus

    # Square-and-multiply
    while exponent > 0:

        if exponent % 2 == 1:
            result = (result * base) % modulus

        base = (base * base) % modulus

        exponent = exponent // 2

    return result