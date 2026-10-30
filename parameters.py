from Crypto.Util.number import getPrime, isPrime


ALLOWED_BITS = (16, 24, 32)


def generate_prime(bits):
    """
    Generate a prime number with the requested bit length
    using the PyCryptodome library.
    """

    if type(bits) is not int:
        raise TypeError("Bit length must be an integer.")

    if bits not in ALLOWED_BITS:
        raise ValueError("Bit length must be 16, 24, or 32.")

    prime = getPrime(bits)

    if prime.bit_length() != bits:
        raise ValueError("Generated prime has incorrect bit length.")

    if not isPrime(prime):
        raise ValueError("Generated number is not prime.")

    return prime


def validate_modulus(p, allow_fixture=False):
    """
    Validate a received Diffie-Hellman prime modulus.

    Normal exchanges require 16-32-bit primes.
    The classroom fixture p=23 is allowed only
    when explicitly requested.
    """

    if type(p) is not int:
        raise TypeError("Modulus must be an integer.")

    if type(allow_fixture) is not bool:
        raise TypeError("allow_fixture must be a Boolean.")

    if allow_fixture and p == 23:
        return True

    if not 16 <= p.bit_length() <= 32:
        raise ValueError("Modulus must be 16-32 bits.")

    if not isPrime(p):
        raise ValueError("Modulus must be prime.")

    return True
def factorize(n):
    """
    Return the prime factors of n, including repeated factors.

    Example:
        factorize(22) -> [2, 11]
        factorize(65536) -> [2, 2, ..., 2]
    """

    if type(n) is not int:
        raise TypeError("Input must be an integer.")

    if n < 1:
        raise ValueError("Input must be positive.")

    factors = []

    divisor = 2

    while divisor * divisor <= n:
        while n % divisor == 0:
            factors.append(divisor)
            n //= divisor

        divisor = 3 if divisor == 2 else divisor + 2

    if n > 1:
        factors.append(n)

    return factors


def distinct_prime_factors(n):
    """
    Return the distinct prime factors of n.

    Example:
        distinct_prime_factors(22) -> [2, 11]
        distinct_prime_factors(65536) -> [2]
    """

    return sorted(set(factorize(n)))

def is_generator(g, p):
    """
    Check whether g is a primitive root modulo prime p.
    """

    if type(g) is not int or type(p) is not int:
        raise TypeError("Generator and modulus must be integers.")

    if p < 3:
        raise ValueError("Modulus must be at least 3.")

    if not isPrime(p):
        raise ValueError("Modulus must be prime.")

    if not 2 <= g <= p - 2:
        return False

    factors = distinct_prime_factors(p - 1)

    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False

    return True


def find_generator(p):
    """
    Find a valid primitive root modulo prime p.
    """

    if type(p) is not int:
        raise TypeError("Modulus must be an integer.")

    if p < 5:
        raise ValueError("Modulus must be at least 5.")

    if not isPrime(p):
        raise ValueError("Modulus must be prime.")

    factors = distinct_prime_factors(p - 1)

    for g in range(2, p - 1):
        valid = True

        for q in factors:
            if pow(g, (p - 1) // q, p) == 1:
                valid = False
                break

        if valid:
            return g

    raise ValueError("No generator found.")