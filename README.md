# Authenticated Diffie–Hellman Key Exchange

## Overview

This project implements an authenticated Diffie–Hellman key exchange in Python. It demonstrates how two participants, Alice and Bob, can establish a shared secret over an insecure communication channel and how digital signatures can help protect the exchange against message tampering and man-in-the-middle attacks.

The implementation combines the mathematical foundations of Diffie–Hellman with authentication, message validation, and session management. It uses PyCryptodome to generate prime numbers, a custom Square-and-Multiply algorithm for modular exponentiation, and Ed25519 digital signatures to authenticate exchanged messages.

The project also includes attack demonstrations, automated security tests, and performance measurements for different prime sizes. It was developed as an educational implementation, so the supported prime sizes are intentionally small and should not be used for real-world cryptographic protection.

## Requirements

The project requires Python 3 and two external libraries:

- **PyCryptodome:** Used for prime generation and primality testing.
- **cryptography:** Provides Ed25519 digital signatures for message authentication.

Python's standard library is used for secure random-number generation, JSON serialization, session handling, benchmarking, and automated testing.

## Installation

Open the project folder in Visual Studio Code or another Python development environment.

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate the environment.

**macOS or Linux:**

```bash
source .venv/bin/activate
```

**Windows:**

```bash
.venv\Scripts\activate
```

Install the required packages:

```bash
python -m pip install pycryptodome cryptography
```

Once the dependencies are installed, the project can be run and tested from the main project directory.

## Project Files

The program is divided into modules to keep the mathematical operations, authentication functions, and protocol logic organized.

| File | Description |
|---|---|
| `modular_math.py` | Implements modular exponentiation using Square-and-Multiply. |
| `parameters.py` | Generates primes, factors integers, and verifies generators. |
| `participant.py` | Handles Diffie–Hellman private values, public values, and shared secrets. |
| `authentication.py` | Generates Ed25519 identity keys and handles digital signatures. |
| `messages.py` | Provides message encoding, validation, and nonce generation. |
| `session.py` | Tracks sessions and enforces the expected message order. |
| `protocol.py` | Implements the three-message authenticated exchange simulation. |
| `secure_receiver.py` | Validates signed initiation messages and detects recognized replays. |
| `attacks.py` | Demonstrates man-in-the-middle attacks against unauthenticated and authenticated exchanges. |
| `benchmark.py` | Measures execution times and writes results to a CSV file. |
| `test_*.py` | Contains the automated tests for the project. |
| `benchmark_results.csv` | Stores the recorded performance measurements. |

## How the Key Exchange Works

The program supports prime sizes of 16, 24, and 32 bits. Prime numbers are generated using PyCryptodome's `getPrime()` function and checked with `isPrime()`.

After generating a prime modulus \(p\), the program factors \(p - 1\) and searches for a valid generator \(g\). The generator is checked using the distinct prime factors of \(p - 1\) to confirm that it has the required order.

Alice and Bob then select private exponents using Python's `secrets` module. Their public values are calculated as:

\[
A = g^a \bmod p
\]

\[
B = g^b \bmod p
\]

After exchanging these values, both participants calculate the shared secret independently:

\[
K_A = B^a \bmod p
\]

\[
K_B = A^b \bmod p
\]

The two results match because both calculations produce \(g^{ab} \bmod p\).

These operations use a custom Square-and-Multiply implementation rather than Python's built-in modular exponentiation function. The algorithm processes the exponent in binary form, making modular exponentiation more efficient than calculating the full power directly.

A small classroom example using \(p = 23\) is also available for testing when explicitly enabled.

## Authentication and Message Security

Diffie–Hellman establishes a shared secret, but the basic protocol does not verify who supplied the public values. Without authentication, an attacker could intercept the exchange and replace those values.

To address this weakness, the project uses Ed25519 digital signatures. Alice and Bob sign their protocol messages using private identity keys, while the corresponding trusted public keys are used to verify the signatures.

The authenticated exchange consists of three messages. Alice sends a signed initiation containing the Diffie–Hellman parameters, her public value, and fresh session information. Bob verifies the message before sending a signed response that includes his public value and references Alice's original message. Alice then sends a signed final message that references the preceding exchange.

Messages are serialized consistently using JSON, allowing signatures to be checked against the same message content. The program also validates required fields, public values, nonces, and session identifiers before accepting messages.

Session management enforces the expected initiation, response, and finish sequence. Duplicate or out-of-order messages are rejected.

The `SecureReceiver` module adds replay checks for signed initiation messages. If an attacker resends an initiation that Bob has already accepted, the receiver rejects the reused session identifier or nonce.

The implementation assumes that each participant already has the correct public verification key for the other participant. It does not include a certificate authority or another mechanism for distributing trusted identity keys.

## Man-in-the-Middle Demonstrations

The project includes two attack demonstrations to show why authentication matters.

In the unauthenticated exchange, Eve intercepts the public values sent between Alice and Bob and substitutes values of her own. Alice and Bob each establish a shared secret with Eve instead of directly with one another. This demonstrates how an attacker can interfere with an otherwise mathematically valid Diffie–Hellman exchange.

In the authenticated demonstration, Eve attempts to modify Alice's signed public value. Because the signature covers the original message, the modification causes signature verification to fail, and the altered message is rejected.

Both demonstrations are simulated locally and can be examined through the tests in `test_attacks.py`.

## Testing

The project uses Python's built-in `unittest` framework to check the mathematical operations, protocol behavior, authentication functions, and security controls.

The tests cover successful key exchanges, prime and generator validation, signature verification, invalid message formats, session ordering, man-in-the-middle attacks, and replayed initiation messages.

To run the complete test suite, enter:

```bash
python -m unittest discover -v
```

The final recorded test run produced:

```text
Ran 111 tests in 0.282s

OK
```

All 111 tests passed.

To run only the replay and initiation-message security tests, use:

```bash
python -m unittest test_secure_receiver -v
```

The tests confirm the expected behavior for the cases examined, although they do not represent a complete security audit.

## Performance Measurements

The program measures the execution time of prime generation, factorization of \(p - 1\), generator search, and the authenticated exchange.

Measurements were collected using 16-bit, 24-bit, and 32-bit primes, with three trials at each size. The results are saved in `benchmark_results.csv`.

To run the benchmark again:

```bash
python benchmark.py
```

The following table shows the average execution times from the recorded trials.

| Prime size | Prime generation | Factorization | Generator search | Authenticated exchange |
|---|---:|---:|---:|---:|
| 16 bits | 1.1324 ms | 0.0115 ms | 0.6131 ms | 7.9296 ms |
| 24 bits | 2.7713 ms | 0.0707 ms | 1.5163 ms | 16.3200 ms |
| 32 bits | 2.8353 ms | 0.0650 ms | 1.6664 ms | 14.6600 ms |

The results show some variation as the prime size increases, although the timings are not perfectly consistent across trials. This is expected for short operations, where random parameter selection and normal execution overhead can affect individual measurements.

The authenticated exchange benchmark generates its own parameters, so its timing is a separate measurement rather than the sum of the other columns.

## Limitations

This implementation is intended to demonstrate cryptographic concepts rather than provide production-ready security.

The 16-bit, 24-bit, and 32-bit prime sizes are far too small for secure real-world use. The protocol also runs as a local simulation instead of exchanging messages between separate applications over a network.

Replay protection for signed initiation messages is maintained in memory and does not persist after the receiver is restarted. Although the session manager enforces message ordering, the dedicated replay tests do not cover all three messages as independently received network traffic.

The program verifies that Alice and Bob calculate matching shared secrets, but it does not include a key-derivation function, encrypted communication, or explicit cryptographic key confirmation.

Despite these limitations, the implementation demonstrates how Diffie–Hellman, digital signatures, and message validation work together to address important security concerns in key exchange protocols.