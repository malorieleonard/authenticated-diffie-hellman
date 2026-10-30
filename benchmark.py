import csv
import time

from parameters import (
    generate_prime,
    factorize,
    find_generator,
)
from protocol import run_authenticated_exchange


def measure_performance():
    """
    Measure prime generation, factorization,
    generator search, and authenticated DH exchange.

    Perform three trials for each supported bit length.
    """

    results = []

    for bits in (16, 24, 32):
        print(f"\n{'=' * 55}")
        print(f"Testing {bits}-bit Diffie-Hellman")
        print(f"{'=' * 55}")

        for trial in range(1, 4):

            # Prime generation
            start = time.perf_counter()
            p = generate_prime(bits)
            prime_time = time.perf_counter() - start

            # Factorization of p - 1
            start = time.perf_counter()
            factors = factorize(p - 1)
            factor_time = time.perf_counter() - start

            # Generator search
            start = time.perf_counter()
            g = find_generator(p)
            generator_time = time.perf_counter() - start

            # Full authenticated exchange
            start = time.perf_counter()
            exchange = run_authenticated_exchange(bits)
            exchange_time = time.perf_counter() - start

            if not exchange["authenticated"]:
                raise RuntimeError("Authentication failed.")

            if not exchange["shared_secret_match"]:
                raise RuntimeError("Shared secrets do not match.")

            result = {
                "bits": bits,
                "trial": trial,
                "prime": p,
                "generator": g,
                "factors": str(factors),
                "prime_time_ms": round(prime_time * 1000, 4),
                "factor_time_ms": round(factor_time * 1000, 4),
                "generator_time_ms": round(generator_time * 1000, 4),
                "exchange_time_ms": round(exchange_time * 1000, 4),
                "authenticated": exchange["authenticated"],
                "shared_secret_match": exchange["shared_secret_match"],
            }

            results.append(result)

            print(
                f"Trial {trial}: "
                f"prime={result['prime_time_ms']:.4f} ms, "
                f"factor={result['factor_time_ms']:.4f} ms, "
                f"generator={result['generator_time_ms']:.4f} ms, "
                f"exchange={result['exchange_time_ms']:.4f} ms"
            )

    filename = "benchmark_results.csv"

    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(results[0].keys())
        )

        writer.writeheader()
        writer.writerows(results)

    print(f"\nSaved {len(results)} trials to {filename}")

    return results


if __name__ == "__main__":
    measure_performance()