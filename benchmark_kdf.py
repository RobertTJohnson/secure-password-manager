#!/usr/bin/env python3
"""
Measure how long master-password key derivation takes at different PBKDF2
iteration counts, and what that implies for an attacker guessing offline.

Run:  python3 benchmark_kdf.py

Why it matters: PBKDF2 is deliberately slow. Each guess an attacker makes against a
stolen vault.json costs the same time as one legitimate unlock, so a higher
iteration count directly multiplies the attacker's cost (OWASP currently recommends at least
600,000 for PBKDF2-HMAC-SHA256) (at the price of a slightly
slower unlock for you). Results vary by machine - run it on your own computer.
"""

import statistics
import time

import password_manager as pm

ITERATION_COUNTS = [10_000, 100_000, 480_000, 600_000, 1_000_000]
RUNS = 5
SALT = b"benchmark-salt-1"


def time_derivation(iterations: int) -> float:
    pm.PBKDF2_ITERATIONS = iterations
    start = time.perf_counter()
    pm.derive_key("benchmark-password", SALT)
    return time.perf_counter() - start


def main():
    print(f"{'iterations':>12} {'median unlock':>15} {'guesses/sec (1 core)':>22} {'years to try 1 billion':>24}")
    for iterations in ITERATION_COUNTS:
        times = [time_derivation(iterations) for _ in range(RUNS)]
        median = statistics.median(times)
        per_second = 1 / median
        years = (1_000_000_000 * median) / (60 * 60 * 24 * 365)
        marker = "   <- default for new vaults" if iterations == 600_000 else ("   <- older vaults" if iterations == 480_000 else "")
        print(f"{iterations:>12,} {median * 1000:>12.0f} ms {per_second:>22.1f} {years:>24.1f}{marker}")
    print("\nNote: attackers can use many cores or GPUs, so treat these as single-core "
          "estimates. A strong master password matters more than any iteration count.")


if __name__ == "__main__":
    main()
