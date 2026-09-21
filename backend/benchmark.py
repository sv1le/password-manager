"""
Cryptographic Benchmark Script
Tests AES, PBKDF2, and bcrypt performance on this machine.
Run: python benchmark.py
"""

import time
import os
import bcrypt
import hashlib
import pandas as pd
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ============================================
# CONFIGURATION
# ============================================
REPETITIONS = 100  # Run each test 100 times, take average
DATA_SIZES = [1024, 10*1024, 100*1024]  # 1KB, 10KB, 100KB
PBKDF2_ITERATIONS = [1000, 10000, 50000, 100000, 500000]
HASH_ALGORITHMS = ['SHA256', 'SHA512']  # bcrypt tested separately

results = []  # Store all results here

# ============================================
# TEST 1: AES ENCRYPTION COMPARISON
# ============================================
def benchmark_aes(key_size, data_size, mode='GCM'):
    """Benchmark AES encryption for given key size and data size."""
    key = os.urandom(key_size // 8)
    data = os.urandom(data_size)
    
    start = time.perf_counter()
    for _ in range(REPETITIONS):
        # Create a NEW cipher and encryptor each iteration
        if mode == 'GCM':
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        elif mode == 'CBC':
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        encryptor = cipher.encryptor()
        encryptor.update(data)
        encryptor.finalize()
    end = time.perf_counter()
    
    avg_ms = (end - start) / REPETITIONS * 1000
    return avg_ms

print("=" * 60)
print("TEST 1: AES ENCRYPTION PERFORMANCE")
print("=" * 60)
print(f"{'Algorithm':<20} {'Data Size':<12} {'Avg Time (ms)':<15} {'Throughput (MB/s)'}")
print("-" * 60)

for key_size in [128, 192, 256]:
    for data_size in DATA_SIZES:
        avg_ms = benchmark_aes(key_size, data_size, 'GCM')
        throughput = (data_size / (1024 * 1024)) / (avg_ms / 1000) if avg_ms > 0 else 0
        size_label = f"{data_size // 1024}KB"
        
        print(f"AES-{key_size}-GCM{'':<8} {size_label:<12} {avg_ms:<15.4f} {throughput:<.2f}")
        
        results.append({
            'Test': 'AES Encryption',
            'Algorithm': f'AES-{key_size}-GCM',
            'Data Size': size_label,
            'Time (ms)': avg_ms,
            'Throughput (MB/s)': throughput
        })

# Test AES-256-CBC for comparison
for data_size in DATA_SIZES:
    avg_ms = benchmark_aes(256, data_size, 'CBC')
    throughput = (data_size / (1024 * 1024)) / (avg_ms / 1000) if avg_ms > 0 else 0
    size_label = f"{data_size // 1024}KB"
    
    print(f"AES-256-CBC{'':<9} {size_label:<12} {avg_ms:<15.4f} {throughput:<.2f}")
    
    results.append({
        'Test': 'AES Encryption',
        'Algorithm': 'AES-256-CBC',
        'Data Size': size_label,
        'Time (ms)': avg_ms,
        'Throughput (MB/s)': throughput
    })

# ============================================
# TEST 2: PBKDF2 ITERATION COUNT
# ============================================
def benchmark_pbkdf2(iterations):
    """Benchmark PBKDF2 key derivation with given iteration count."""
    password = b"test_master_password_123"
    salt = os.urandom(16)
    
    start = time.perf_counter()
    for _ in range(10):  # PBKDF2 is slow, only 10 reps
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        kdf.derive(password)
    end = time.perf_counter()
    
    avg_ms = (end - start) / 10 * 1000
    return avg_ms

print("\n" + "=" * 60)
print("TEST 2: PBKDF2 ITERATION COUNT vs DERIVATION TIME")
print("=" * 60)
print(f"{'Iterations':<15} {'Avg Time (ms)':<15} {'Guesses/sec (approx)'}")
print("-" * 60)

for iterations in PBKDF2_ITERATIONS:
    avg_ms = benchmark_pbkdf2(iterations)
    guesses_per_sec = 1000 / avg_ms if avg_ms > 0 else 0
    
    print(f"{iterations:<15} {avg_ms:<15.4f} {guesses_per_sec:<.2f}")
    
    results.append({
        'Test': 'PBKDF2 Iterations',
        'Algorithm': f'PBKDF2-{iterations}',
        'Data Size': 'N/A',
        'Time (ms)': avg_ms,
        'Throughput (MB/s)': guesses_per_sec
    })

# ============================================
# TEST 3: HASH FUNCTION COMPARISON
# ============================================
def benchmark_hash(algo):
    """Benchmark SHA-256 or SHA-512."""
    password = b"test_password_123"
    
    start = time.perf_counter()
    for _ in range(REPETITIONS):
        hashlib.new(algo, password).hexdigest()
    end = time.perf_counter()
    
    avg_ms = (end - start) / REPETITIONS * 1000
    return avg_ms

def benchmark_bcrypt():
    """Benchmark bcrypt hashing."""
    password = b"test_password_123"
    
    start = time.perf_counter()
    for _ in range(10):  # bcrypt is slow, only 10 reps
        salt = bcrypt.gensalt()
        bcrypt.hashpw(password, salt)
    end = time.perf_counter()
    
    avg_ms = (end - start) / 10 * 1000
    return avg_ms

print("\n" + "=" * 60)
print("TEST 3: HASH FUNCTION PERFORMANCE")
print("=" * 60)
print(f"{'Algorithm':<15} {'Avg Time (ms)':<15} {'Hashes/sec'}")
print("-" * 60)

for algo in HASH_ALGORITHMS:
    avg_ms = benchmark_hash(algo)
    hashes_per_sec = 1000 / avg_ms if avg_ms > 0 else 0
    print(f"{algo:<15} {avg_ms:<15.6f} {hashes_per_sec:<.2f}")
    
    results.append({
        'Test': 'Hash Functions',
        'Algorithm': algo,
        'Data Size': 'N/A',
        'Time (ms)': avg_ms,
        'Throughput (MB/s)': hashes_per_sec
    })

avg_ms = benchmark_bcrypt()
hashes_per_sec = 1000 / avg_ms if avg_ms > 0 else 0
print(f"bcrypt{'':<10} {avg_ms:<15.4f} {hashes_per_sec:<.2f}")

results.append({
    'Test': 'Hash Functions',
    'Algorithm': 'bcrypt',
    'Data Size': 'N/A',
    'Time (ms)': avg_ms,
    'Throughput (MB/s)': hashes_per_sec
})

# ============================================
# SAVE RESULTS TO CSV
# ============================================
df = pd.DataFrame(results)
df.to_csv('benchmark_results.csv', index=False)
print("\n✅ Results saved to benchmark_results.csv")
print(f"Total tests run: {len(results)}")