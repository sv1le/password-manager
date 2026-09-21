"""
Generate summary tables for the report.
Run: python summary_tables.py
"""

import pandas as pd

df = pd.read_csv('benchmark_results.csv')

# Table 1: AES Encryption
print("=" * 70)
print("TABLE 1: AES ENCRYPTION PERFORMANCE (Average of 100 runs)")
print("=" * 70)
aes = df[df['Test'] == 'AES Encryption'][['Algorithm', 'Data Size', 'Time (ms)', 'Throughput (MB/s)']]
print(aes.to_string(index=False))

# Table 2: PBKDF2
print("\n" + "=" * 70)
print("TABLE 2: PBKDF2 ITERATION COUNT vs DERIVATION TIME")
print("=" * 70)
pbkdf2 = df[df['Test'] == 'PBKDF2 Iterations'][['Algorithm', 'Time (ms)', 'Throughput (MB/s)']]
pbkdf2.columns = ['Iterations', 'Time (ms)', 'Guesses/sec']
print(pbkdf2.to_string(index=False))

# Table 3: Hash Functions
print("\n" + "=" * 70)
print("TABLE 3: HASH FUNCTION PERFORMANCE")
print("=" * 70)
hash_df = df[df['Test'] == 'Hash Functions'][['Algorithm', 'Time (ms)', 'Throughput (MB/s)']]
hash_df.columns = ['Algorithm', 'Time (ms)', 'Hashes/sec']
print(hash_df.to_string(index=False))

# Save as CSV for report
aes.to_csv('table_aes.csv', index=False)
pbkdf2.to_csv('table_pbkdf2.csv', index=False)
hash_df.to_csv('table_hash.csv', index=False)

print("\n✅ Tables saved as CSV files")