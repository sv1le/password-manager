"""
Generate graphs from benchmark results.
Run: python generate_graphs.py
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load results
df = pd.read_csv('benchmark_results.csv')

# Set style
plt.style.use('seaborn-v0_8-darkgrid')
colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#3B1F2B']

# ============================================
# GRAPH 1: AES Encryption Time by Key Size
# ============================================
aes_df = df[df['Test'] == 'AES Encryption'].copy()

fig, ax = plt.subplots(figsize=(10, 6))
data_sizes = ['1KB', '10KB', '100KB']
x = np.arange(len(data_sizes))
width = 0.2

algorithms = ['AES-128-GCM', 'AES-192-GCM', 'AES-256-GCM', 'AES-256-CBC']

for i, algo in enumerate(algorithms):
    algo_data = aes_df[aes_df['Algorithm'] == algo]
    times = [algo_data[algo_data['Data Size'] == size]['Time (ms)'].values[0] for size in data_sizes]
    bars = ax.bar(x + i*width, times, width, label=algo, color=colors[i])
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.3f}', ha='center', va='bottom', fontsize=8)

ax.set_xlabel('Data Size', fontsize=12)
ax.set_ylabel('Encryption Time (ms)', fontsize=12)
ax.set_title('AES Encryption Performance Comparison', fontsize=14, fontweight='bold')
ax.set_xticks(x + width * 1.5)
ax.set_xticklabels(data_sizes)
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig('graph_aes_comparison.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Saved graph_aes_comparison.png")

# ============================================
# GRAPH 2: PBKDF2 Iterations vs Time
# ============================================
pbkdf2_df = df[df['Test'] == 'PBKDF2 Iterations'].copy()
pbkdf2_df['Iterations'] = pbkdf2_df['Algorithm'].str.replace('PBKDF2-', '').astype(int)
pbkdf2_df = pbkdf2_df.sort_values('Iterations')

fig, ax1 = plt.subplots(figsize=(10, 6))

ax1.plot(pbkdf2_df['Iterations'], pbkdf2_df['Time (ms)'], 'o-', color='#2E86AB', linewidth=2, markersize=8, label='Derivation Time')
ax1.set_xlabel('Iteration Count', fontsize=12)
ax1.set_ylabel('Time per Derivation (ms)', fontsize=12, color='#2E86AB')
ax1.tick_params(axis='y', labelcolor='#2E86AB')
ax1.set_xscale('log')

ax2 = ax1.twinx()
ax2.plot(pbkdf2_df['Iterations'], pbkdf2_df['Throughput (MB/s)'], 's--', color='#C73E1D', linewidth=2, markersize=8, label='Guesses/sec')
ax2.set_ylabel('Guesses per Second', fontsize=12, color='#C73E1D')
ax2.tick_params(axis='y', labelcolor='#C73E1D')

ax1.set_title('PBKDF2: Security vs Performance Trade-off', fontsize=14, fontweight='bold')

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=10)

plt.tight_layout()
plt.savefig('graph_pbkdf2_tradeoff.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Saved graph_pbkdf2_tradeoff.png")

# ============================================
# GRAPH 3: Hash Function Comparison
# ============================================
hash_df = df[df['Test'] == 'Hash Functions'].copy()
hash_df = hash_df.sort_values('Time (ms)')

fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.barh(hash_df['Algorithm'], hash_df['Time (ms)'], color=['#2E86AB', '#A23B72', '#C73E1D'])

for bar in bars:
    width = bar.get_width()
    ax.text(width, bar.get_y() + bar.get_height()/2.,
            f'{width:.4f} ms', ha='left', va='center', fontsize=10, fontweight='bold')

ax.set_xlabel('Hash Time (ms)', fontsize=12)
ax.set_title('Hash Function Performance (Lower is Faster)', fontsize=14, fontweight='bold')
ax.set_xlim(0, max(hash_df['Time (ms)']) * 1.3)
plt.tight_layout()
plt.savefig('graph_hash_comparison.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Saved graph_hash_comparison.png")

print("\n🎉 All graphs generated successfully!")