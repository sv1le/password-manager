import matplotlib.pyplot as plt
import numpy as np

attacks = ['XSS Injection', 'Stolen JWT', 'MITM (Network)', 'Server Compromise', 'DB Tampering']
# Data format: [Plaintext Stolen (%), Ciphertext/Useless Data (%)]
plaintext_stolen = [100, 0, 0, 0, 0] 
ciphertext_only = [0, 100, 100, 100, 100]

plt.figure(figsize=(10, 5))
# Plot Plaintext (Red)
plt.barh(attacks, plaintext_stolen, color='#ff4444', label='Plaintext (Readable) Data Stolen')
# Plot Ciphertext (Green)
plt.barh(attacks, ciphertext_only, left=plaintext_stolen, color='#00d4ff', label='Ciphertext (Useless) Data Stolen')

plt.xlabel('Percentage of Data Exfiltrated (%)', fontsize=12)
plt.title('Data Exfiltration: What the Attacker Actually Gets', fontsize=14, fontweight='bold')
plt.xlim(0, 100)
plt.legend(loc='lower right')

# Add text labels
for i in range(len(attacks)):
    if plaintext_stolen[i] > 0:
        plt.text(50, i, "100% PLAINTEXT", va='center', ha='center', color='white', fontweight='bold')
    else:
        plt.text(50, i, "100% USELESS CIPHERTEXT", va='center', ha='center', color='black', fontweight='bold')

plt.tight_layout()
plt.savefig('graph_data_exfiltration.png', dpi=300)
plt.show()