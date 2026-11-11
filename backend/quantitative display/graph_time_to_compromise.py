import matplotlib.pyplot as plt
import numpy as np

attacks = ['JWT Theft', 'Rate-Limiter\nBypass', 'XSS Injection', 'DB Tampering', 'Brute-Force\nAES-256']
# Time in seconds
times = [1, 10800, 86400, 604800, 3.15e16] 

plt.figure(figsize=(10, 6))
plt.barh(attacks, times, color=['red', 'orange', 'yellow', 'lightblue', 'green'])
plt.xscale('log') # LOGARITHMIC SCALE IS CRUCIAL HERE
plt.xlabel('Time to Compromise (Seconds - Log Scale)')
plt.title('Attacker Effort: Time-to-Compromise by Attack Vector')
plt.grid(axis='x', linestyle='--', alpha=0.7)

# Add text labels to the bars
for i, v in enumerate(times):
    plt.text(v, i, f" {v:,.0f} sec", va='center')

plt.tight_layout()
plt.savefig('graph_time_to_compromise.png', dpi=300)
plt.show()