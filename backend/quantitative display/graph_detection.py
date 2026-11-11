import matplotlib.pyplot as plt
import numpy as np

attacks = ['DB Tampering', 'Rate-Limiter DoS', 'MITM (Network)', 'Server Compromise', 'XSS Injection']
# Percentage of time the system detects the attack
detection_rates = [100, 100, 100, 0, 0]
# Percentage of time it happens silently
silent_rates = [0, 0, 0, 100, 100]

plt.figure(figsize=(10, 5))
plt.barh(attacks, detection_rates, color='#00d4ff', label='Detected & Blocked by System')
plt.barh(attacks, silent_rates, left=detection_rates, color='#ff4444', label='Silently Succeeds (No Detection)')

plt.xlabel('Detection Rate (%)', fontsize=12)
plt.title('System Defense: Can the App Detect the Attack?', fontsize=14, fontweight='bold')
plt.xlim(0, 100)
plt.legend(loc='lower right')

for i in range(len(attacks)):
    if detection_rates[i] > 0:
        plt.text(50, i, "100% DETECTED", va='center', ha='center', color='white', fontweight='bold')
    else:
        plt.text(50, i, "0% DETECTED", va='center', ha='center', color='white', fontweight='bold')

plt.tight_layout()
plt.savefig('graph_detection_rate.png', dpi=300)
plt.show()