import matplotlib.pyplot as plt
import numpy as np

# Labels for the groups (The Attack Surfaces)
attacks = ['XSS Injection', 'MITM (Network)', 'DB Tampering', 'Password Brute-Force']

# The 4 Parameters we are measuring
parameters = ['Privilege Required', 'Compute Cost', 'Ease of Execution', 'Data Exfiltrated']

# Data (Scale 1 to 5)
# Format: [Privilege, Compute, Ease, Data]
xss_data = [1, 1, 5, 5]          # Easy to do, needs no admin, steals everything
mitm_data = [2, 1, 4, 1]         # Needs to be on same wifi, steals little (TLS blocks it)
db_tamper_data = [5, 1, 2, 0]    # Needs root access, but yields 0 plaintext (GCM blocks it)
bruteforce_data = [1, 5, 1, 0]   # Anyone can try, but needs massive compute, yields 0

# Set up the figure
x = np.arange(len(attacks))  # The label locations
width = 0.2  # The width of the bars
multiplier = 0

fig, ax = plt.subplots(figsize=(12, 6))

# Loop through the 4 parameters and create a bar for each attack
colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
for attribute, measurement in zip(parameters, zip(xss_data, mitm_data, db_tamper_data, bruteforce_data)):
    offset = width * multiplier
    rects = ax.bar(x + offset, measurement, width, label=attribute, color=colors[multiplier])
    ax.bar_label(rects, padding=3)
    multiplier += 1

# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Score (1 = Low, 5 = High)', fontsize=12)
ax.set_title('Attacker Effort vs. Impact: Comparing Attack Surfaces', fontsize=14, fontweight='bold')
ax.set_xticks(x + width * 1.5, attacks, fontsize=12)
ax.legend(loc='upper right', ncols=2)
ax.set_ylim(0, 6)

plt.tight_layout()
plt.savefig('graph_attacker_profile.png', dpi=300)
print("✅ Saved graph_attacker_profile.png")
plt.show()