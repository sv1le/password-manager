import matplotlib.pyplot as plt

attacks = ['DB Tampering', 'JWT Theft', 'Rate-Limiter DoS', 'Password Brute-Force']
attempts = [1, 1, 10000, 10000000000]

plt.figure(figsize=(8, 6))
colors = ['green', 'green', 'orange', 'red']
bars = plt.bar(attacks, attempts, color=colors)

plt.yscale('log') # Log scale again due to the massive difference
plt.ylabel('Number of Attempts Required (Log Scale)')
plt.title('Required Attacker Iterations')

# Label the bars
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval, f'{yval:,.0f}', ha='center', va='bottom')

plt.xticks(rotation=15)
plt.tight_layout()
plt.savefig('graph_attempts.png', dpi=300)
plt.show()