import matplotlib.pyplot as plt
import numpy as np
import os
import seaborn as sns

def main():
    os.makedirs('evaluation/figures', exist_ok=True)
    
    # Style
    plt.style.use('seaborn-v0_8-whitegrid')
    
    # 1. Confusion Matrix
    cm = np.array([[20, 0], [9, 11]])
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['BENIGN', 'ATTACK'], yticklabels=['BENIGN', 'ATTACK'], cbar=False, annot_kws={"size": 16})
    plt.title('Confusion Matrix (Mocked Benchmark)', fontsize=14, pad=15)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('Actual Label', fontsize=12)
    plt.tight_layout()
    plt.savefig('evaluation/figures/confusion_matrix.png', dpi=300)
    plt.close()

    # 2. Layer Interception
    categories = ['Rule Detection', 'Semantic Detection', 'Reached Target LLM']
    counts = [2, 9, 9]
    colors = ['#1f77b4', '#ff7f0e', '#d62728']
    
    plt.figure(figsize=(7, 5))
    bars = plt.bar(categories, counts, color=colors)
    plt.title('Layer-wise Malicious Request Interception (n=20)', fontsize=14, pad=15)
    plt.ylabel('Number of Requests', fontsize=12)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.1, int(yval), ha='center', va='bottom', fontsize=12)
    plt.tight_layout()
    plt.savefig('evaluation/figures/layer_interception.png', dpi=300)
    plt.close()

    # 3. Groq Usage
    metrics = ['Security', 'Target', 'Critic', 'Total']
    values = [0.30, 0.72, 0.72, 1.75]
    
    plt.figure(figsize=(7, 5))
    bars = plt.bar(metrics, values, color=['#9467bd', '#2ca02c', '#8c564b', '#7f7f7f'])
    plt.title('Average Groq Calls per Request', fontsize=14, pad=15)
    plt.ylabel('Average Calls', fontsize=12)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.02, f"{yval:.2f}", ha='center', va='bottom', fontsize=12)
    plt.tight_layout()
    plt.savefig('evaluation/figures/groq_usage.png', dpi=300)
    plt.close()

    # 4. Latency
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Mock
    mock_labels = ['Avg', 'Median', 'Min', 'Max']
    mock_vals = [0.27, 0.18, 0.05, 2.45]
    ax1.bar(mock_labels, mock_vals, color='#17becf')
    ax1.set_title('Controlled Mock Benchmark Latency', fontsize=12)
    ax1.set_ylabel('Milliseconds (ms)')
    for i, v in enumerate(mock_vals):
        ax1.text(i, v + 0.05, str(v), ha='center')
        
    # Live
    live_labels = ['Rule\nAttack', 'Semantic\nAttack', 'Educational', 'Legitimate\n+Validation']
    live_vals = [0.05, 1338, 3242, 2816]
    ax2.bar(live_labels, live_vals, color='#e377c2')
    ax2.set_title('Representative Live Verification Latency', fontsize=12)
    ax2.set_ylabel('Milliseconds (ms)')
    for i, v in enumerate(live_vals):
        ax2.text(i, v + 50, str(v), ha='center')
        
    plt.suptitle('Latency Comparison: Mocked vs Live', fontsize=14)
    plt.tight_layout()
    plt.savefig('evaluation/figures/latency_mock_vs_live.png', dpi=300)
    plt.close()
    
    print("Figures generated successfully.")

if __name__ == '__main__':
    main()
