#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

def plot_prover_results(csv_file='mercury_prover_results.csv'):
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found.")
        return False
    
    df = pd.read_csv(csv_file)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    ax1.plot(df['log_n'], df['total_time_ms'], 'o-', label='prover time')
    ax1.plot(df['log_n'], df['division_time_ms'], 's-', label='gq poly construction')
    ax1.set_xlabel('log(n)')
    ax1.set_ylabel('time (ms)')
    ax1.set_title('mercury prover runtime')
    ax1.grid(True, alpha=0.5)
    ax1.legend()
    # ax1.set_yscale('log')
    
    ax2.plot(df['log_n'], df['division_percentage'], 'o-')
    ax2.set_xlabel('log(n)')
    ax2.set_ylabel('gq poly construction (%)')
    ax2.set_title('gq poly construction as % of prover time')
    ax2.grid(True, alpha=0.5)
    ax2.set_ylim(0, 100)
    
    # Add text labels
    for i, row in df.iterrows():
        ax2.text(row['log_n'], row['division_percentage'] + 3, 
                f"{row['division_percentage']:.1f}%", ha='center')
    
    plt.tight_layout()
    plt.savefig('mercury_prover_performance.png')
    print("Saved: mercury_prover_performance.png")
    return True

def plot_verifier_results(csv_file='mercury_verifier_results.csv'):
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found.")
        return False
    
    df = pd.read_csv(csv_file)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    ax1.plot(df['log_n'], df['total_time_ms'], 'o-', label='verifier time')
    ax1.plot(df['log_n'], df['pairing_time_ms'], 's-', label='pairing operations')
    ax1.set_xlabel('log(n)')
    ax1.set_ylabel('time (ms)')
    ax1.set_title('mercury verifier runtime')
    ax1.legend()
    ax1.grid(True, alpha=0.5)
    
    # Plot percentage
    ax2.plot(df['log_n'], df['pairing_percentage'], 'o-')
    ax2.set_xlabel('log(n)')
    ax2.set_ylabel('pairing cost (%)')
    ax2.set_title('pairing operations as % of verifier time')
    ax2.grid(True, alpha=0.5)
    ax2.set_ylim(0, 100)
    
    # Add text labels
    for i, row in df.iterrows():
        ax2.text(row['log_n'], row['pairing_percentage'] + 3, 
                f"{row['pairing_percentage']:.1f}%", ha='center')
    
    plt.tight_layout()
    plt.savefig('mercury_verifier_performance.png')
    print("Saved: mercury_verifier_performance.png")
    return True
    

def plot_commitment_timings(csv_file='mercury_commitment_timings.csv'):
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found.")
        return False
    df = pd.read_csv(csv_file)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Set colors for consistency
    color_total = '#333333'
    color_g = '#1f77b4'  # blue
    color_q = '#ff7f0e'   # orange
    color_h = '#2ca02c' # green
    color_batch = '#d62728' # red

    # Absolute times
    ax1.plot(df['log_n'], df['total_prover_ms'], 'o-', label='total prover time', color=color_total)
    ax1.plot(df['log_n'], df['commit_q_ms'], 's-', label='commit q', color=color_q)
    ax1.plot(df['log_n'], df['commit_g_ms'], '^-', label='commit g', color=color_g)
    ax1.plot(df['log_n'], df['commit_h_ms'], 'v-', label='commit H', color=color_h)
    ax1.plot(df['log_n'], df['commit_batch_proof_ms'], 'd-', label="commit batch proof", color=color_batch)
    ax1.set_xlabel('log(n)')
    ax1.set_ylabel('time log scale(ms)')
    ax1.set_title('mercury commitment timings')
    ax1.grid(True, alpha=0.5)
    ax1.set_yscale('log')
    ax1.legend()

    # Percentages
    ax2.plot(df['log_n'], df['commit_q_pct'], 's-', label='commit q (%)', color=color_q)
    ax2.plot(df['log_n'], df['commit_g_pct'], '^-', label='commit g (%)', color=color_g)
    ax2.plot(df['log_n'], df['commit_h_pct'], 'v-', label='commit H (%)', color=color_h)
    ax2.plot(df['log_n'], df['commit_batch_proof_pct'], 'd-', label="commit batch proof (%)", color=color_batch)
    ax2.set_xlabel('log(n)')
    ax2.set_ylabel('percentage of prover time (%)')
    ax2.set_title('commitment as % of prover time')
    ax2.grid(True, alpha=0.5)
    ax2.set_ylim(0, 100)
    ax2.legend()

    # # Add text labels for percentages
    # for i, row in df.iterrows():
    #     ax2.text(row['log_n'], row['commit_q_pct'] + 2, f"{row['commit_q_pct']:.1f}%", ha='center')
    #     ax2.text(row['log_n'], row['commit_g_pct'] + 2, f"{row['commit_g_pct']:.1f}%", ha='center')
    #     ax2.text(row['log_n'], row['commit_h_pct'] + 2, f"{row['commit_h_pct']:.1f}%", ha='center')
    #     ax2.text(row['log_n'], row['commit_batch_proof_pct'] + 2, f"{row['commit_batch_proof_pct']:.1f}%", ha='center')

    plt.tight_layout()
    plt.savefig('mercury_commitment_timings.png')
    print("Saved: mercury_commitment_timings.png")
    return True

# plot_prover_results()
# plot_verifier_results()
plot_commitment_timings()
