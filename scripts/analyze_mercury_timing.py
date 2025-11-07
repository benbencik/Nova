#!/usr/bin/env python3
"""
Mercury Timing Analyzer

Parses and visualizes timing data from Mercury proof generation.
Reads JSON timing data and produces analysis and visualizations.

Usage:
    python scripts/analyze_mercury_timing.py timing_data.json
    python scripts/analyze_mercury_timing.py timing_data.json --plot
"""

import json
import sys
from collections import defaultdict
from typing import Dict, List, Tuple


def parse_timing_data(filename: str) -> List[Dict]:
    """Load timing data from JSON file."""
    with open(filename, 'r') as f:
        data = json.load(f)
    return data.get('timings', [])


def analyze_timings(timings: List[Dict]) -> Dict:
    """Analyze timing data and compute statistics."""
    stats = defaultdict(lambda: {'times': [], 'count': 0, 'total': 0})
    
    for entry in timings:
        section = entry['section']
        duration_us = entry['duration_us']
        
        stats[section]['times'].append(duration_us)
        stats[section]['count'] += 1
        stats[section]['total'] += duration_us
    
    # Compute additional statistics
    for section, data in stats.items():
        times = data['times']
        data['avg'] = data['total'] / data['count']
        data['min'] = min(times)
        data['max'] = max(times)
        
        # Compute median
        sorted_times = sorted(times)
        n = len(sorted_times)
        if n % 2 == 0:
            data['median'] = (sorted_times[n//2-1] + sorted_times[n//2]) / 2
        else:
            data['median'] = sorted_times[n//2]
    
    return dict(stats)


def print_analysis(stats: Dict):
    """Print analysis in human-readable format."""
    print("\n=== Mercury Performance Analysis ===\n")
    
    # Sort by total time
    sorted_sections = sorted(stats.items(), 
                            key=lambda x: x[1]['total'], 
                            reverse=True)
    
    total_time = sum(s['total'] for s in stats.values())
    
    print(f"Total execution time: {total_time/1000:.2f} ms")
    print(f"Number of sections: {len(stats)}\n")
    
    print(f"{'Section':<50} {'Total (ms)':<12} {'Count':<8} {'Avg (ms)':<12} {'Min (ms)':<12} {'Max (ms)':<12} {'% of Total':<10}")
    print("-" * 130)
    
    for section, data in sorted_sections:
        total_ms = data['total'] / 1000
        avg_ms = data['avg'] / 1000
        min_ms = data['min'] / 1000
        max_ms = data['max'] / 1000
        percentage = (data['total'] / total_time) * 100
        
        print(f"{section:<50} {total_ms:<12.2f} {data['count']:<8} {avg_ms:<12.2f} {min_ms:<12.2f} {max_ms:<12.2f} {percentage:<10.1f}%")
    
    print("\n=== Performance Hotspots ===\n")
    
    # Identify major categories
    categories = {
        'FFT': [],
        'MSM': [],
        'Polynomial': [],
        'Pairing': [],
        'Other': []
    }
    
    for section, data in stats.items():
        if 'fft' in section.lower():
            categories['FFT'].append((section, data))
        elif 'msm' in section.lower() or 'commit' in section.lower():
            categories['MSM'].append((section, data))
        elif 'pairing' in section.lower():
            categories['Pairing'].append((section, data))
        elif any(x in section.lower() for x in ['poly', 'divide', 'compute']):
            categories['Polynomial'].append((section, data))
        else:
            categories['Other'].append((section, data))
    
    for category, items in categories.items():
        if items:
            category_total = sum(data['total'] for _, data in items)
            percentage = (category_total / total_time) * 100
            print(f"{category}: {category_total/1000:.2f} ms ({percentage:.1f}%)")


def plot_timings(stats: Dict):
    """Create visualizations of timing data."""
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("Error: matplotlib not installed. Install with: pip install matplotlib")
        return
    
    # Sort by total time
    sorted_sections = sorted(stats.items(), 
                            key=lambda x: x[1]['total'], 
                            reverse=True)
    
    # Take top 15 sections for readability
    top_sections = sorted_sections[:15]
    
    sections = [s[0] for s in top_sections]
    totals = [s[1]['total'] / 1000 for s in top_sections]  # Convert to ms
    
    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Bar chart
    y_pos = np.arange(len(sections))
    ax1.barh(y_pos, totals)
    ax1.set_yticks(y_pos)
    ax1.set_yticklabels(sections, fontsize=8)
    ax1.invert_yaxis()
    ax1.set_xlabel('Time (ms)')
    ax1.set_title('Mercury - Top Operations by Total Time')
    ax1.grid(axis='x', alpha=0.3)
    
    # Pie chart for categories
    categories = {
        'FFT Operations': 0,
        'MSM/Commitments': 0,
        'Polynomial Ops': 0,
        'Pairing': 0,
        'Batch Evaluation': 0,
        'Other': 0
    }
    
    total_time = sum(s['total'] for s in stats.values())
    
    for section, data in stats.items():
        section_lower = section.lower()
        if 'fft' in section_lower:
            categories['FFT Operations'] += data['total']
        elif 'msm' in section_lower or 'commit' in section_lower:
            categories['MSM/Commitments'] += data['total']
        elif 'pairing' in section_lower:
            categories['Pairing'] += data['total']
        elif 'batch' in section_lower:
            categories['Batch Evaluation'] += data['total']
        elif any(x in section_lower for x in ['poly', 'divide', 'compute', 'make_s']):
            categories['Polynomial Ops'] += data['total']
        else:
            categories['Other'] += data['total']
    
    # Filter out zero categories
    categories = {k: v/1000 for k, v in categories.items() if v > 0}
    
    labels = list(categories.keys())
    sizes = list(categories.values())
    
    ax2.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax2.set_title('Mercury - Time Distribution by Category')
    
    plt.tight_layout()
    plt.savefig('mercury_timing_analysis.png', dpi=150, bbox_inches='tight')
    print("\nPlot saved as 'mercury_timing_analysis.png'")
    plt.show()


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_mercury_timing.py <timing_data.json> [--plot]")
        sys.exit(1)
    
    filename = sys.argv[1]
    plot = '--plot' in sys.argv
    
    timings = parse_timing_data(filename)
    
    if not timings:
        print("No timing data found in file.")
        sys.exit(1)
    
    stats = analyze_timings(timings)
    print_analysis(stats)
    
    if plot:
        plot_timings(stats)


if __name__ == '__main__':
    main()
