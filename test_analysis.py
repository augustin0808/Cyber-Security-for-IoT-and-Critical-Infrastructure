"""Quick test of threat analysis on a smaller dataset"""
from analyze import (
    analyze_exploitation_threats, 
    print_threat_analysis_report,
    plot_exploitation_threats_distribution,
    plot_threats_by_year
)

if __name__ == "__main__":
    # Test with just last 2 years to verify it works
    start_year = 2024
    end_year = 2025
    
    print("="*80)
    print("THREAT ANALYSIS TEST (2024-2025)")
    print("="*80)
    print(f"Analyzing CVE data from {start_year} to {end_year}\n")
    
    threat_results = analyze_exploitation_threats(start_year, end_year)
    print_threat_analysis_report(threat_results)
    plot_exploitation_threats_distribution(threat_results)
    
    print("\n✓ Test complete! Check generated PNG files.")
