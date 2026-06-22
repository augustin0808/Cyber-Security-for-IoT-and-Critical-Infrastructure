import os
import requests
import zipfile
import json
import matplotlib.pyplot as plt
from os import listdir
from os.path import join


def download_cves(start_year, end_year, output_dir="zip"):
    """Download CVE JSON zip files for a year-range from NIST NVD."""

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    for year in range(start_year, end_year + 1):
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip"
        filename = f"nvdcve-2.0-{year}.json.zip"
        filepath = os.path.join(output_dir, filename)

        print(f"Downloading {year}...")

        try:
            response = requests.get(url, timeout=300)
            response.raise_for_status()

            with open(filepath, 'wb') as f:
                f.write(response.content)

            print(f"✓ Saved: {filename}")

        except requests.exceptions.RequestException as e:
            print(f"✗ Failed to download {year}: {e}")

    print("\nDownload complete!")


#if __name__ == "__main__":
    # 1: Get NVD CVE zip files and store them locally
    #download_cves(2016, 2025)

def unzip_cves(input_dir="zip", output_dir="json"):
    """Unzip downloaded CVE JSON zip files"""
    # Create output directory for JSON files if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    # Get all zip files from the input directory
    files_to_unzip = [f for f in listdir(input_dir)]
    files_to_unzip.sort()
    print(f"\nUnzipping files...")
    for filename in files_to_unzip:
        zip_filepath = os.path.join(input_dir, filename)
        print(f"Unzipping: {filename}...")
        try:
            with zipfile.ZipFile(zip_filepath, 'r') as archive:
                archive.extractall(output_dir)
                print(f"✓ Extracted {filename}")
        except zipfile.BadZipFile:
            print(f"✗ Failed to unzip {filename}: Not a valid zip file.")
        except Exception as e:
            print(f"✗ Failed to unzip {filename}: {e}")
    print("\nUnzip complete!")


#if __name__ == "__main__":
    # 2. Extract json files from zip files
    #unzip_cves()


def create_nvd_dict(year, json_dir="json", verbose=False):
    """Load a CVE JSON file for a given year into a dictionary.

    Args:
        year (int): The year of the CVE data to load.
        json_dir (str): The directory where the JSON files are located.
        verbose (bool): Whether to print status messages.

    Returns:
        dict: A dictionary containing CVE data for the specified year.
    """
    filename = join(json_dir, f"nvdcve-2.0-{year}.json")
    if verbose:
        print(f"Opening: {filename}")
    try:
        with open(filename, encoding='utf8') as json_file:
            cve_dict = json.load(json_file)
            if verbose:
                print(f"✓ Successfully loaded {filename}")
            return cve_dict
    except FileNotFoundError:
        if verbose:
            print(f"✗ File not found: {filename}")
        return None
    except json.JSONDecodeError as e:
        if verbose:
            print(f"✗ Failed to parse JSON from {filename}: {e}")
        return None
    except Exception as e:
        if verbose:
            print(f"✗ Failed to load {filename}: {e}")
        return None


def get_cve_items(cve_data):
    if not cve_data:
        return []
    if 'vulnerabilities' in cve_data:
        return cve_data['vulnerabilities']
    if 'CVE_Items' in cve_data:
        return cve_data['CVE_Items']
    return []


def get_description(item):
    cve_obj = item.get('cve', {}) if isinstance(item, dict) else {}
    descriptions = cve_obj.get('descriptions')
    if descriptions and isinstance(descriptions, list) and descriptions:
        return descriptions[0].get('value')
    return cve_obj.get('description')


# if __name__ == "__main__":
#     year_to_load = 2020
#     cve_data = create_nvd_dict(year_to_load)
#     if cve_data:
#         items = cve_data.get('CVE_Items', cve_data.get('vulnerabilities', []))
#         if items and len(items) > 0:
#             print(json.dumps(items[0], indent=4, separators=(',', ': ')))
#         else:
#             print("No CVE items found in the data")

def contains_word(s, w):
    """Check if word/phrase w is contained in string s (case-insensitive)."""
    if not s:
        return False
    s_lower = s.lower()
    w_lower = w.lower()
    # Check with word boundaries
    return (' ' + w_lower + ' ') in (' ' + s_lower + ' ') or w_lower in s_lower


def search_description(expression, start_year, end_year, json_dir="json"):
    """
    Searches CVE descriptions for a given keyword across a range of years.
    Args:
        expression (str): The keyword or phrase to search for.
        start_year (int): The starting year for the search.
        end_year (int): The ending year for the search.
        json_dir (str): The directory containing the CVE JSON files.
    Returns:
        list: A list of entries with the expression.
    """
    list_of_reports = []
    expression_lower = expression.lower()
    
    for year in range(start_year, end_year + 1):
        cve_data = create_nvd_dict(year, json_dir, verbose=False)
        if not cve_data:
            continue
            
        items = get_cve_items(cve_data)
        matched = 0
        
        for item in items:
            description_value = get_description(item)
            # Optimized check: if phrase appears anywhere in description
            if description_value and expression_lower in description_value.lower():
                cve_id = item.get('cve', {}).get('id') or item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                list_of_reports.append({
                    'year': year,
                    'cve_id': cve_id,
                    'main_description': description_value
                })
                matched += 1
        
        print(f"    {year}: {matched} matches")
    
    return list_of_reports


def count_vulnerabilities_by_year(component_type, start_year, end_year, json_dir="json"):
    counts = {}
    for year in range(start_year, end_year + 1):
        cve_data = create_nvd_dict(year, json_dir)
        year_count = 0
        for item in get_cve_items(cve_data):
            description_value = get_description(item)
            if description_value and contains_word(description_value, component_type):
                year_count += 1
        counts[year] = year_count
    return counts


def plot_vulnerability_scale(component_type, start_year, end_year, json_dir="json"):
    counts = count_vulnerabilities_by_year(component_type, start_year, end_year, json_dir)
    years = list(counts.keys())
    values = [counts[year] for year in years]

    plt.figure(figsize=(10, 6))
    plt.bar(years, values, color='tab:blue')
    plt.title(f"Vulnerability instances for component type: {component_type}")
    plt.xlabel("Year")
    plt.ylabel("Number of CVE reports")
    plt.xticks(years, rotation=45)
    plt.tight_layout()
    output_file = f"vulnerability_scale_{component_type}.png"
    plt.savefig(output_file)
    plt.close()
    print(f"Saved graph to {output_file}")


# ==================== EXPLOITATION THREAT ANALYSIS ====================

# Define exploitation threats with descriptions
EXPLOITATION_THREATS = {
    'overflow': {
        'name': 'Buffer Overflow',
        'description': 'A buffer overflow vulnerability occurs when a program writes more data to a buffer than it can hold. '
                      'This can cause data corruption, crashes, or allow attackers to overwrite adjacent memory locations. '
                      'Attackers can exploit this to execute arbitrary code or escalate privileges. '
                      'Buffer overflows are particularly dangerous in C/C++ programs that use unsafe memory operations.'
    },
    'denial of service': {
        'name': 'Denial of Service (DoS)',
        'description': 'A Denial of Service attack aims to make a system, service, or network unavailable to legitimate users. '
                      'Common DoS attacks include flooding with network traffic, exploiting algorithmic weaknesses, or '
                      'crashing the application through malformed input. DoS vulnerabilities can have severe impacts on '
                      'critical infrastructure and business continuity.'
    },
    'SQL injection': {
        'name': 'SQL Injection',
        'description': 'SQL Injection occurs when an attacker inserts malicious SQL code into user input fields that are '
                      'incorporated into database queries without proper sanitization. This allows attackers to execute '
                      'unauthorized SQL commands, potentially leading to unauthorized data access, modification, or deletion. '
                      'SQL injection is one of the most common and dangerous web application vulnerabilities.'
    },
    'cross-site scripting': {
        'name': 'Cross-Site Scripting (XSS)',
        'description': 'Cross-Site Scripting vulnerabilities allow attackers to inject malicious JavaScript code that runs '
                      'in users\' browsers. This can lead to session hijacking, credential theft, malware distribution, and '
                      'defacement. XSS vulnerabilities exist when user input is not properly validated and sanitized before '
                      'being displayed in web pages.'
    },
    'memory corruption': {
        'name': 'Memory Corruption',
        'description': 'Memory corruption vulnerabilities occur when a program incorrectly accesses or modifies memory, leading to '
                      'unpredictable behavior. Common causes include use-after-free errors, double-free vulnerabilities, and '
                      'uninitialized memory access. Memory corruption can lead to crashes, arbitrary code execution, and is often '
                      'exploited in advanced attack chains.'
    }
}


def analyze_exploitation_threats(start_year, end_year, json_dir="json"):
    """
    Analyze exploitation threats across CVE data.
    
    Args:
        start_year (int): Starting year for analysis
        end_year (int): Ending year for analysis
        json_dir (str): Directory containing JSON files
        
    Returns:
        dict: Results containing threat counts and detailed information
    """
    threat_results = {}
    total_threats = len(EXPLOITATION_THREATS)
    
    for idx, (threat_key, threat_info) in enumerate(EXPLOITATION_THREATS.items(), 1):
        print(f"\n[{idx}/{total_threats}] Searching for {threat_info['name']}...")
        reports = search_description(threat_key, start_year, end_year, json_dir)
        threat_results[threat_key] = {
            'name': threat_info['name'],
            'description': threat_info['description'],
            'count': len(reports),
            'reports': reports
        }
    
    return threat_results


def plot_exploitation_threats_distribution(threat_results):
    """
    Create a bar chart showing the distribution of exploitation threats.
    
    Args:
        threat_results (dict): Results from analyze_exploitation_threats()
    """
    threat_names = [threat_results[key]['name'] for key in EXPLOITATION_THREATS.keys()]
    threat_counts = [threat_results[key]['count'] for key in EXPLOITATION_THREATS.keys()]
    
    plt.figure(figsize=(12, 7))
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8']
    bars = plt.bar(threat_names, threat_counts, color=colors, edgecolor='black', linewidth=1.5)
    
    # Add value labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    plt.title('Exploitation Threats in CVE Database (2016-2025)', fontsize=14, fontweight='bold')
    plt.xlabel('Threat Type', fontsize=12, fontweight='bold')
    plt.ylabel('Number of Vulnerability Reports', fontsize=12, fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()
    
    output_file = "exploitation_threats_distribution.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"\n✓ Saved distribution chart to {output_file}")


def plot_threats_by_year(threat_results, start_year, end_year, json_dir="json"):
    """
    Create a line chart showing threat trends over time.
    
    Args:
        threat_results (dict): Results from analyze_exploitation_threats()
        start_year (int): Starting year
        end_year (int): Ending year
        json_dir (str): Directory containing JSON files
    """
    years = list(range(start_year, end_year + 1))
    threat_keys = list(EXPLOITATION_THREATS.keys())
    
    plt.figure(figsize=(14, 8))
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8']
    
    for idx, threat_key in enumerate(threat_keys):
        yearly_counts = []
        for year in years:
            reports = threat_results[threat_key]['reports']
            count = len([r for r in reports if r['year'] == year])
            yearly_counts.append(count)
        
        plt.plot(years, yearly_counts, marker='o', linewidth=2.5, markersize=8,
                label=threat_results[threat_key]['name'], color=colors[idx])
    
    plt.title('Exploitation Threats Trends Over Time (2016-2025)', fontsize=14, fontweight='bold')
    plt.xlabel('Year', fontsize=12, fontweight='bold')
    plt.ylabel('Number of CVE Reports', fontsize=12, fontweight='bold')
    plt.xticks(years, rotation=45)
    plt.legend(loc='best', fontsize=10)
    plt.grid(True, alpha=0.3, linestyle='--')
    plt.tight_layout()
    
    output_file = "exploitation_threats_timeline.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✓ Saved timeline chart to {output_file}")


def print_threat_analysis_report(threat_results):
    """
    Print a detailed analysis report of exploitation threats.
    
    Args:
        threat_results (dict): Results from analyze_exploitation_threats()
    """
    print("\n" + "="*80)
    print("EXPLOITATION THREATS ANALYSIS REPORT")
    print("="*80)
    
    total_threats = sum(result['count'] for result in threat_results.values())
    
    print(f"\nTOTAL VULNERABILITY INSTANCES: {total_threats}\n")
    
    # Sort by count descending
    sorted_threats = sorted(threat_results.items(), key=lambda x: x[1]['count'], reverse=True)
    
    for idx, (threat_key, threat_data) in enumerate(sorted_threats, 1):
        percentage = (threat_data['count'] / total_threats * 100) if total_threats > 0 else 0
        print(f"\n{idx}. {threat_data['name'].upper()}")
        print(f"   Count: {threat_data['count']} ({percentage:.1f}% of total)")
        print(f"   Description: {threat_data['description']}")
        print("-" * 80)


if __name__ == "__main__":
    # Analyze exploitation threats
    start_year = 2016
    end_year = 2025
    
    print("="*80)
    print("EXPLOITATION THREATS ANALYSIS")
    print("="*80)
    print(f"Analyzing CVE data from {start_year} to {end_year}\n")
    
    # Perform analysis
    threat_results = analyze_exploitation_threats(start_year, end_year)
    
    # Print detailed report
    print_threat_analysis_report(threat_results)
    
    # Create visualizations
    print("\nGenerating visualizations...")
    plot_exploitation_threats_distribution(threat_results)
    plot_threats_by_year(threat_results, start_year, end_year)
    
    print("\n" + "="*80)
    print("✓ Analysis complete!")
    print("="*80)
