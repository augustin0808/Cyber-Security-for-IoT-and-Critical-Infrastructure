import json
from pathlib import Path
from collections import Counter
import matplotlib.pyplot as plt

paths = sorted(Path('json').glob('nvdcve-2.0-*.json'))
print(f'Found {len(paths)} JSON files')

threat_terms = [
    ('overflow', 'Overflow'),
    ('denial of service', 'Denial of Service'),
    ('sql injection', 'SQL Injection'),
    ('cross-site scripting', 'Cross-Site Scripting'),
    ('memory corruption', 'Memory Corruption'),
]

cps_terms = [
    'cps',
    'cyber-physical',
    'industrial control',
    'scada',
    'plc',
    'rtu',
    'ics',
    'distributed control system',
    'dcs',
    'programmable logic controller',
    'supervisory control and data acquisition',
]

all_counts = Counter()
cps_only_counts = Counter()
cps_matches = {t: [] for t, _ in threat_terms}

for path in paths:
    data = json.loads(path.read_text(encoding='utf8'))
    items = data.get('vulnerabilities', data.get('CVE_Items', []))
    for item in items:
        cve = item.get('cve', {})
        descs = cve.get('descriptions') or cve.get('description') or ''
        if isinstance(descs, list) and descs:
            desc = descs[0].get('value', '') or ''
        elif isinstance(descs, str):
            desc = descs
        else:
            desc = ''
        desc_low = desc.lower()
        if not desc_low:
            continue
        item_id = cve.get('id') or cve.get('CVE_data_meta', {}).get('ID')
        is_cps = any(term in desc_low for term in cps_terms)
        for term, label in threat_terms:
            if term in desc_low:
                all_counts[label] += 1
                if is_cps:
                    cps_only_counts[label] += 1
                    cps_matches[term].append((item_id, path.stem.split('-')[-1], desc.strip().replace('\n', ' ')))

print('All threat counts:')
for label in [label for _, label in threat_terms]:
    print(f'  {label}: {all_counts[label]}')

print('\nCPS-specific threat counts:')
for label in [label for _, label in threat_terms]:
    print(f'  {label}: {cps_only_counts[label]}')

print('\nThreats with zero CPS matches:')
for term, label in threat_terms:
    if cps_only_counts[label] == 0:
        print(f'  {label}')

print('\nTop CPS examples by threat category:')
for term, label in threat_terms:
    examples = cps_matches[term][:3]
    print(f'\n{label} ({len(cps_matches[term])} CPS matches)')
    for item_id, year, desc in examples:
        print(f'   - {item_id} ({year}) {desc[:120]}...')


def plot_cps_threat_trends(output_file='cps_threat_trends.png'):
    """Generate a CPS threat correlation plot from the JSON CVE dataset."""
    yearly_counts = []
    years = []

    for path in sorted(Path('json').glob('nvdcve-2.0-*.json')):
        year = int(path.stem.split('-')[-1])
        years.append(year)
        counts = {label: 0 for _, label in threat_terms}
        data = json.loads(path.read_text(encoding='utf8'))
        items = data.get('vulnerabilities', data.get('CVE_Items', []))

        for item in items:
            cve = item.get('cve', {})
            descs = cve.get('descriptions') or cve.get('description') or ''
            if isinstance(descs, list) and descs:
                desc = descs[0].get('value', '') or ''
            elif isinstance(descs, str):
                desc = descs
            else:
                desc = ''
            desc_low = desc.lower()
            if not desc_low or not any(term in desc_low for term in cps_terms):
                continue
            for term, label in threat_terms:
                if term in desc_low:
                    counts[label] += 1

        yearly_counts.append(counts)

    fig, ax = plt.subplots(figsize=(12, 7))
    x = list(range(len(years)))
    width = 0.15

    for i, (_, label) in enumerate(threat_terms):
        values = [counts[label] for counts in yearly_counts]
        ax.bar([pos + i * width for pos in x], values, width=width, label=label)

    ax.set_xlabel('Year')
    ax.set_ylabel('CPS-related CVE count')
    ax.set_title('CPS threat correlation by year and category')
    ax.set_xticks([pos + width * (len(threat_terms) - 1) / 2 for pos in x])
    ax.set_xticklabels(years, rotation=45)
    ax.legend()
    ax.grid(axis='y', alpha=0.25)
    plt.tight_layout()
    plt.savefig(output_file, dpi=200)
    plt.close()
    print(f'Saved plot: {output_file}')


plot_cps_threat_trends()
