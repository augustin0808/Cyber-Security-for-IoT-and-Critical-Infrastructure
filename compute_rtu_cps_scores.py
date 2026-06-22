import json
from pathlib import Path

def load_json(path):
    with open(path, encoding='utf8') as f:
        return json.load(f)

def get_items(data):
    if isinstance(data, dict):
        if 'vulnerabilities' in data:
            return data['vulnerabilities']
        return data.get('CVE_Items', [])
    return []

def get_desc(item):
    cve = item.get('cve', {})
    descs = cve.get('descriptions') or cve.get('description')
    if isinstance(descs, list) and descs:
        return descs[0].get('value', '') or ''
    if isinstance(descs, str):
        return descs
    return ''

def get_score(item):
    cve = item.get('cve', {})
    metrics = cve.get('metrics', {})
    if isinstance(metrics, dict):
        for key in ('cvssMetricV3', 'baseMetricV3', 'cvssMetricV2', 'baseMetricV2'):
            if key in metrics:
                data = metrics[key]
                if isinstance(data, list) and data:
                    data = data[0]
                if isinstance(data, dict):
                    cvss = data.get('cvssData') or data.get('cvssV3') or data
                    if isinstance(cvss, dict):
                        for score_field in ('baseScore', 'score'):
                            score = cvss.get(score_field)
                            if isinstance(score, (int, float)):
                                return score
    impact = cve.get('impact')
    if isinstance(impact, dict):
        for score_field in ('baseScore', 'score'):
            score = impact.get(score_field)
            if isinstance(score, (int, float)):
                return score
    return None

def find_scores(term):
    term_lower = term.lower()
    scores = []
    for path in sorted(Path('json').glob('nvdcve-2.0-*.json')):
        data = load_json(path)
        for item in get_items(data):
            desc = get_desc(item) or ''
            if term_lower in desc.lower():
                score = get_score(item)
                if isinstance(score, (int, float)):
                    scores.append(score)
    return scores

if __name__ == '__main__':
    for term in ['MTU', 'CPS']:
        scores = find_scores(term)
        avg = sum(scores) / len(scores) if scores else None
        print(f"{term}: count={len(scores)}, avg={avg}")
