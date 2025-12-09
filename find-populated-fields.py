#!/usr/bin/env python3
"""
Script to find fields that actually contain data in Elasticsearch indices.
Usage: python3 find-populated-fields.py [ELASTICSEARCH_URL] [INDEX_PATTERN]

Defaults:
  ELASTICSEARCH_URL: http://localhost:9200
  INDEX_PATTERN: suricata-*
"""

import json
import sys
import urllib.request
import urllib.error

ES_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9200"
INDEX = sys.argv[2] if len(sys.argv) > 2 else "suricata-*"

def get_sample_docs(es_url, index, size=100):
    """Get sample documents to find populated fields."""
    query = {
        "size": size,
        "_source": True,
        "query": {"match_all": {}}
    }

    url = f"{es_url}/{index}/_search"
    req = urllib.request.Request(
        url,
        data=json.dumps(query).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"Error connecting to Elasticsearch: {e}")
        sys.exit(1)

def flatten_dict(d, parent_key='', sep='.'):
    """Flatten nested dictionary to dot notation."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            for item in v:
                items.extend(flatten_dict(item, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def main():
    print(f"Connecting to {ES_URL}...")
    print(f"Searching index pattern: {INDEX}")
    print("-" * 50)

    result = get_sample_docs(ES_URL, INDEX)
    hits = result.get("hits", {}).get("hits", [])

    if not hits:
        print("No documents found!")
        sys.exit(1)

    print(f"Analyzed {len(hits)} sample documents")

    # Collect all populated fields
    populated_fields = set()
    for hit in hits:
        source = hit.get("_source", {})
        flat = flatten_dict(source)
        for key, value in flat.items():
            if value is not None and value != "" and value != []:
                populated_fields.add(key)

    # Sort and display
    sorted_fields = sorted(populated_fields)

    print(f"\nFound {len(sorted_fields)} fields with actual data:\n")
    for field in sorted_fields:
        print(field)

    # Save to file
    output_file = "populated-fields.txt"
    with open(output_file, "w") as f:
        for field in sorted_fields:
            f.write(field + "\n")

    print(f"\nSaved to {output_file}")

if __name__ == "__main__":
    main()
