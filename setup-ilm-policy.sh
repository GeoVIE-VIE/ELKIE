#!/bin/bash
# setup-ilm-policy.sh
# Creates an ILM policy in Elasticsearch that automatically deletes
# suricata indices after 30 days.
#
# Usage: ./setup-ilm-policy.sh [ELASTICSEARCH_URL] [RETENTION_DAYS]
#   ELASTICSEARCH_URL  defaults to http://localhost:9200
#   RETENTION_DAYS     defaults to 30

ES_URL="${1:-http://localhost:9200}"
RETENTION_DAYS="${2:-30}"
POLICY_NAME="suricata-30d-delete"

echo "Setting up ILM policy '${POLICY_NAME}' on ${ES_URL}"
echo "Retention: ${RETENTION_DAYS} days"
echo ""

# Step 1: Create the ILM policy
echo "--- Creating ILM policy ---"
curl -s -X PUT "${ES_URL}/_ilm/policy/${POLICY_NAME}" \
  -H 'Content-Type: application/json' \
  -d "{
  \"policy\": {
    \"phases\": {
      \"hot\": {
        \"actions\": {
          \"rollover\": {
            \"max_age\": \"1d\",
            \"max_primary_shard_size\": \"50gb\"
          }
        }
      },
      \"delete\": {
        \"min_age\": \"${RETENTION_DAYS}d\",
        \"actions\": {
          \"delete\": {}
        }
      }
    }
  }
}" | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# Step 2: Apply the policy to existing suricata indices via index template
echo "--- Updating index template to use ILM policy ---"
curl -s -X PUT "${ES_URL}/_index_template/suricata" \
  -H 'Content-Type: application/json' \
  -d "{
  \"index_patterns\": [\"suricata-*\"],
  \"template\": {
    \"settings\": {
      \"index.lifecycle.name\": \"${POLICY_NAME}\",
      \"index.lifecycle.rollover_alias\": \"suricata\",
      \"index.number_of_shards\": 1,
      \"index.number_of_replicas\": 0,
      \"index.refresh_interval\": \"5s\",
      \"index.codec\": \"best_compression\"
    }
  },
  \"priority\": 200
}" | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

# Step 3: Apply the ILM policy to any existing indices that don't have it yet
echo "--- Applying ILM policy to existing suricata indices ---"
curl -s -X PUT "${ES_URL}/suricata-*/_settings" \
  -H 'Content-Type: application/json' \
  -d "{
  \"index.lifecycle.name\": \"${POLICY_NAME}\"
}" | python3 -m json.tool 2>/dev/null || echo "(raw response above)"
echo ""

echo "Done! ILM policy '${POLICY_NAME}' is now active."
echo "Indices matching 'suricata-*' will be automatically deleted after ${RETENTION_DAYS} days."
echo ""
echo "Useful commands:"
echo "  Check policy:    curl -s ${ES_URL}/_ilm/policy/${POLICY_NAME} | python3 -m json.tool"
echo "  Check status:    curl -s ${ES_URL}/suricata-*/_ilm/explain | python3 -m json.tool"
echo "  List indices:    curl -s ${ES_URL}/_cat/indices/suricata-*?v&s=index"
echo "  Delete manually: curl -X DELETE ${ES_URL}/suricata-YYYY.MM.DD"
