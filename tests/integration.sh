#!/bin/bash
# build first
cargo build --bin mock_server --bin ferret
# start mock server in background, capture its output

cargo run --bin mock_server > /tmp/mock_url.txt & MOCK_PID=$!
# wait for server to start and grab the URL
sleep 1
BASE_URL=$(cat /tmp/mock_url.txt)
# if that doesn't work, just hardcode or read from a file
# the mock server prints the URL, so we can also do:
# BASE_URL="http://127.0.0.1:5000"  # httpmock default
echo "Mock server running at: $BASE_URL"
echo ""
failed=0
# "args|expected"
test_cases=(
    # valid cases
    "${BASE_URL}/testget|get successful"
    "${BASE_URL}/testpost -d data|post successful"
    "${BASE_URL}/testget -X get|get successful"
    "${BASE_URL}/testpost -X post -d data|post successful"
    # error cases
    "${BASE_URL}/testpost -X post|ERRO"
    "https://invalid.com|ERRO"
)
for tc in "${test_cases[@]}"; do
    args="${tc%|*}"
    expected="${tc#*|}"
    
    echo "=== Test: ferret $args ==="
    output=$(cargo run --bin ferret -- $args 2>&1)
    
    if [[ "${output,,}" == *"${expected,,}"* ]]; then  # ,, = lowercase
        echo "✓ PASSED"
    else
        echo "✗ FAILED"
        echo "  Expected: $expected"
        echo "  Got: $output"
        ((failed++))
    fi
    echo ""
done


echo ""
# cleanup
kill $MOCK_PID 2>/dev/null
echo "=== $failed failed ==="
exit $failed
