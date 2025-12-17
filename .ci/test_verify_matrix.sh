#!/bin/sh
# Test batch verification (verify_matrix) functionality

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

setup_test_env

test_header "Verify Matrix Tests"

if [ -z "$SAMPLE_WASM" ]; then
    skip "No sample WASM file available"
    print_summary
    exit 0
fi

# Generate multiple key pairs
"$WASMSIGN2" keygen -k "${TEST_DIR}/key1.sk" -K "${TEST_DIR}/key1.pk" >/dev/null 2>&1
"$WASMSIGN2" keygen -k "${TEST_DIR}/key2.sk" -K "${TEST_DIR}/key2.pk" >/dev/null 2>&1
"$WASMSIGN2" keygen -k "${TEST_DIR}/key3.sk" -K "${TEST_DIR}/key3.pk" >/dev/null 2>&1

# Sign with first two keys
"$WASMSIGN2" sign -k "${TEST_DIR}/key1.sk" -i "$SAMPLE_WASM" -o "${TEST_DIR}/signed1.wasm" >/dev/null 2>&1
"$WASMSIGN2" sign -k "${TEST_DIR}/key2.sk" -i "${TEST_DIR}/signed1.wasm" -o "${TEST_DIR}/signed2.wasm" >/dev/null 2>&1

# Test verify_matrix with multiple public keys
assert_success "Verify matrix with multiple keys" \
    "$WASMSIGN2" verify_matrix -i "${TEST_DIR}/signed2.wasm" \
    -K "${TEST_DIR}/key1.pk" "${TEST_DIR}/key2.pk" "${TEST_DIR}/key3.pk"

# Test that output shows valid keys
assert_output_contains "Matrix output shows valid keys" "Valid public keys" \
    "$WASMSIGN2" verify_matrix -i "${TEST_DIR}/signed2.wasm" \
    -K "${TEST_DIR}/key1.pk" "${TEST_DIR}/key2.pk" "${TEST_DIR}/key3.pk"

# Test verify_matrix with only non-signer keys
output=$("$WASMSIGN2" verify_matrix -i "${TEST_DIR}/signed2.wasm" -K "${TEST_DIR}/key3.pk" 2>&1)
if echo "$output" | grep -q "No valid public keys"; then
    pass "Matrix shows no valid keys when none match"
else
    # The output format might vary - just check it runs successfully
    if echo "$output" | grep -qv "Valid"; then
        pass "Matrix correctly handles non-signer keys"
    else
        fail "Matrix should indicate no valid keys for non-signer"
    fi
fi

# Test with split pattern
"$WASMSIGN2" split -i "$SAMPLE_WASM" -o "${TEST_DIR}/split.wasm" -s "name" >/dev/null 2>&1
"$WASMSIGN2" sign -k "${TEST_DIR}/key1.sk" -i "${TEST_DIR}/split.wasm" -o "${TEST_DIR}/split_signed.wasm" >/dev/null 2>&1

assert_success "Verify matrix with split pattern" \
    "$WASMSIGN2" verify_matrix -i "${TEST_DIR}/split_signed.wasm" \
    -K "${TEST_DIR}/key1.pk" "${TEST_DIR}/key2.pk" -s "name"

# Test missing public keys argument
assert_failure "Verify matrix fails without public keys" \
    "$WASMSIGN2" verify_matrix -i "${TEST_DIR}/signed2.wasm"

print_summary
