#!/bin/sh
# Test multiple signature functionality

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

setup_test_env

test_header "Multi-Signature Tests"

if [ -z "$SAMPLE_WASM" ]; then
    skip "No sample WASM file available"
    print_summary
    exit 0
fi

# Generate multiple key pairs
"$WASMSIGN2" keygen -k "${TEST_DIR}/key1.sk" -K "${TEST_DIR}/key1.pk" >/dev/null 2>&1
"$WASMSIGN2" keygen -k "${TEST_DIR}/key2.sk" -K "${TEST_DIR}/key2.pk" >/dev/null 2>&1
"$WASMSIGN2" keygen -k "${TEST_DIR}/key3.sk" -K "${TEST_DIR}/key3.pk" >/dev/null 2>&1

# Sign with first key
assert_success "Sign with first key" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/key1.sk" -i "$SAMPLE_WASM" -o "${TEST_DIR}/signed1.wasm"

# Add second signature
assert_success "Add second signature" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/key2.sk" -i "${TEST_DIR}/signed1.wasm" -o "${TEST_DIR}/signed2.wasm"

# Verify with first key
assert_success "Verify multi-signed module with first key" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed2.wasm" -K "${TEST_DIR}/key1.pk"

# Verify with second key
assert_success "Verify multi-signed module with second key" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed2.wasm" -K "${TEST_DIR}/key2.pk"

# Verification should fail with third key (not a signer)
assert_failure "Verify fails with non-signer key" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed2.wasm" -K "${TEST_DIR}/key3.pk"

# Add third signature
assert_success "Add third signature" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/key3.sk" -i "${TEST_DIR}/signed2.wasm" -o "${TEST_DIR}/signed3.wasm"

# All three keys should now verify
assert_success "Verify triple-signed with key1" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed3.wasm" -K "${TEST_DIR}/key1.pk"

assert_success "Verify triple-signed with key2" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed3.wasm" -K "${TEST_DIR}/key2.pk"

assert_success "Verify triple-signed with key3" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed3.wasm" -K "${TEST_DIR}/key3.pk"

# File sizes should increase with each signature
size1=$(wc -c < "${TEST_DIR}/signed1.wasm" | tr -d ' ')
size2=$(wc -c < "${TEST_DIR}/signed2.wasm" | tr -d ' ')
size3=$(wc -c < "${TEST_DIR}/signed3.wasm" | tr -d ' ')

if [ "$size2" -gt "$size1" ] && [ "$size3" -gt "$size2" ]; then
    pass "File size increases with each signature"
else
    fail "File size should increase with each signature"
fi

print_summary
