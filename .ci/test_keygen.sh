#!/bin/sh
# Test key generation functionality

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

setup_test_env

test_header "Key Generation Tests"

# Test basic key generation
assert_success "Generate key pair" \
    "$WASMSIGN2" keygen -k "${TEST_DIR}/secret.key" -K "${TEST_DIR}/public.key"

assert_file_exists "${TEST_DIR}/secret.key"
assert_file_exists "${TEST_DIR}/public.key"

# Check key file sizes (Ed25519 keys have specific sizes)
sk_size=$(wc -c < "${TEST_DIR}/secret.key" | tr -d ' ')
pk_size=$(wc -c < "${TEST_DIR}/public.key" | tr -d ' ')

if [ "$sk_size" -eq 65 ]; then
    pass "Secret key has correct size (65 bytes)"
else
    fail "Secret key has incorrect size: $sk_size (expected 65)"
fi

if [ "$pk_size" -eq 33 ]; then
    pass "Public key has correct size (33 bytes)"
else
    fail "Public key has incorrect size: $pk_size (expected 33)"
fi

# Test generating multiple key pairs
assert_success "Generate second key pair" \
    "$WASMSIGN2" keygen -k "${TEST_DIR}/secret2.key" -K "${TEST_DIR}/public2.key"

# Keys should be different
assert_files_differ "${TEST_DIR}/secret.key" "${TEST_DIR}/secret2.key"
assert_files_differ "${TEST_DIR}/public.key" "${TEST_DIR}/public2.key"

# Test overwriting existing keys
assert_success "Overwrite existing key pair" \
    "$WASMSIGN2" keygen -k "${TEST_DIR}/secret.key" -K "${TEST_DIR}/public.key"

# Test missing arguments
assert_failure "Fail with missing secret key arg" \
    "$WASMSIGN2" keygen -K "${TEST_DIR}/public3.key"

assert_failure "Fail with missing public key arg" \
    "$WASMSIGN2" keygen -k "${TEST_DIR}/secret3.key"

print_summary
