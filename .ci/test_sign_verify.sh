#!/bin/sh
# Test basic signing and verification functionality

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

setup_test_env

test_header "Sign and Verify Tests"

if [ -z "$SAMPLE_WASM" ]; then
    skip "No sample WASM file available"
    print_summary
    exit 0
fi

# Generate a key pair for testing
"$WASMSIGN2" keygen -k "${TEST_DIR}/secret.key" -K "${TEST_DIR}/public.key" >/dev/null 2>&1

# Test signing a module
assert_success "Sign WASM module" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -i "$SAMPLE_WASM" -o "${TEST_DIR}/signed.wasm"

assert_file_exists "${TEST_DIR}/signed.wasm"

# Signed file should be larger (includes signature section)
orig_size=$(wc -c < "$SAMPLE_WASM" | tr -d ' ')
signed_size=$(wc -c < "${TEST_DIR}/signed.wasm" | tr -d ' ')

if [ "$signed_size" -gt "$orig_size" ]; then
    pass "Signed file is larger than original"
else
    fail "Signed file should be larger than original"
fi

# Test verifying a signed module
assert_success "Verify signed module with correct key" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed.wasm" -K "${TEST_DIR}/public.key"

# Test verification with wrong key fails
"$WASMSIGN2" keygen -k "${TEST_DIR}/wrong_secret.key" -K "${TEST_DIR}/wrong_public.key" >/dev/null 2>&1

assert_failure "Verify fails with wrong key" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed.wasm" -K "${TEST_DIR}/wrong_public.key"

# Test verification of unsigned module fails
assert_failure "Verify fails on unsigned module" \
    "$WASMSIGN2" verify -i "$SAMPLE_WASM" -K "${TEST_DIR}/public.key"

# Test signing with key ID (public key provided)
assert_success "Sign with key ID" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -K "${TEST_DIR}/public.key" \
    -i "$SAMPLE_WASM" -o "${TEST_DIR}/signed_with_id.wasm"

assert_success "Verify module signed with key ID" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/signed_with_id.wasm" -K "${TEST_DIR}/public.key"

# Test verbose output
assert_output_contains "Verbose sign shows structure" "signature" \
    "$WASMSIGN2" -v sign -k "${TEST_DIR}/secret.key" -i "$SAMPLE_WASM" -o "${TEST_DIR}/verbose_signed.wasm"

# Test missing input file
assert_failure "Fail with missing input file" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -i "${TEST_DIR}/nonexistent.wasm" -o "${TEST_DIR}/out.wasm"

# Test missing secret key
assert_failure "Fail with missing secret key file" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/nonexistent.key" -i "$SAMPLE_WASM" -o "${TEST_DIR}/out.wasm"

print_summary
