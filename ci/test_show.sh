#!/bin/sh
# Test show command functionality

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

setup_test_env

test_header "Show Command Tests"

if [ -z "$SAMPLE_WASM" ]; then
    skip "No sample WASM file available"
    print_summary
    exit 0
fi

# Generate keys and create signed module
"$WASMSIGN2" keygen -k "${TEST_DIR}/secret.key" -K "${TEST_DIR}/public.key" >/dev/null 2>&1
"$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -i "$SAMPLE_WASM" -o "${TEST_DIR}/signed.wasm" >/dev/null 2>&1

# Test basic show command
assert_success "Show unsigned module structure" \
    "$WASMSIGN2" show -i "$SAMPLE_WASM"

assert_success "Show signed module structure" \
    "$WASMSIGN2" show -i "${TEST_DIR}/signed.wasm"

# Test verbose output
assert_success "Show with verbose flag" \
    "$WASMSIGN2" -v show -i "$SAMPLE_WASM"

# Signed module should show signature section
assert_output_contains "Show signed module includes signature section" "signature" \
    "$WASMSIGN2" show -i "${TEST_DIR}/signed.wasm"

# Test show on split module
"$WASMSIGN2" split -i "$SAMPLE_WASM" -o "${TEST_DIR}/split.wasm" -s "name" >/dev/null 2>&1

assert_success "Show split module structure" \
    "$WASMSIGN2" show -i "${TEST_DIR}/split.wasm"

# Test missing input file
assert_failure "Show fails with missing input file" \
    "$WASMSIGN2" show -i "${TEST_DIR}/nonexistent.wasm"

# Test with invalid WASM file
echo "not a wasm file" > "${TEST_DIR}/invalid.wasm"
assert_failure "Show fails with invalid WASM file" \
    "$WASMSIGN2" show -i "${TEST_DIR}/invalid.wasm"

print_summary
