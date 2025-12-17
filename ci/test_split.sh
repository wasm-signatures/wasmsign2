#!/bin/sh
# Test cutting points (split) and partial verification

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

setup_test_env

test_header "Split and Partial Verification Tests"

if [ -z "$SAMPLE_WASM" ]; then
    skip "No sample WASM file available"
    print_summary
    exit 0
fi

# Generate keys
"$WASMSIGN2" keygen -k "${TEST_DIR}/secret.key" -K "${TEST_DIR}/public.key" >/dev/null 2>&1

# Test basic split
assert_success "Add cutting point" \
    "$WASMSIGN2" split -i "$SAMPLE_WASM" -o "${TEST_DIR}/split.wasm" -s "name"

assert_file_exists "${TEST_DIR}/split.wasm"

# Split file may be slightly larger due to cutting point markers
assert_files_differ "$SAMPLE_WASM" "${TEST_DIR}/split.wasm"

# Test split with regex pattern
assert_success "Add cutting point with regex" \
    "$WASMSIGN2" split -i "$SAMPLE_WASM" -o "${TEST_DIR}/split_regex.wasm" -s '^[.]debug'

# Sign the split module
assert_success "Sign split module" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -i "${TEST_DIR}/split.wasm" -o "${TEST_DIR}/split_signed.wasm"

# Verify full module
assert_success "Verify full split module" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/split_signed.wasm" -K "${TEST_DIR}/public.key"

# Verify with partial split pattern
assert_success "Verify with split pattern 'name'" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/split_signed.wasm" -K "${TEST_DIR}/public.key" -s "name"

# Test multiple cutting points
assert_success "Add multiple cutting points" \
    "$WASMSIGN2" split -i "$SAMPLE_WASM" -o "${TEST_DIR}/multi_split.wasm" -s "debug|name"

assert_success "Sign multi-split module" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -i "${TEST_DIR}/multi_split.wasm" -o "${TEST_DIR}/multi_split_signed.wasm"

assert_success "Verify multi-split with pattern" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/multi_split_signed.wasm" -K "${TEST_DIR}/public.key" -s "debug|name"

# Test chained splits
assert_success "First split" \
    "$WASMSIGN2" split -i "$SAMPLE_WASM" -o "${TEST_DIR}/chain1.wasm" -s "first_pattern"

assert_success "Second split on already-split module" \
    "$WASMSIGN2" split -i "${TEST_DIR}/chain1.wasm" -o "${TEST_DIR}/chain2.wasm" -s "second_pattern"

# Show command should work on split modules
assert_success "Show split module structure" \
    "$WASMSIGN2" show -i "${TEST_DIR}/split.wasm"

print_summary
