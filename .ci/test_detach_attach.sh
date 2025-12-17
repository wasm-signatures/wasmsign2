#!/bin/sh
# Test detached signature functionality

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

setup_test_env

test_header "Detach and Attach Signature Tests"

if [ -z "$SAMPLE_WASM" ]; then
    skip "No sample WASM file available"
    print_summary
    exit 0
fi

# Generate keys
"$WASMSIGN2" keygen -k "${TEST_DIR}/secret.key" -K "${TEST_DIR}/public.key" >/dev/null 2>&1

# Sign the module first
"$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -i "$SAMPLE_WASM" -o "${TEST_DIR}/signed.wasm" >/dev/null 2>&1

# Test detaching signature
assert_success "Detach signature from module" \
    "$WASMSIGN2" detach -i "${TEST_DIR}/signed.wasm" -o "${TEST_DIR}/unsigned.wasm" -S "${TEST_DIR}/signature.bin"

assert_file_exists "${TEST_DIR}/unsigned.wasm"
assert_file_exists "${TEST_DIR}/signature.bin"

# Unsigned module should be smaller than signed module
signed_size=$(wc -c < "${TEST_DIR}/signed.wasm" | tr -d ' ')
unsigned_size=$(wc -c < "${TEST_DIR}/unsigned.wasm" | tr -d ' ')

if [ "$unsigned_size" -lt "$signed_size" ]; then
    pass "Detached module is smaller than signed module"
else
    fail "Detached module should be smaller than signed module"
fi

# Signature file should have content
sig_size=$(wc -c < "${TEST_DIR}/signature.bin" | tr -d ' ')
if [ "$sig_size" -gt 0 ]; then
    pass "Signature file has content"
else
    fail "Signature file is empty"
fi

# Verification with detached signature should work
assert_success "Verify with detached signature" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/unsigned.wasm" -K "${TEST_DIR}/public.key" -S "${TEST_DIR}/signature.bin"

# Verification without detached signature should fail (module is unsigned)
assert_failure "Verify unsigned module without detached sig fails" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/unsigned.wasm" -K "${TEST_DIR}/public.key"

# Test attaching signature back
assert_success "Attach signature to module" \
    "$WASMSIGN2" attach -i "${TEST_DIR}/unsigned.wasm" -o "${TEST_DIR}/reattached.wasm" -S "${TEST_DIR}/signature.bin"

assert_file_exists "${TEST_DIR}/reattached.wasm"

# Reattached module should verify without detached signature
assert_success "Verify reattached module" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/reattached.wasm" -K "${TEST_DIR}/public.key"

# Reattached and original signed should be similar in size
reattached_size=$(wc -c < "${TEST_DIR}/reattached.wasm" | tr -d ' ')

if [ "$reattached_size" -eq "$signed_size" ]; then
    pass "Reattached module same size as original signed"
else
    # They might differ slightly due to section ordering
    diff=$((reattached_size - signed_size))
    if [ "$diff" -lt 0 ]; then
        diff=$((diff * -1))
    fi
    if [ "$diff" -lt 100 ]; then
        pass "Reattached module approximately same size as original signed (diff: $diff bytes)"
    else
        fail "Reattached module significantly different size from original signed"
    fi
fi

# Test signing directly to detached signature
assert_success "Sign with detached signature output" \
    "$WASMSIGN2" sign -k "${TEST_DIR}/secret.key" -i "$SAMPLE_WASM" \
    -o "${TEST_DIR}/module_for_detached.wasm" -S "${TEST_DIR}/direct_sig.bin"

assert_file_exists "${TEST_DIR}/direct_sig.bin"

# Verify the direct detached signature
assert_success "Verify directly created detached signature" \
    "$WASMSIGN2" verify -i "${TEST_DIR}/module_for_detached.wasm" -K "${TEST_DIR}/public.key" -S "${TEST_DIR}/direct_sig.bin"

# Test missing signature file in detach
assert_failure "Detach fails without signature file arg" \
    "$WASMSIGN2" detach -i "${TEST_DIR}/signed.wasm" -o "${TEST_DIR}/out.wasm"

# Test missing signature file in attach
assert_failure "Attach fails without signature file arg" \
    "$WASMSIGN2" attach -i "${TEST_DIR}/unsigned.wasm" -o "${TEST_DIR}/out.wasm"

print_summary
