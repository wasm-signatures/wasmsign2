#!/bin/sh
# Common test utilities for wasmsign2 functional tests

# Colors for output (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Get script directory
get_script_dir() {
    cd "$(dirname "$0")" && pwd
}

# Get project root directory
get_project_root() {
    cd "$(get_script_dir)/.." && pwd
}

# Print test header
test_header() {
    printf "\n${YELLOW}=== %s ===${NC}\n" "$1"
}

# Print success message
pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    printf "${GREEN}PASS${NC}: %s\n" "$1"
}

# Print failure message
fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf "${RED}FAIL${NC}: %s\n" "$1"
}

# Print skip message
skip() {
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    printf "${YELLOW}SKIP${NC}: %s\n" "$1"
}

# Assert command succeeds
assert_success() {
    msg="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$msg"
        return 0
    else
        fail "$msg"
        return 1
    fi
}

# Assert command fails
assert_failure() {
    msg="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$msg (expected failure but succeeded)"
        return 1
    else
        pass "$msg"
        return 0
    fi
}

# Assert file exists
assert_file_exists() {
    if [ -f "$1" ]; then
        pass "File exists: $1"
        return 0
    else
        fail "File does not exist: $1"
        return 1
    fi
}

# Assert file does not exist
assert_file_not_exists() {
    if [ ! -f "$1" ]; then
        pass "File does not exist: $1"
        return 0
    else
        fail "File exists but should not: $1"
        return 1
    fi
}

# Assert files are identical
assert_files_equal() {
    if cmp -s "$1" "$2"; then
        pass "Files are equal: $1 == $2"
        return 0
    else
        fail "Files differ: $1 != $2"
        return 1
    fi
}

# Assert files are different
assert_files_differ() {
    if cmp -s "$1" "$2"; then
        fail "Files are equal but should differ: $1 == $2"
        return 1
    else
        pass "Files differ: $1 != $2"
        return 0
    fi
}

# Assert output contains string
assert_output_contains() {
    msg="$1"
    expected="$2"
    shift 2
    output=$("$@" 2>&1)
    if echo "$output" | grep -q "$expected"; then
        pass "$msg"
        return 0
    else
        fail "$msg (output did not contain: $expected)"
        return 1
    fi
}

# Setup test environment
setup_test_env() {
    PROJECT_ROOT=$(get_project_root)
    WASMSIGN2="${PROJECT_ROOT}/target/release/wasmsign2"

    if [ ! -x "$WASMSIGN2" ]; then
        # Try debug build
        WASMSIGN2="${PROJECT_ROOT}/target/debug/wasmsign2"
    fi

    if [ ! -x "$WASMSIGN2" ]; then
        printf "${RED}ERROR${NC}: wasmsign2 binary not found. Run 'cargo build --release' first.\n"
        exit 1
    fi

    # Create temporary directory for test files
    TEST_DIR=$(mktemp -d)
    trap 'rm -rf "$TEST_DIR"' EXIT

    # Copy sample WASM file if available
    if [ -f "${PROJECT_ROOT}/z.wasm" ]; then
        cp "${PROJECT_ROOT}/z.wasm" "${TEST_DIR}/test.wasm"
        SAMPLE_WASM="${TEST_DIR}/test.wasm"
    else
        SAMPLE_WASM=""
    fi

    export WASMSIGN2 TEST_DIR SAMPLE_WASM PROJECT_ROOT
}

# Create a minimal valid WASM module for testing
create_minimal_wasm() {
    output_file="$1"
    # Minimal valid WASM: magic number + version
    # \x00asm = magic number, \x01\x00\x00\x00 = version 1
    printf '\x00asm\x01\x00\x00\x00' > "$output_file"
}

# Print test summary
print_summary() {
    total=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))
    printf "\n${YELLOW}=== Test Summary ===${NC}\n"
    printf "${GREEN}Passed${NC}:  %d\n" "$TESTS_PASSED"
    printf "${RED}Failed${NC}:  %d\n" "$TESTS_FAILED"
    printf "${YELLOW}Skipped${NC}: %d\n" "$TESTS_SKIPPED"
    printf "Total:   %d\n" "$total"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        return 1
    fi
    return 0
}
