#!/bin/sh
# Main test runner for wasmsign2 functional tests

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Colors for output
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

echo "${BLUE}========================================${NC}"
echo "${BLUE}  wasmsign2 Functional Test Suite${NC}"
echo "${BLUE}========================================${NC}"

# Build the project first
echo "\n${YELLOW}Building project...${NC}"
cd "$PROJECT_ROOT"
if cargo build --release >/dev/null 2>&1; then
    echo "${GREEN}Build successful${NC}"
else
    echo "${RED}Build failed${NC}"
    exit 1
fi

# Track overall results
TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

run_test_suite() {
    suite_name="$1"
    script_path="$2"

    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    echo "\n${BLUE}Running: $suite_name${NC}"
    echo "----------------------------------------"

    if sh "$script_path"; then
        PASSED_SUITES=$((PASSED_SUITES + 1))
        echo "${GREEN}$suite_name: PASSED${NC}"
    else
        FAILED_SUITES=$((FAILED_SUITES + 1))
        echo "${RED}$suite_name: FAILED${NC}"
    fi
}

# Run all test suites
run_test_suite "Key Generation Tests" "$SCRIPT_DIR/test_keygen.sh"
run_test_suite "Sign/Verify Tests" "$SCRIPT_DIR/test_sign_verify.sh"
run_test_suite "Multi-Signature Tests" "$SCRIPT_DIR/test_multi_sign.sh"
run_test_suite "Split Tests" "$SCRIPT_DIR/test_split.sh"
run_test_suite "Detach/Attach Tests" "$SCRIPT_DIR/test_detach_attach.sh"
run_test_suite "Verify Matrix Tests" "$SCRIPT_DIR/test_verify_matrix.sh"
run_test_suite "Show Command Tests" "$SCRIPT_DIR/test_show.sh"

# Print overall summary
echo "\n${BLUE}========================================${NC}"
echo "${BLUE}  Overall Summary${NC}"
echo "${BLUE}========================================${NC}"
echo "${GREEN}Passed Suites${NC}: $PASSED_SUITES"
echo "${RED}Failed Suites${NC}: $FAILED_SUITES"
echo "Total Suites:  $TOTAL_SUITES"

if [ "$FAILED_SUITES" -gt 0 ]; then
    echo "\n${RED}Some tests failed!${NC}"
    exit 1
else
    echo "\n${GREEN}All tests passed!${NC}"
    exit 0
fi
