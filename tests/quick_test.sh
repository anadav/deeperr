#!/bin/bash
# Quick test script for syscall-failure-analyzer
# Tests with smaller buffer sizes and timeouts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$SCRIPT_DIR/output"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "================================"
echo "Syscall Failure Analyzer Tests"
echo "================================"

# Function to run a test with timeout
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected="$3"
    local timeout_val="${4:-10}"  # Default 10 seconds
    
    echo -n "Running $test_name... "
    
    # Run with timeout
    if timeout "$timeout_val" bash -c "$test_cmd" > "$OUTPUT_DIR/${test_name}.out" 2> "$OUTPUT_DIR/${test_name}.err"; then
        if [ "$expected" = "success" ]; then
            echo -e "${GREEN}PASSED${NC}"
            return 0
        else
            echo -e "${RED}FAILED${NC} (expected failure but succeeded)"
            return 1
        fi
    else
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo -e "${YELLOW}TIMEOUT${NC} (after ${timeout_val}s)"
            return 1
        elif [ "$expected" = "failure" ]; then
            echo -e "${GREEN}PASSED${NC}"
            return 0
        else
            echo -e "${RED}FAILED${NC} (expected success but failed)"
            return 1
        fi
    fi
}

# Compile test C program
echo "Compiling test programs..."
if [ -f "$SCRIPT_DIR/c_programs/test_fail.c" ]; then
    gcc -o "$SCRIPT_DIR/c_programs/test_fail" "$SCRIPT_DIR/c_programs/test_fail.c" 2>/dev/null || true
fi

echo ""
echo "Running tests with small buffer sizes..."
echo "----------------------------------------"

# Test 1: Basic failure with 1MB buffer (Intel PT mode)
run_test "openat_1mb" \
    "cd $BASE_DIR && uv run python3 ./syscall-failure-analyzer.py record --quiet --syscall=openat -n 1 --snapshot-size=1 -- $SCRIPT_DIR/c_programs/test_fail" \
    "failure" \
    60

# Test 2: Small buffer (1MB min) - Intel PT mode
run_test "openat_1mb_min" \
    "cd $BASE_DIR && uv run python3 ./syscall-failure-analyzer.py record --quiet --syscall=openat -n 1 --snapshot-size=1 -- $SCRIPT_DIR/c_programs/test_fail" \
    "failure" \
    30

# Test 3: Test with ls and small buffer - Intel PT mode
run_test "ls_nonexistent_1mb" \
    "cd $BASE_DIR && uv run python3 ./syscall-failure-analyzer.py record --quiet --syscall=stat -n 1 --snapshot-size=1 -- ls /nonexistent" \
    "failure" \
    60

# Test 4: Baseline - run without tracing
run_test "baseline_no_trace" \
    "$SCRIPT_DIR/c_programs/test_fail" \
    "failure" \
    5

# Test 5: Test report generation
run_test "report_generation" \
    "cd $BASE_DIR && uv run python3 ./syscall-failure-analyzer.py report --syscall=openat" \
    "success" \
    30

echo ""
echo "================================"
echo "Test Results Summary"
echo "================================"

# Count results
total_tests=5
passed=$(grep -c "PASSED" "$OUTPUT_DIR"/*.out 2>/dev/null || echo 0)
failed=$(grep -c "FAILED" "$OUTPUT_DIR"/*.err 2>/dev/null || echo 0)

echo "Total tests: $total_tests"
echo -e "Passed: ${GREEN}$passed${NC}"
echo -e "Failed: ${RED}$failed${NC}"

# Show any errors if verbose mode
if [ "$1" = "-v" ]; then
    echo ""
    echo "Error details:"
    for err_file in "$OUTPUT_DIR"/*.err; do
        if [ -s "$err_file" ]; then
            echo "--- $(basename "$err_file" .err) ---"
            head -n 10 "$err_file"
        fi
    done
fi

echo ""
echo "Output saved to: $OUTPUT_DIR"