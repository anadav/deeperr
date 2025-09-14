# Syscall Failure Analyzer Tests

This directory contains test cases for the syscall-failure-analyzer tool.

## Structure

```
tests/
├── c_programs/       # C test programs that trigger syscall failures
├── python_scripts/   # Python test scripts
├── output/          # Test output and results (gitignored)
├── run_tests.py     # Main Python test runner with timeout handling
├── quick_test.sh    # Quick bash test script
└── README.md        # This file
```

## Running Tests

### Quick Test (Bash)

For a quick smoke test with smaller buffer sizes:

```bash
./tests/quick_test.sh

# Verbose mode to see error details
./tests/quick_test.sh -v
```

### Complete Workflow Test

Test the full record->report pipeline:

```bash
./tests/test_workflow.sh
```

### Full Test Suite (Python)

For comprehensive testing with configurable options:

```bash
# Run all tests
uv run python3 tests/run_tests.py

# Verbose output
uv run python3 tests/run_tests.py -v

# Dry run (see what would be executed)
uv run python3 tests/run_tests.py -d

# Run specific test
uv run python3 tests/run_tests.py -t openat_failure_small_buffer
```

## Key Features

### Intel PT Mode (Default)
Tests use Intel PT mode by default instead of kprobes mode:
- **Intel PT**: Hardware-based tracing, fast but requires CPU support
- **Kprobes**: Software-based, works everywhere but EXTREMELY slow
- To test kprobes mode, add `--kprobes` flag manually (expect 5+ minute runtimes)

### Smaller Buffer Sizes
Tests use much smaller buffer sizes (1-2 MB) instead of the default 30MB to speed up initialization:
- 1MB for minimal/standard tests (minimum allowed)
- 2MB for tests requiring more trace data
- Note: The tool requires integer MB values (0.5 is not valid)

### Timeout Handling
All tests have configurable timeouts to prevent hanging:
- Simple tests: 5-30 seconds
- Tests with Intel PT tracing: 90 seconds (with margin for ~53s runtime)
- Report generation: 30 seconds
- Kprobes tests would need 300+ seconds (not used by default)
- Python runner uses subprocess timeout
- Bash runner uses GNU timeout command

### Test Categories

1. **Basic Failure Tests**: Simple syscall failures (openat on non-existent file)
2. **Buffer Size Tests**: Verify tool works with various buffer sizes
3. **Timeout Tests**: Ensure timeouts work properly
4. **Baseline Tests**: Run programs without tracing for comparison
5. **Report Tests**: Verify report generation and analysis works
6. **Workflow Tests**: Complete record->report pipeline validation

## Adding New Tests

### Python Test Runner

Add new test cases to `get_test_cases()` in `run_tests.py`:

```python
tests.append(TestCase(
    name="my_test",
    description="Test description",
    command=["program", "args"],
    expected_result="error",  # or "success"
    timeout=10,  # seconds
    buffer_size=1,  # MB
    syscall="openat"  # syscall to trace
))
```

### Bash Test Runner

Add new test calls in `quick_test.sh`:

```bash
run_test "test_name" \
    "command to run" \
    "failure"  # or "success" \
    10  # timeout in seconds
```

## Test Output

Test results are saved in `tests/output/`:
- `*.out` - stdout from each test
- `*.err` - stderr from each test  
- `test_results_*.json` - JSON summary from Python runner

## Prerequisites

- Tool must be installed with `uv sync`
- For unprivileged testing: run `sudo ./install_permissions.sh` first
- GCC for compiling C test programs
- GNU timeout command (usually pre-installed)

## Troubleshooting

### Tests timing out
- Reduce buffer size further
- Increase timeout values
- Check system load

### Permission errors
- Run `sudo ./install_permissions.sh` 
- Or run tests with sudo: `sudo uv run python3 tests/run_tests.py`

### Compilation errors
- Ensure gcc is installed: `sudo apt install build-essential`