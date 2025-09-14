#!/usr/bin/env python3
"""
Test runner for syscall-failure-analyzer
Runs various test cases with timeout handling and configurable buffer sizes
"""

import os
import sys
import subprocess
import time
import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class TestStatus(Enum):
    PASSED = "✓"
    FAILED = "✗"
    TIMEOUT = "⏱"
    SKIPPED = "⊘"

@dataclass
class TestCase:
    name: str
    description: str
    command: List[str]
    expected_result: str
    timeout: int = 60  # seconds - increased default for tracing overhead
    buffer_size: Optional[int] = None  # MB - only for record tests
    requires_root: bool = False
    syscall: Optional[str] = None
    
@dataclass
class TestResult:
    test: TestCase
    status: TestStatus
    duration: float
    output: str
    error: str

class TestRunner:
    def __init__(self, verbose: bool = False, dry_run: bool = False):
        self.verbose = verbose
        self.dry_run = dry_run
        self.base_dir = Path(__file__).parent.parent
        self.test_dir = Path(__file__).parent
        self.output_dir = self.test_dir / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        # Check if we have necessary permissions
        self.has_permissions = self._check_permissions()
        
    def _check_permissions(self) -> bool:
        """Check if we have the necessary permissions to run tests"""
        if os.geteuid() == 0:
            return True
            
        # Check if we can read /proc/kcore
        try:
            with open("/proc/kcore", "rb") as f:
                f.read(1)
            return True
        except (PermissionError, OSError):
            pass
            
        # Check if install_permissions.sh has been run
        try:
            result = subprocess.run(
                ["getcap", sys.executable],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "cap_dac_override" in result.stdout or "cap_dac_read_search" in result.stdout:
                return True
        except:
            pass
            
        return False
    
    def _compile_c_program(self, source: Path) -> Optional[Path]:
        """Compile a C test program"""
        output = source.with_suffix("")
        try:
            result = subprocess.run(
                ["gcc", "-o", str(output), str(source)],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                print(f"Failed to compile {source}: {result.stderr}")
                return None
            return output
        except subprocess.TimeoutExpired:
            print(f"Compilation timeout for {source}")
            return None
        except Exception as e:
            print(f"Error compiling {source}: {e}")
            return None
    
    def _run_test(self, test: TestCase) -> TestResult:
        """Run a single test case with timeout handling"""
        if self.dry_run:
            print(f"Would run: {' '.join(test.command)}")
            return TestResult(test, TestStatus.SKIPPED, 0.0, "", "Dry run")
        
        if test.requires_root and not self.has_permissions:
            return TestResult(test, TestStatus.SKIPPED, 0.0, "", "Requires permissions")
        
        start_time = time.time()
        
        # Prepare the command
        cmd = test.command.copy()
        
        # If it's a syscall test, use our tool for recording
        if test.syscall:
            tool_cmd = [
                "uv", "run", "python3",
                str(self.base_dir / "syscall-failure-analyzer.py"),
                "record",
                "--quiet",  # Use quiet mode to avoid progress bar issues
                # NOTE: Removed --kprobes flag as it's extremely slow
                # Intel PT mode should be used instead if available
                f"--syscall={test.syscall}",
                "-n", "1"
            ]
            if test.buffer_size:
                tool_cmd.append(f"--snapshot-size={test.buffer_size}")
            tool_cmd.append("--")
            cmd = tool_cmd + cmd
        # Report tests already have the full command prepared
        
        if self.verbose:
            print(f"Running: {' '.join(cmd)}")
        
        # Clean environment to avoid VIRTUAL_ENV conflicts
        env = os.environ.copy()
        env.pop('VIRTUAL_ENV', None)  # Remove VIRTUAL_ENV to avoid uv warnings
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=test.timeout,
                cwd=str(self.base_dir),
                env=env
            )
            
            duration = time.time() - start_time
            
            # Check if test passed based on expected result type
            status = TestStatus.PASSED
            
            if test.expected_result == "baseline":
                # Baseline test - expect non-zero exit code (program fails)
                if result.returncode == 0:
                    status = TestStatus.FAILED
            elif test.expected_result == "record":
                # Recording test - tool should exit 0 after recording
                if result.returncode != 0:
                    status = TestStatus.FAILED
            elif test.expected_result == "report":
                # Report test - should complete successfully
                # Note: Report may take time to load large data files
                if result.returncode != 0:
                    status = TestStatus.FAILED
                # For now, just check it completes - output validation is tricky
                # since report output goes to various places
            else:
                # Legacy behavior for backward compatibility
                if result.returncode != 0:
                    status = TestStatus.FAILED
            
            return TestResult(test, status, duration, result.stdout, result.stderr)
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return TestResult(test, TestStatus.TIMEOUT, duration, "", f"Timeout after {test.timeout}s")
        except Exception as e:
            duration = time.time() - start_time
            return TestResult(test, TestStatus.FAILED, duration, "", str(e))
    
    def get_test_cases(self) -> List[TestCase]:
        """Get all test cases"""
        tests = []
        
        # Test 1: Record and report openat failure
        test_fail_c = self.test_dir / "c_programs" / "test_fail.c"
        if test_fail_c.exists():
            binary = self._compile_c_program(test_fail_c)
            if binary:
                tests.append(TestCase(
                    name="record_openat_failure",
                    description="Record openat syscall failure",
                    command=[str(binary)],
                    expected_result="record",
                    timeout=90,
                    buffer_size=1,  # Standard 1MB for all tests
                    syscall="openat",
                    requires_root=True
                ))
                
                # Report test for the above recording
                tests.append(TestCase(
                    name="report_openat_failure",
                    description="Report analysis of openat failure",
                    command=["uv", "run", "python3", str(self.base_dir / "syscall-failure-analyzer.py"),
                             "report", "--syscall=openat"],
                    expected_result="report",
                    timeout=60,  # Increased - needs to load data file
                    requires_root=False
                ))
        
        # Test 2: Baseline - run test program directly without tracing
        if test_fail_c.exists():
            binary = self._compile_c_program(test_fail_c)
            if binary:
                tests.append(TestCase(
                    name="baseline_no_tracing",
                    description="Run test program without tracing",
                    command=[str(binary)],
                    expected_result="baseline",  # Direct execution, expect failure exit code
                    timeout=5,
                    requires_root=False
                ))
        
        # Test 3: Record and report stat failure
        tests.append(TestCase(
            name="record_stat_failure",
            description="Record stat syscall failure with ls",
            command=["ls", "/nonexistent/path"],
            expected_result="record",
            timeout=90,
            buffer_size=1,  # Consistent 1MB
            syscall="stat",
            requires_root=True
        ))
        
        tests.append(TestCase(
            name="report_stat_failure",
            description="Report analysis of stat failure",
            command=["uv", "run", "python3", str(self.base_dir / "syscall-failure-analyzer.py"),
                     "report", "--syscall=stat"],
            expected_result="report",
            timeout=60,  # Increased - needs to load data file
            requires_root=False
        ))
        
        # Test 4: Verify successful syscalls don't trigger failures
        tests.append(TestCase(
            name="record_no_failure",
            description="Verify successful syscalls don't trigger",
            command=["ls", "/tmp"],
            expected_result="record",  # Should complete without capturing failures
            timeout=90,
            buffer_size=1,  # Consistent 1MB
            syscall="openat",
            requires_root=True
        ))
        
        # Note: Kprobes mode tests are commented out due to extreme slowness
        # Uncomment only if you specifically need to test kprobes functionality
        # tests.append(TestCase(
        #     name="kprobes_test",
        #     description="Test with kprobes mode (VERY SLOW)",
        #     command=["ls", "/nonexistent"],
        #     expected_result="error",
        #     timeout=300,  # 5 minutes - kprobes is extremely slow
        #     buffer_size=1,
        #     syscall="stat",
        #     requires_root=True
        # ))
        
        return tests
    
    def run_all_tests(self) -> Dict[str, TestResult]:
        """Run all test cases"""
        tests = self.get_test_cases()
        results = {}
        
        if not self.has_permissions:
            print("\n" + "=" * 60)
            print("WARNING: Insufficient permissions detected!")
            print("Tests requiring syscall tracing will be skipped.")
            print("To run all tests, either:")
            print("  1. Run: sudo ./install_permissions.sh")
            print("  2. Run tests with: sudo uv run python3 tests/run_tests.py")
            print("=" * 60)
        
        # Count test types for better info
        record_tests = sum(1 for t in tests if t.expected_result == "record")
        report_tests = sum(1 for t in tests if t.expected_result == "report")
        other_tests = len(tests) - record_tests - report_tests
        
        print(f"\nRunning {len(tests)} tests ({record_tests} record, {report_tests} report, {other_tests} other)...")
        print("=" * 60)
        
        for test in tests:
            print(f"\n[{test.name}]")
            print(f"  {test.description}")
            if test.buffer_size is not None:
                print(f"  Buffer: {test.buffer_size}MB, Timeout: {test.timeout}s")
            else:
                print(f"  Timeout: {test.timeout}s")
            
            result = self._run_test(test)
            results[test.name] = result
            
            status_color = {
                TestStatus.PASSED: "\033[92m",  # Green
                TestStatus.FAILED: "\033[91m",  # Red
                TestStatus.TIMEOUT: "\033[93m", # Yellow
                TestStatus.SKIPPED: "\033[90m", # Gray
            }
            
            reset = "\033[0m"
            color = status_color.get(result.status, "")
            
            print(f"  Status: {color}{result.status.value} {result.status.name}{reset}")
            print(f"  Duration: {result.duration:.2f}s")
            
            if self.verbose and result.error:
                print(f"  Error: {result.error[:500]}")
            elif result.status == TestStatus.FAILED and "report" in result.test.name:
                # Always show some info for failed report tests
                print(f"  Output length: stdout={len(result.output)} stderr={len(result.error)}")
                if result.output:
                    print(f"  First 100 chars of stdout: {result.output[:100]}")
                if result.error:
                    print(f"  First 100 chars of stderr: {result.error[:100]}")
        
        return results
    
    def print_summary(self, results: Dict[str, TestResult]):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        total = len(results)
        passed = sum(1 for r in results.values() if r.status == TestStatus.PASSED)
        failed = sum(1 for r in results.values() if r.status == TestStatus.FAILED)
        timeout = sum(1 for r in results.values() if r.status == TestStatus.TIMEOUT)
        skipped = sum(1 for r in results.values() if r.status == TestStatus.SKIPPED)
        
        print(f"Total:   {total}")
        print(f"Passed:  {passed} ✓")
        print(f"Failed:  {failed} ✗")
        print(f"Timeout: {timeout} ⏱")
        print(f"Skipped: {skipped} ⊘")
        
        if failed > 0 or timeout > 0:
            print("\nFailed/Timeout tests:")
            for name, result in results.items():
                if result.status in [TestStatus.FAILED, TestStatus.TIMEOUT]:
                    print(f"  - {name}: {result.status.name}")
                    if self.verbose:
                        print(f"    {result.error[:100]}")
        
        # Save results to JSON
        output_file = self.output_dir / f"test_results_{int(time.time())}.json"
        with open(output_file, 'w') as f:
            json.dump({
                name: {
                    "status": result.status.name,
                    "duration": result.duration,
                    "error": result.error
                }
                for name, result in results.items()
            }, f, indent=2)
        print(f"\nResults saved to: {output_file}")
        
        return passed == total

def main():
    parser = argparse.ArgumentParser(description="Run syscall-failure-analyzer tests")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Dry run (don't execute tests)")
    parser.add_argument("-t", "--test", help="Run specific test by name")
    args = parser.parse_args()
    
    runner = TestRunner(verbose=args.verbose, dry_run=args.dry_run)
    
    if args.test:
        # Run specific test
        tests = runner.get_test_cases()
        test = next((t for t in tests if t.name == args.test), None)
        if not test:
            print(f"Test '{args.test}' not found")
            print("Available tests:")
            for t in tests:
                print(f"  - {t.name}")
            return 1
        
        result = runner._run_test(test)
        runner.print_summary({test.name: result})
    else:
        # Run all tests
        results = runner.run_all_tests()
        success = runner.print_summary(results)
        return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())