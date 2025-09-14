#!/usr/bin/env python3
import subprocess
import time

# Clear ftrace
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo > /sys/kernel/debug/tracing/trace'", shell=True)
subprocess.run("sudo bash -c 'echo > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 102400 > /sys/kernel/debug/tracing/buffer_size_kb'", shell=True)

# Enable specific syscall events
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/enable'", shell=True)

# Set trigger on sys_exit_openat for failures
subprocess.run("sudo bash -c 'echo \"snapshot if ret<0\" > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/trigger'", shell=True)

subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Run a command with failing openat
subprocess.run("./test_fail 2>/dev/null", shell=True)

# Stop tracing
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Check snapshot
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/snapshot | grep -E 'sys_(enter|exit)_openat' | head -20", shell=True, capture_output=True, text=True)
print("Snapshot output (syscall events):")
print(result.stdout)

# Check if there are any lines in snapshot
result = subprocess.run("sudo wc -l /sys/kernel/debug/tracing/snapshot", shell=True, capture_output=True, text=True)
print(f"\nTotal lines in snapshot: {result.stdout.strip()}")

# Cleanup
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo \"!snapshot\" > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/trigger'", shell=True)
