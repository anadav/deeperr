#!/usr/bin/env python3
import subprocess
import time

# Clear ftrace
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo > /sys/kernel/debug/tracing/trace'", shell=True)
subprocess.run("sudo bash -c 'echo > /sys/kernel/debug/tracing/snapshot'", shell=True)

# Enable specific syscall events
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/enable'", shell=True)

subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Run a command with failing openat
subprocess.run("./test_fail 2>/dev/null", shell=True)

# Stop tracing
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Manually trigger snapshot
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/snapshot'", shell=True)

# Check snapshot
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/snapshot | grep -E 'sys_(enter|exit)_openat' | head -10", shell=True, capture_output=True, text=True)
print("Snapshot output (syscall events):")
print(result.stdout)

# Check regular trace buffer
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/trace | grep -E 'sys_(enter|exit)_openat' | head -10", shell=True, capture_output=True, text=True)
print("\nRegular trace output (syscall events):")
print(result.stdout)

# Cleanup
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/enable'", shell=True)
