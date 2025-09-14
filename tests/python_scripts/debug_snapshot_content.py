#!/usr/bin/env python3
import subprocess
import sys

# Setup and run test
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo > /sys/kernel/debug/tracing/trace'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 30720 > /sys/kernel/debug/tracing/buffer_size_kb'", shell=True)

# Enable raw syscall events with filter
subprocess.run("sudo bash -c 'echo \"id==257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/filter'", shell=True)
subprocess.run("sudo bash -c 'echo \"ret<0 && id==257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/filter'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable'", shell=True)

# Start tracing
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Run failing syscall
subprocess.run("./test_fail 2>/dev/null", shell=True)

# Trigger snapshot manually
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/snapshot'", shell=True)

# Stop tracing
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Check what's in the snapshot
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/snapshot | grep -E 'sys_enter|sys_exit' | head -10", 
                       shell=True, capture_output=True, text=True)
print("Syscall events in snapshot:")
print(result.stdout if result.stdout else "NO SYSCALL EVENTS FOUND")

# Check main trace buffer
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/trace | grep -E 'sys_enter|sys_exit' | head -10", 
                       shell=True, capture_output=True, text=True)
print("\nSyscall events in main trace buffer:")
print(result.stdout if result.stdout else "NO SYSCALL EVENTS FOUND")

# Cleanup
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable'", shell=True)
