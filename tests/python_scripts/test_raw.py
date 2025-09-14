#!/usr/bin/env python3
import subprocess
import time

# Clear and setup ftrace
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo > /sys/kernel/debug/tracing/trace'", shell=True)

# Enable raw syscall events
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Run a command
subprocess.run("ls /nonexistent 2>/dev/null", shell=True)

# Stop tracing
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Get trace
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/trace | grep -E 'sys_(enter|exit)' | head -10", shell=True, capture_output=True, text=True)
print("Raw syscall trace output:")
print(result.stdout)

# Cleanup
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable'", shell=True)
