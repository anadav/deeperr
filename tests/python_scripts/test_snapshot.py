#!/usr/bin/env python3
import subprocess
import time

# Clear and setup ftrace
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo > /sys/kernel/debug/tracing/trace'", shell=True)
subprocess.run("sudo bash -c 'echo 102400 > /sys/kernel/debug/tracing/buffer_size_kb'", shell=True)

# Enable specific syscall events
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Run a command that will fail
subprocess.run("ls /nonexistent 2>/dev/null", shell=True)

# Stop tracing
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Get trace
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/trace | grep -E 'sys_(enter|exit)_openat' | head -20", shell=True, capture_output=True, text=True)
print("Trace output:")
print(result.stdout)

# Cleanup
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/enable'", shell=True)
