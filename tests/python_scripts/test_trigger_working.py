#!/usr/bin/env python3
import subprocess
import time

# Clean and setup
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 2 > /sys/kernel/debug/tracing/snapshot'", shell=True)  # Clear it

# Set trigger 
subprocess.run("sudo bash -c 'echo \"snapshot:1 if ret < 0 && id == 257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger'", shell=True)

# Enable the event
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable'", shell=True)
subprocess.run("sudo bash -c 'echo \"id==257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/filter'", shell=True)

# Enable tracing
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Run failing syscall
print("Running test_fail...")
subprocess.run("./test_fail 2>/dev/null", shell=True)

# Give it a moment
time.sleep(0.1)

# Disable tracing
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Check trigger status
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger", 
                       shell=True, capture_output=True, text=True)
print(f"Trigger after test: {result.stdout.strip()}")

# Check snapshot
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/snapshot | grep -c sys_", 
                       shell=True, capture_output=True, text=True)
print(f"Syscall events in snapshot: {result.stdout.strip()}")

# Check if we have both enter and exit
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/snapshot | grep -E 'sys_enter.*NR 257|sys_exit.*NR 257' | head -5", 
                       shell=True, capture_output=True, text=True)
print(f"Sample events:\n{result.stdout}")

# Cleanup
subprocess.run("sudo bash -c 'echo \"!*\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger'", shell=True, stderr=subprocess.DEVNULL)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
