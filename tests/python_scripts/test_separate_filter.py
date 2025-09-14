#!/usr/bin/env python3
import subprocess
import time

# Clean and setup
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 2 > /sys/kernel/debug/tracing/snapshot'", shell=True)  # Clear it

# Set filter FIRST
print("Setting filter...")
subprocess.run("sudo bash -c 'echo \"ret < 0 && id == 257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/filter'", shell=True)

# Then set simple trigger
print("Setting trigger...")
subprocess.run("sudo bash -c 'echo \"snapshot\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger'", shell=True)

# Enable the event
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable'", shell=True)
subprocess.run("sudo bash -c 'echo \"id == 257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/filter'", shell=True)

# Enable tracing
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Run failing syscall
print("Running test_fail...")
subprocess.run("./test_fail 2>/dev/null", shell=True)

# Give it a moment
time.sleep(0.1)

# Disable tracing
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/tracing_on'", shell=True)

# Check snapshot
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/snapshot | grep -E 'sys_enter.*NR 257|sys_exit.*NR 257' | wc -l", 
                       shell=True, capture_output=True, text=True)
print(f"Syscall events in snapshot: {result.stdout.strip()}")

# Show some events
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/snapshot | grep -E 'sys_enter.*NR 257|sys_exit.*NR 257' | head -5", 
                       shell=True, capture_output=True, text=True)
print(f"Sample events:\n{result.stdout}")

# Cleanup
subprocess.run("sudo bash -c 'echo \"!*\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger'", shell=True, stderr=subprocess.DEVNULL)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/filter'", shell=True)
