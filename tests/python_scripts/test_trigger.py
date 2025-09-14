#!/usr/bin/env python3
import subprocess
import time

# Clean state
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/enable'", shell=True)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/snapshot'", shell=True)
subprocess.run("sudo bash -c 'echo 4096 > /sys/kernel/debug/tracing/buffer_size_kb'", shell=True)

# Try to set trigger
print("Setting snapshot trigger with filter...")
result = subprocess.run("sudo bash -c 'echo \"snapshot:1 if ret < 0 && id == 257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger'", 
                       shell=True, capture_output=True, text=True)
if result.returncode != 0:
    print(f"Failed to set trigger: {result.stderr}")
    # Try alternative syntax
    print("Trying alternative syntax...")
    result = subprocess.run("sudo bash -c 'echo \"snapshot if ret < 0\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger'", 
                           shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Also failed: {result.stderr}")
    else:
        print("Alternative syntax worked!")
        # Now add filter separately
        result = subprocess.run("sudo bash -c 'echo \"id==257\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/filter'", 
                               shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("Filter set separately")
else:
    print("Trigger set successfully")

# Check what was set
result = subprocess.run("sudo cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger", 
                       shell=True, capture_output=True, text=True)
print(f"Current trigger: {result.stdout.strip()}")

result = subprocess.run("sudo cat /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/filter", 
                       shell=True, capture_output=True, text=True)
print(f"Current filter: {result.stdout.strip()}")

# Clean up
subprocess.run("sudo bash -c 'echo \"!*\" > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/trigger'", shell=True, stderr=subprocess.DEVNULL)
subprocess.run("sudo bash -c 'echo 0 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/filter'", shell=True, stderr=subprocess.DEVNULL)
