#!/usr/bin/env python3
"""Test buffer resize timing"""
import time
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ftrace import Ftrace

def test_buffer_resize():
    """Test different buffer sizes and timing"""
    ftrace = Ftrace()
    
    sizes_kb = [512, 1024, 2048, 4096, 8192]  # 0.5MB to 8MB
    
    print("Testing ftrace buffer resize timing:")
    print("-" * 40)
    
    for size_kb in sizes_kb:
        size_mb = size_kb / 1024
        print(f"\nTesting {size_mb:.1f}MB ({size_kb}KB):")
        
        # First read current size
        current = ftrace.buffer_size_kb
        print(f"  Current size: {current}KB")
        
        # Time the resize
        start = time.time()
        ftrace.buffer_size_kb = size_kb
        duration = time.time() - start
        
        print(f"  Resize took: {duration:.2f}s")
        
        # Verify it was set
        actual = ftrace.buffer_size_kb
        print(f"  Actual size: {actual}KB")
        
        if actual != size_kb:
            print(f"  WARNING: Size mismatch! Requested {size_kb}, got {actual}")

if __name__ == "__main__":
    try:
        test_buffer_resize()
    except PermissionError:
        print("Permission denied. Run with sudo or after install_permissions.sh")
    except Exception as e:
        print(f"Error: {e}")