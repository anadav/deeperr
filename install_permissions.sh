#!/bin/bash
# Install script to set up permissions for unprivileged execution
# This script should be run with sudo and doesn't require any Python environment

set -e

echo "Setting up permissions for syscall-failure-analyzer..."

# Set kernel.perf_event_paranoid to -1 for Intel PT access
echo "Setting kernel.perf_event_paranoid to -1..."
sysctl -w kernel.perf_event_paranoid=-1

# Set kernel.kptr_restrict to 0 to allow reading kernel addresses from /proc/kallsyms
echo "Setting kernel.kptr_restrict to 0..."
sysctl -w kernel.kptr_restrict=0

# Make it persistent
echo "Making settings persistent..."
echo "kernel.perf_event_paranoid = -1" > /etc/sysctl.d/10-perf-paranoid.conf
echo "kernel.kptr_restrict = 0" >> /etc/sysctl.d/10-perf-paranoid.conf

# Make /proc/kcore readable - needed for kcore access
# Note: This is temporary and resets on reboot for security
echo "Setting /proc/kcore permissions..."
chmod 444 /proc/kcore 2>/dev/null || {
    echo "Warning: Could not make /proc/kcore world-readable"
    echo "  Will rely on cap_dac_override capability instead"
}

# Find Python executable
PYTHON_PATH=$(which python3)
if [ -z "$PYTHON_PATH" ]; then
    echo "Error: python3 not found"
    exit 1
fi

# Set capabilities on Python for kcore/kallsyms access
echo "Setting capabilities on Python binary..."
# cap_dac_override allows reading files regardless of permissions (like /proc/kcore)
setcap cap_sys_admin,cap_sys_ptrace,cap_dac_override,cap_dac_read_search+ep "$PYTHON_PATH" || {
    echo "Warning: Failed to set capabilities on $PYTHON_PATH"
    echo "You may need to run the tool with sudo"
}

# Find the REAL perf executable (not wrapper script)
PERF_WRAPPER=$(which perf 2>/dev/null || true)
if [ -n "$PERF_WRAPPER" ]; then
    # Check if it's a script
    if file "$PERF_WRAPPER" | grep -q "script\|text"; then
        echo "Found perf wrapper at $PERF_WRAPPER, looking for actual binary..."
        # Try to find the actual binary it calls
        ACTUAL_PERF=$(grep -E "exec.*perf|^[^#]*perf" "$PERF_WRAPPER" 2>/dev/null | sed -n 's/.*exec[[:space:]]*\([^[:space:]]*perf[^[:space:]]*\).*/\1/p' | head -1)
        if [ -z "$ACTUAL_PERF" ]; then
            # Try common locations
            for p in /usr/lib/linux-tools/*/perf /usr/lib/linux-tools-*/perf /opt/perf; do
                if [ -x "$p" ]; then
                    ACTUAL_PERF="$p"
                    break
                fi
            done
        fi
        if [ -n "$ACTUAL_PERF" ] && [ -x "$ACTUAL_PERF" ]; then
            PERF_PATH="$ACTUAL_PERF"
        else
            PERF_PATH="$PERF_WRAPPER"
        fi
    else
        PERF_PATH="$PERF_WRAPPER"
    fi

    echo "Setting capabilities on perf binary: $PERF_PATH"
    # Set all necessary capabilities for perf to access kcore
    # cap_perfmon is for performance monitoring (kernel 5.8+)
    # cap_dac_override allows reading files regardless of permissions
    # cap_sys_rawio for raw I/O operations
    # cap_ipc_lock for locking memory
    setcap cap_dac_override,cap_ipc_lock,cap_sys_rawio,cap_sys_ptrace,cap_sys_admin,cap_syslog,cap_perfmon=ep "$PERF_PATH" 2>/dev/null || {
        # Fallback for older kernels without cap_perfmon
        echo "  Trying without cap_perfmon (for older kernels)..."
        setcap cap_dac_override,cap_ipc_lock,cap_sys_rawio,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep "$PERF_PATH" || {
            echo "Warning: Failed to set capabilities on $PERF_PATH"
        }
    }

    # Also try to set capabilities on the wrapper if different
    if [ "$PERF_WRAPPER" != "$PERF_PATH" ]; then
        echo "Also setting capabilities on wrapper: $PERF_WRAPPER"
        setcap cap_dac_override,cap_ipc_lock,cap_sys_rawio,cap_sys_ptrace,cap_sys_admin,cap_syslog,cap_perfmon=ep "$PERF_WRAPPER" 2>/dev/null || true
    fi
else
    echo "perf not found, skipping perf setup"
fi

# Create a helper script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_SCRIPT="$SCRIPT_DIR/syscall-analyzer"

echo "Creating helper script at $HELPER_SCRIPT..."
cat > "$HELPER_SCRIPT" << 'EOF'
#!/bin/bash
# Helper script to run syscall-failure-analyzer
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if uv is available
if command -v uv &> /dev/null; then
    exec uv run python3 ./syscall-failure-analyzer.py "$@"
else
    # Fallback to activated venv if uv is not available
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    elif [ -f "myvenv/bin/activate" ]; then
        source myvenv/bin/activate
    fi
    exec python3 ./syscall-failure-analyzer.py "$@"
fi
EOF

chmod +x "$HELPER_SCRIPT"

echo ""
echo "Installation complete!"
echo ""
echo "You can now run the tool without sudo using:"
echo "  $HELPER_SCRIPT [options]"
echo ""
echo "For example:"
echo "  $HELPER_SCRIPT --help"
echo "  $HELPER_SCRIPT --kprobes --syscall=openat -n 1 record ./test"
echo ""
echo "IMPORTANT: Check /proc/kcore permissions:"
echo "  ls -l /proc/kcore"
echo ""
echo "If it shows -r-------- (not readable), the permission didn't stick."
echo "This happens because /proc/kcore permissions reset for security."
echo ""
echo "To fix:"
echo "  Option 1: sudo chmod 444 /proc/kcore  (temporary, resets on reboot)"
echo "  Option 2: Run the tool with sudo"
echo "  Option 3: Re-run this install script after each reboot"
echo ""
echo "==================================================================="
echo "UBUNTU USERS - IMPORTANT: AppArmor may block perf from accessing kcore"
echo "==================================================================="
echo ""
echo "If you get 'ERROR: kcore is not readable' even with correct permissions,"
echo "you need to disable AppArmor for perf:"
echo ""
echo "  sudo ln -s /etc/apparmor.d/usr.bin.perf /etc/apparmor.d/disable/"
echo "  sudo apparmor_parser -R /etc/apparmor.d/usr.bin.perf"
echo ""
echo "Or temporarily (until reboot):"
echo "  sudo aa-complain /usr/bin/perf"
echo ""
echo "To check if AppArmor is blocking perf:"
echo "  sudo dmesg | grep -i denied | grep perf"
echo "==================================================================="