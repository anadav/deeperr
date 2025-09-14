#!/bin/bash
# Setup BCC symlink for the virtual environment
# This is needed because BCC is installed system-wide and needs to be linked

VENV_DIR="${1:-.venv}"
PYTHON_VERSION=$(python3 -c "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')")

if [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found at $VENV_DIR"
    echo "Run 'uv sync' first to create the environment"
    exit 1
fi

BCC_SOURCE="/usr/lib/python3/dist-packages/bcc"
BCC_TARGET="$VENV_DIR/lib/$PYTHON_VERSION/site-packages/bcc"

if [ ! -e "$BCC_SOURCE" ]; then
    echo "BCC not found at $BCC_SOURCE"
    echo "Please install BCC: sudo apt install python3-bpfcc"
    exit 1
fi

if [ -e "$BCC_TARGET" ]; then
    echo "BCC symlink already exists"
else
    echo "Creating BCC symlink..."
    ln -s "$BCC_SOURCE" "$BCC_TARGET"
    echo "BCC symlink created successfully"
fi