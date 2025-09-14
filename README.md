# Syscall failure analyzer

## Overview

Syscall failure analyzer is a tool for root-cause analysis of syscall failures.
The tool generates a callstack of the condition that triggered the syscall
failure.

The analysis is performed by tracking of branches that were taken during the
invocation of the syscall and replaying the syscall.

## Try it out

### Prerequisites

The installation steps and prerequisites provided in this document have been
primarily tested on Ubuntu. While Ubuntu itself is based on Debian, and
therefore the instructions are expected to work on Debian-based distributions,
there might be subtle differences.

If you are using another Linux distribution or a different package manager, the
package names and installation steps may vary. In such cases, we encourage you
to contribute by documenting the steps for your specific distribution in the
[CONTRIBUTING_DCO.md](CONTRIBUTING_DCO.md) file.

Feel free to integrate this snippet into your documentation where it fits best.

1. Install `binutils` and `bcc`, which are required for
   tracing and analysis.
   ```bash
   sudo apt install binutils bpfcc-tools python3-bpfcc

   # perf is only needed for recording traces using Intel PT. If you are using a
   # custom kernel, do not install linus-tools-`uname -r` since it would fail.
   sudo apt install linux-tools-common linux-tools-generic linux-tools-`uname -r`
   ```

2. Install `libcapstone4` or `libcapstone3`.
   ```bash
   sudo apt install libcapstone4 || sudo apt install libcapstone3
   ```

3. **REQUIRED:** Install the kernel debug symbols (vmlinux)
   
   The syscall-failure-analyzer **requires** kernel debug symbols to function properly. 
   The vmlinux file must be available in one of the following locations:
   - `/usr/lib/debug/boot/vmlinux-$(uname -r)`
   - `/boot/vmlinux-$(uname -r)`
   - Or explicitly specified via the `--vmlinux` command-line option
   
   To install kernel debug symbols:
   ```bash
   codename=$(lsb_release -c | awk  '{print $2}')
   sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
   deb http://ddebs.ubuntu.com/ ${codename}      main restricted universe multiverse
   deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
   deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
   deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
   EOF

   wget -O - http://ddebs.ubuntu.com/dbgsym-release-key.asc | sudo apt-key add -

   sudo apt update
   sudo apt install linux-image-`uname -r`-dbgsym
   ```
   
   **Note:** If the vmlinux file is not found, the tool will fail to initialize properly.
   For other distributions, use the appropriate commands:
   - **Fedora:** `sudo dnf debuginfo-install kernel`
   - **Arch:** `sudo pacman -S linux-headers`
   - **Gentoo:** `sudo emerge -av sys-kernel/linux-headers`

4. *Recommended:* Installing the Linux source code is essential for any
   meaningful analysis using syscall-failure-analyzer output. If you have access to the source code
   through a custom kernel or other means, this step can be skipped. Please note
   that while the source code is not required for syscall-failure-analyzer execution, it is necessary
   for debugging based on syscall-failure-analyzer output.

   ```bash
   sudo apt-get install linux-source
   tar xvf /usr/src/linux-source-$(uname -r).tar.bz2
   cd linux-source-$(uname -r)
   ```

- <u>Custom Kernels</u>:
 If you choose to build your own custom kernel, syscall-failure-analyzer will require access to
 the debug information. You can edit your `.config` file and confirm that
 `CONFIG_DEBUG_INFO=y` is set. If it is not set, please update the settings and
 rebuild your kernel.

### Run

#### Identifying the Failing Syscall

The syscall-failure-analyzer tool requires the name or number of the failing
syscall as an argument. Typically, you would identify this failing syscall
during the development process or through debugging tools like strace. For
instance, running strace alongside your application could show system calls
that return an error. Once you identify the failing syscall, you can provide
its name or number as an argument when running syscall-failure-analyzer. This
enables the tool to specifically target and analyze that particular syscall for
failures.

#### Permission Setup

This tool requires elevated privileges to access system features like kcore and kallsyms. You have two options:

##### Option 1: One-time Installation (Recommended)

Run the install script once with sudo to set up permissions for unprivileged users:

```bash
sudo ./install_permissions.sh
```

This will:
- Set kernel.perf_event_paranoid to -1 (for Intel PT access)
- Create persistent configuration in /etc/sysctl.d/
- Set necessary capabilities on Python and perf binaries
- Create a helper script for easier execution

After installation, you can run the tool without sudo using the generated helper script.

##### Option 2: Run with Sudo

Alternatively, you can run the tool with sudo permissions each time.

#### Environment Setup

This project uses [uv](https://github.com/astral-sh/uv) for dependency management. uv is a fast Python package installer and resolver written in Rust that simplifies dependency management.

1. **Install uv**
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   # Or using pipx (recommended):
   # pipx install uv
   ```

2. **Navigate to the Project Directory**
    ```bash
    cd /path/to/syscall-failure-analyzer
    ```

3. **Install Dependencies**
    ```bash
    uv sync
    ./setup_bcc.sh  # Setup BCC symlink (only needed once)
    ```
    That's it! No need to manually create or activate virtual environments. uv handles everything automatically.

4. **Run the Tool**
    
    You can run the tool directly without activating any virtual environment:
    ```bash
    uv run python3 ./syscall-failure-analyzer.py --help
    ```

5. **Optional: Manual Virtual Environment Activation**
    
    If you prefer to work with an activated environment:
    ```bash
    source .venv/bin/activate
    python3 ./syscall-failure-analyzer.py --help
    deactivate  # When done
    ```

#### Recording Syscall Failure

To record syscall failures, use the following command. This example targets the
first failure of `setregid` syscall when running Linux Test Project's `setregid03`
test:

```bash
uv run python3 ./syscall-failure-analyzer.py --kprobes --syscall=setregid -n 1 record /opt/ltp/testcases/bin/setregid03
```

> Note: Use the `--kprobes` flag for recording with kprobe points. If Intel PT is supported and you prefer to use it, omit the `--kprobes` flag.

#### Reporting Syscall Failures

After recording, generate a report using the following command:

```bash
uv run python3 ./syscall-failure-analyzer.py --syscall=setregid report
```

#### Command-line Arguments

The tool provides a variety of command-line options to customize its behavior:

- **Basic Options**
    - `-h, --help`: Show help message and exit
    - `--verbose, -v`: Enable verbose analysis info
    - `--quiet, -q`: Enable quiet mode
    - `--syscall SYSCALL, -s SYSCALL`: Specify the failing syscall number to track
    - `--occurrences OCCURRENCES, -n OCCURRENCES`: Specify occurrences to record

- **Advanced Options**
    - `--vmlinux OBJS [OBJS ...], -l OBJS [OBJS ...]`: Specify the location of the vmlinux file (required if not in standard locations) or other kernel modules
    - `--path SRC_PATH, -p SRC_PATH`: Specify the path to source code
    - `--perf FileType('x'), -f FileType('x')`: Specify the location of perf
    - `--debug, -d`: Enable debug mode verbosity

For a complete list of command-line options, you can run the tool with `-h` or `--help`:

```bash
python3 ./syscall-failure-analyzer.py -h
```

## Documentation

As of now, the project is in active development, and comprehensive
documentation is in the works. For the time being, you can find the most
relevant information about how to use and contribute to the project in this
[README.md](README.md) and in the [CONTRIBUTING_DCO.md](CONTRIBUTING_DCO.md) files.

If you have specific questions or encounter issues, feel free to open an issue
on GitHub, and we'll do our best to assist you.

We also welcome contributions to improve documentation. If you would like to
contribute, please see the "Contributing" section for guidelines.

## Testing

The project includes a comprehensive test suite in the `tests/` directory. See [tests/README.md](tests/README.md) for details on running tests.

Quick test:
```bash
./tests/quick_test.sh
```

Full test suite:
```bash
uv run python3 tests/run_tests.py
```

## Contributing

The syscall-failure-analyzer project team welcomes contributions from the community. Before you start working with syscall-failure-analyzer, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING_DCO.md](CONTRIBUTING_DCO.md).

## License

This project is licensed under the BSD-2-Clause License. For more details, please see the [LICENSE.md](LICENSE) file in the root directory of this source tree.
