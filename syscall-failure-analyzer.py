#!/usr/bin/python3
# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import glob
import logging
import os
import pickle
import sys
import io
import lz4.frame
import subprocess
import shutil
from typing import Optional, Set, List, Any, Dict, Union

from angrmgr import Angr
from addr2line import Addr2Line
from claripy.backends.backend_smtlib_solvers import *  # Required for angr's solver system
from intelptrecorder import IntelPTRecorder
from intelptreporter import IntelPTReporter
from kallsyms import Kallsyms, get_vmlinux
from kprobesrecorder import KProbesRecorder
from kprobesreporter import KprobesReporter
from reporter import Reporter
from prmsg import pr_msg, quiet, warn_once, change_output, set_debug, set_quiet
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from syscall import ErrorcodeInfo, SyscallInfo
from kcore import Kcore
from ftrace import Ftrace

DEFAULT_DATA_FILENAME = 'deeperr.data'

def get_occurrences(s:str) -> Optional[Set[int]]:
    if s is None:
        return None
    if s.isnumeric():
        return {int(s)}
    try:
        r = {int(v.strip()) for v in s.split(',')}
    except (ValueError, AttributeError):
        pr_msg('Could not parse occurances list, skipping input', level='ERROR')
        r = None

    return r

def report(inputs: str,
           src_path: Optional[str],
           output: Optional[str],
           print_stats: bool,
           objs: List[io.BufferedReader],
           syscall_filter: Optional[int],
           errcode_filter: Optional[int],
           occurrences_filter: Optional[Set[int]],
           **kwargs: Any) -> None:
    if output is not None:
        try:
            change_output(output)
        except Exception as e:
            pr_msg(f'{e}', level='FATAL')
            return

    res_files = glob.glob(inputs)
    if len(res_files) == 0:
        pr_msg('found no result files', level="ERROR")
        return

    for f_name in res_files:
        try:
            with lz4.frame.open(f_name, 'rb') as failure_file:
                # Load the data from the file
                data = pickle.load(failure_file)
        except FileNotFoundError:
            pr_msg(f'error reading result file {f_name}: file not found', level='ERROR')
            continue
        except EOFError:
            pr_msg(f'error reading result file {f_name}: file is empty', level='ERROR')
            continue
        except lz4.frame.LZ4FrameError:
            pr_msg(f'error reading result file {f_name}: file is corrupted', level='ERROR')
            continue
        
        kallsyms = data['kallsyms'] if 'kallsyms' in data else Kallsyms(objs)
        saved_segs = data.get('kcore')
        kcore = Kcore() if saved_segs is None else None

        if saved_segs is None:
            pr_msg(f'kcore was not saved, reading from /proc/kcore', level='INFO')

        # We need to init ftrace before angr to clear all probe points that
        # might have been left. Otherwise, disassembly will fail.
        ftrace = Ftrace()
        ftrace.kprobe_event_disable_all()

        angr_mgr = Angr(kallsyms, 
                        kcore = kcore,
                        saved_segs = saved_segs)

        reporter_cls = IntelPTReporter if data['type'] == 'intel-pt' else KprobesReporter
        report_kwargs = {
            'objs': objs,
            'errcode_filter': errcode_filter,
            'syscall_filter': syscall_filter,
            'print_stats': print_stats,
            # Filtering based on occurrences is done during reporting only for Intel PT,
            # since we cannot reliably filter it out during recording
            'occurrences_filter': occurrences_filter,
            'angr_mgr': angr_mgr,
            'traces': data['traces'],
            'failures': data['failures'],
            'src_path': src_path,
        }

        reporter: Reporter = reporter_cls(**report_kwargs)
        reporter.report()


def valid_path(path: str) -> str:
    if os.path.exists(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"Path '{path}' does not exist.")

def main() -> None:
    def arg_error(parser: argparse.ArgumentParser) -> None:
        # add suffix to the usage string
        parser.print_help()
        exit()

    parser = argparse.ArgumentParser("deeperr", epilog="application")
    parser.add_argument('--verbose', '-v', action='store_true', dest='verbose', help='prints verbose analysis info')
    parser.add_argument('--vmlinux', '-l', action='store', dest='objs', help='location of vmlinux file or other modules', type=argparse.FileType('rb'), nargs='+', default=[])
    parser.add_argument('--perf', '-f', default='perf', metavar=argparse.FileType('x'), help='location of perf')
    parser.add_argument('--debug', '-d', action='store_true', dest='debug', help='debug mode verbosity')
    parser.add_argument('--llvm-symbolizer', '-y', action='store', dest='llvm_symbolizer', default='llvm-symbolizer', help='path to llvm-symbolizer')
    parser.add_argument('--snapshot-size', '-z', action='store', dest='snapshot_size', type=int, default=262144, help='perf snapshot size')
    parser.add_argument('--tmp', '-t', action='store', dest='tmp_path', default='/tmp', type=valid_path, help='tmp path')
    parser.add_argument('--syscall', '-s', action='store', dest='syscall', help='failing syscall number to track')
    parser.add_argument('--quiet', '-q', action='store_true', dest='quiet', help='quiet mode')
    parser.add_argument('--errcode', '-r', action='store', dest='errcode', help='error number')
    parser.add_argument('--output', '-o', action='store', dest='output', help='output file', default=None, metavar='PATH')
    parser.add_argument('--input', '-i', action='store', dest='input', help='input file', default=DEFAULT_DATA_FILENAME, metavar='FILES')
    parser.add_argument('--kprobes', '-k', action='store_true', dest='kprobes', help='use kprobes')
    parser.add_argument('--occurrences', '-n', action='store', dest='occurrences', help='occurrences to record')
    parser.add_argument('--extra-info', '-x', action='store_true', dest='print_stats', help='detailed output with analysis statistics')
    parser.add_argument('--path', '-p', action='store', dest='src_path', default=None, type=valid_path, help='path to source code')
    parser.add_argument('--nokcore', '-w', action='store_true', dest='nokcore', help='do not save kcore')
    parser.add_argument('--early-stop', '-e', action='store_true', dest='early_stop', help='stop execution after first failure')
    parser.add_argument('command', choices=['record', 'report', 'install'], help='command to run: record, report, or install')

    parser.usage = parser.format_usage()[7:].rstrip('\n ') + ' -- <command> [args]\n'

    try:
        args, remaining_argv = parser.parse_known_args()
    except SystemExit:
        # Exit with error
        exit(1)

    if args.command == 'install':
        if os.geteuid() != 0:
            pr_msg(f'Install mode must be run as root', level='FATAL')
            exit(1)
    elif os.geteuid() != 0 and args.command in ['record', 'report']:
        # Check if capabilities are set on the real Python binary
        real_python = os.path.realpath(sys.executable)
        try:
            result = subprocess.run(['getcap', real_python], capture_output=True, text=True)
            if 'cap_sys_rawio' not in result.stdout:
                pr_msg(f'This tool requires root privileges or proper capabilities.', level='FATAL')
                pr_msg(f'Run "sudo {sys.executable} {__file__} install" to set up permissions.', level='INFO')
                exit(1)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pr_msg(f'This tool requires root privileges.', level='FATAL')
            pr_msg(f'Run "sudo {sys.executable} {__file__} install" to set up permissions.', level='INFO')
            exit(1)

    if remaining_argv and remaining_argv[0] == '--':
        remaining_argv = remaining_argv[1:]
    
    sys.setrecursionlimit(10 ** 5)

    loglevel = 'ERROR'
    if args.debug:
        loglevel = 'DEBUG'
    elif args.verbose:
        loglevel = 'INFO'

    set_quiet(args.quiet)
    set_debug(args.debug)

    logging.basicConfig(filename='deeperr.log', level=loglevel, force=True)
    logging.getLogger().setLevel(loglevel)
    for l in ['angr', 'cle', 'pyvex', 'claripy']:
        logging.getLogger(l).setLevel('ERROR')

    objs = get_vmlinux(args.objs)

    syscall_filter = None
    if args.syscall is not None:
        try:
            syscall_filter = SyscallInfo.get_syscall_nr(args.syscall)
        except ValueError as e:
            pr_msg(str(e), level="ERROR")
            pr_msg('recording all syscall', level="WARN")
    errcode_filter = ErrorcodeInfo.get_errno(args.errcode) if args.errcode else None
    occurrences_filter = get_occurrences(args.occurrences) if args.occurrences else None

    a2l = Addr2Line.get_instance()
    a2l.llvm_symbolizer = args.llvm_symbolizer

    if args.command == 'record' and len(remaining_argv) < 1:
        arg_error(parser)

    if args.command == 'install':
        pr_msg('Setting up permissions for unprivileged users...', level='INFO')
        
        # Set perf_event_paranoid to -1
        try:
            with open('/proc/sys/kernel/perf_event_paranoid', 'w') as f:
                f.write('-1')
            pr_msg('Set /proc/sys/kernel/perf_event_paranoid to -1', level='INFO')
        except Exception as e:
            pr_msg(f'Failed to set perf_event_paranoid: {e}', level='ERROR')
        
        # Set kptr_restrict to 0 to allow reading kernel addresses
        try:
            with open('/proc/sys/kernel/kptr_restrict', 'w') as f:
                f.write('0')
            pr_msg('Set /proc/sys/kernel/kptr_restrict to 0 (kernel addresses visible)', level='INFO')
        except Exception as e:
            pr_msg(f'Failed to set kptr_restrict: {e}', level='ERROR')
        
        # Make /proc/kcore readable by changing permissions temporarily
        # This is a security risk but necessary for perf --kcore to work
        try:
            subprocess.run(['chmod', '444', '/proc/kcore'], check=True, capture_output=True, text=True)
            pr_msg('Made /proc/kcore world-readable (temporary, resets on reboot)', level='INFO')
            pr_msg('  WARNING: This reduces system security', level='WARN')
        except subprocess.CalledProcessError as e:
            pr_msg(f'Failed to change /proc/kcore permissions: {e.stderr}', level='ERROR')
        
        # Set ptrace_scope to 0 to allow ptrace
        ptrace_scope_path = '/proc/sys/kernel/yama/ptrace_scope'
        if os.path.exists(ptrace_scope_path):
            try:
                with open(ptrace_scope_path, 'w') as f:
                    f.write('0')
                pr_msg('Set ptrace_scope to 0 (allows ptrace)', level='INFO')
            except Exception as e:
                pr_msg(f'Failed to set ptrace_scope: {e}', level='ERROR')
        
        # Check if debugfs is mounted at /sys/kernel/debug
        debugfs_path = '/sys/kernel/debug'
        if not os.path.exists(os.path.join(debugfs_path, 'tracing')):
            pr_msg('debugfs not mounted or tracing not available', level='WARN')
            try:
                # Try to mount debugfs
                subprocess.run(['mount', '-t', 'debugfs', 'none', debugfs_path],
                             check=True, capture_output=True, text=True)
                pr_msg(f'Mounted debugfs at {debugfs_path}', level='INFO')
            except subprocess.CalledProcessError:
                pr_msg('Could not mount debugfs, kprobes may not work', level='WARN')
        else:
            pr_msg('debugfs already mounted with tracing support', level='INFO')
        
        # Set permissions on tracing directory
        tracing_path = os.path.join(debugfs_path, 'tracing')
        if os.path.exists(tracing_path):
            try:
                # Make tracing accessible (this might not persist across reboots)
                subprocess.run(['chmod', '-R', 'a+rX', tracing_path],
                             check=True, capture_output=True, text=True)
                pr_msg(f'Set read permissions on {tracing_path}', level='INFO')
            except subprocess.CalledProcessError as e:
                pr_msg(f'Could not set permissions on tracing: {e.stderr}', level='WARN')
        
        # Make it persistent across reboots
        try:
            sysctl_conf = '/etc/sysctl.d/99-syscall-analyzer.conf'
            with open(sysctl_conf, 'w') as f:
                f.write('# Configuration for syscall-failure-analyzer\n')
                f.write('kernel.perf_event_paranoid = -1\n')
            pr_msg(f'Created {sysctl_conf} for persistent settings', level='INFO')
        except Exception as e:
            pr_msg(f'Failed to create sysctl config: {e}', level='ERROR')
        
        # Find the actual Python executable that will be used
        python_path = sys.executable
        pr_msg(f'Current Python executable: {python_path}', level='INFO')
        
        # Find the real Python binary (resolve all symlinks)
        real_python_path = os.path.realpath(python_path)
        pr_msg(f'Real Python binary: {real_python_path}', level='INFO')
        
        # Also check which python3 to handle different environments
        which_python = shutil.which('python3')
        if which_python:
            which_python_real = os.path.realpath(which_python)
            pr_msg(f'System python3: {which_python_real}', level='INFO')
        
        # Set capabilities on the real Python executable
        # Add cap_perfmon for perf/ftrace access, cap_bpf for BPF programs, cap_dac_override to read /proc/kcore
        capabilities = 'cap_sys_rawio,cap_sys_admin,cap_sys_ptrace,cap_dac_read_search,cap_dac_override,cap_perfmon,cap_bpf,cap_net_admin+ep'
        try:
            subprocess.run(['setcap', capabilities, real_python_path], 
                         check=True, capture_output=True, text=True)
            pr_msg(f'Set capabilities on {real_python_path}', level='INFO')
        except subprocess.CalledProcessError as e:
            pr_msg(f'Failed to set capabilities on {real_python_path}: {e.stderr}', level='ERROR')
            # Try with a reduced set of capabilities for older kernels
            try:
                fallback_caps = 'cap_sys_rawio,cap_sys_admin,cap_sys_ptrace,cap_dac_read_search,cap_dac_override+ep'
                subprocess.run(['setcap', fallback_caps, real_python_path],
                             check=True, capture_output=True, text=True)
                pr_msg(f'Set reduced capabilities on {real_python_path} (older kernel)', level='INFO')
            except subprocess.CalledProcessError as e2:
                pr_msg(f'Failed to set any capabilities: {e2.stderr}', level='ERROR')
                pr_msg(f'You may need to manually set capabilities on your Python binary', level='WARN')
        
        # Find perf executable and set capabilities
        # Use the --perf argument if provided, otherwise find the default perf
        perf_path = args.perf if args.perf != 'perf' else shutil.which('perf')
        
        if perf_path:
            # Check if perf_path is a wrapper script and find the real binary
            real_perf_paths: List[str] = []
            
            # Check if it's the standard Ubuntu perf wrapper
            if os.path.isfile(perf_path):
                try:
                    with open(perf_path, 'r') as f:
                        first_line = f.readline()
                    if first_line.startswith('#!/bin/bash'):
                        # It's likely a wrapper script, find the real perf binary
                        import platform
                        kernel_version = platform.release()
                        
                        # Try standard Ubuntu locations
                        possible_paths = [
                            f'/usr/lib/linux-tools/{kernel_version}/perf',
                            f'/usr/lib/linux-tools-{kernel_version}/perf',
                        ]
                        
                        # Also check what the wrapper would execute
                        for path in possible_paths:
                            if os.path.exists(path):
                                # Resolve any symlinks
                                real_path = os.path.realpath(path)
                                if os.path.exists(real_path):
                                    real_perf_paths.append(real_path)
                        
                        # Also add the wrapper itself
                        real_perf_paths.append(perf_path)
                    else:
                        # It's the actual binary
                        real_perf_paths = [perf_path]
                except (IOError, OSError):
                    real_perf_paths = [perf_path]
            else:
                real_perf_paths = [perf_path]
            
            # Remove duplicates while preserving order
            seen: Set[str] = set()
            unique_perf_paths: List[str] = []
            for path in real_perf_paths:
                if path not in seen:
                    seen.add(path)
                    unique_perf_paths.append(path)
            
            for perf_binary in unique_perf_paths:
                try:
                    # Skip if it's a script
                    if os.path.isfile(perf_binary):
                        with open(perf_binary, 'rb') as f:
                            # Check if it's an ELF binary (starts with magic bytes)
                            magic = f.read(4)
                            if magic != b'\x7fELF':
                                pr_msg(f'Skipping {perf_binary} (not an ELF binary)', level='INFO')
                                continue
                    
                    # perf needs cap_sys_rawio and cap_dac_override to read /proc/kcore, cap_perfmon for performance monitoring
                    perf_caps = 'cap_sys_rawio,cap_sys_admin,cap_sys_ptrace,cap_syslog,cap_dac_override,cap_perfmon,cap_ipc_lock+ep'
                    subprocess.run(['setcap', perf_caps, perf_binary],
                                 check=True, capture_output=True, text=True)
                    pr_msg(f'Set capabilities on {perf_binary}', level='INFO')
                except subprocess.CalledProcessError as e:
                    pr_msg(f'Failed to set capabilities on {perf_binary}: {e.stderr}', level='ERROR')
                    # Try with reduced capabilities for older kernels
                    try:
                        fallback_perf_caps = 'cap_sys_rawio,cap_sys_admin,cap_sys_ptrace,cap_syslog,cap_dac_override+ep'
                        subprocess.run(['setcap', fallback_perf_caps, perf_binary],
                                     check=True, capture_output=True, text=True)
                        pr_msg(f'Set reduced capabilities on {perf_binary} (older kernel)', level='INFO')
                    except subprocess.CalledProcessError as e2:
                        pr_msg(f'Failed to set any capabilities on {perf_binary}: {e2.stderr}', level='ERROR')
                except Exception as e:
                    pr_msg(f'Error processing {perf_binary}: {e}', level='ERROR')
        else:
            pr_msg('perf not found in PATH', level='WARN')
        
        # Create a helper script for running without sudo
        script_path = os.path.abspath(__file__)
        helper_script = os.path.join(os.path.dirname(script_path), 'syscall-analyzer')
        try:
            with open(helper_script, 'w') as f:
                f.write('#!/bin/bash\n')
                f.write(f'# Helper script for syscall-failure-analyzer\n')
                f.write(f'exec {python_path} {script_path} "$@"\n')
            os.chmod(helper_script, 0o755)
            pr_msg(f'Created helper script: {helper_script}', level='INFO')
        except Exception as e:
            pr_msg(f'Failed to create helper script: {e}', level='ERROR')
        
        pr_msg('\nInstallation complete!', level='INFO')
        pr_msg('You can now run the tool without sudo:', level='INFO')
        pr_msg(f'  {helper_script} record --syscall <syscall> -- <command>', level='INFO')
        pr_msg(f'  {helper_script} report', level='INFO')
        pr_msg('\nNote: Some features may still require elevated privileges.', level='WARN')
        pr_msg('If you encounter permission issues, try running with sudo.', level='WARN')
        return
    
    if args.command == 'record':
        kprobes = args.kprobes

        if not kprobes and not IntelPTRecorder.cpu_supports_pt():
            pr_msg("CPU does not support Intel PT", level="ERROR")

        recorder_cls: Any = KProbesRecorder if kprobes else IntelPTRecorder
        a = recorder_cls(
            perf=args.perf,
            objs=objs,
            snapshot_size=args.snapshot_size,
            errcode_filter=errcode_filter,
            syscall_filter=syscall_filter,
            occurrences_filter=occurrences_filter,
            output=args.output or 'deeperr.data',
            tmp_path=args.tmp_path,
            debug=args.debug,
            save_kcore=not args.nokcore,
            early_stop=args.early_stop,
        )
        try:
            a.record(args=remaining_argv)
        except OSError as e:
            pr_msg(f'error recording: {e}', level='FATAL')
    else:
        report(inputs=args.input,
               output=args.output,
               print_stats=args.print_stats,
               objs=objs,
               errcode_filter=errcode_filter,
               syscall_filter=syscall_filter,
               occurrences_filter=occurrences_filter,
               src_path=args.src_path)

if __name__ == "__main__":
    main()