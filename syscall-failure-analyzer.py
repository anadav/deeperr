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
import subprocess
from typing import Optional, Set, List, Any, Dict, Union

# Import all modules directly
import lz4.frame
from prmsg import pr_msg, quiet, warn_once, change_output, set_debug, set_quiet
from angrmgr import Angr
from addr2line import Addr2Line
import claripy.backends.backend_smtlib_solvers  # Required for angr's solver system
from intelptrecorder import IntelPTRecorder
from intelptreporter import IntelPTReporter
from kallsyms import Kallsyms, get_vmlinux
from kprobesrecorder import KProbesRecorder
from kprobesreporter import KprobesReporter
from reporter import Reporter
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
    parser.add_argument('--perf', '-f', default='perf', metavar='PATH', help='location of perf')
    parser.add_argument('--debug', '-d', action='store_true', dest='debug', help='debug mode verbosity')
    parser.add_argument('--llvm-symbolizer', '-y', action='store', dest='llvm_symbolizer', default='llvm-symbolizer', help='path to llvm-symbolizer')
    parser.add_argument('--snapshot-size', '-z', action='store', dest='snapshot_size', type=int, default=1, 
                        help='snapshot size in MB (default: 1MB, use larger values like 5 or 10 if you get "failed to capture full snapshot" errors)')
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
    parser.add_argument('command', choices=['record', 'report'], help='command to run: record or report')

    parser.usage = parser.format_usage()[7:].rstrip('\n ') + ' -- <command> [args]\n'

    try:
        args, remaining_argv = parser.parse_known_args()
    except SystemExit:
        # Exit with error
        exit(1)

    # No longer need conditional loading since install mode is removed
    
    if os.geteuid() != 0 and args.command in ['record', 'report']:
        # Check if kptr_restrict is set (which hides kernel addresses)
        try:
            with open('/proc/sys/kernel/kptr_restrict', 'r') as f:
                kptr_restrict = int(f.read().strip())
                if kptr_restrict != 0:
                    pr_msg(f'kernel.kptr_restrict is set to {kptr_restrict}, which hides kernel addresses', level='FATAL')
                    pr_msg(f'Run "sudo ./install_permissions.sh" to configure the system properly', level='INFO')
                    pr_msg(f'Or run with sudo: sudo {" ".join(sys.argv)}', level='INFO')
                    exit(1)
        except (FileNotFoundError, ValueError, IOError):
            pass  # If we can't read it, continue and let other checks handle it

        # Check if capabilities are set on the real Python binary
        real_python = os.path.realpath(sys.executable)
        try:
            result = subprocess.run(['getcap', real_python], capture_output=True, text=True)
            if 'cap_sys_rawio' not in result.stdout:
                pr_msg(f'This tool requires root privileges or proper capabilities.', level='FATAL')
                pr_msg(f'Run "sudo ./install_permissions.sh" to set up permissions for unprivileged access.', level='INFO')
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
    
    # Install mode has been moved to install_permissions.sh
    # The rest of the code is for record/report commands
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
        return
    
    if args.command == 'record':
        kprobes = args.kprobes

        if not kprobes and not IntelPTRecorder.cpu_supports_pt():
            pr_msg("CPU does not support Intel PT", level="ERROR")

        recorder_cls: Any = KProbesRecorder if kprobes else IntelPTRecorder
        # Convert snapshot size from MB to bytes
        snapshot_size_bytes = args.snapshot_size * 1024 * 1024
        a = recorder_cls(
            perf=args.perf,
            objs=objs,
            snapshot_size=snapshot_size_bytes,
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