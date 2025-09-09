# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from abstractarch import Arch
from x86arch import ArchX86

# Global architecture instance - currently x86-64
arch: Arch = ArchX86()