#!/usr/bin/env python3
"""Unit tests for kernel_cve_triage.py's find_config_symbol(): the
Makefile-based Kconfig-symbol lookup that both kernel_cve_triage.py's own
config_inapplicable_candidates bucket and ai_cve_escalation.py's reverify()
rely on to confirm a named file is actually compiled out of a build.

Usage: python3 test_kernel_cve_triage.py
"""
import tempfile
import unittest
from pathlib import Path

from kernel_cve_triage import find_config_symbol, _OBJ_RULE_CACHE


class FindConfigSymbolTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.kdir = Path(self.tmpdir.name)
        _OBJ_RULE_CACHE.clear()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_makefile(self, subdir, text):
        d = self.kdir / subdir
        d.mkdir(parents=True, exist_ok=True)
        (d / "Makefile").write_text(text)

    def test_direct_obj_rule(self):
        self._write_makefile("drivers/foo", "obj-$(CONFIG_FOO) += foo.o\n")
        self.assertEqual(find_config_symbol(str(self.kdir), "drivers/foo/foo.c"), "FOO")

    def test_composite_object_one_level(self):
        """Real pilot finding (CVE-2020-27815): fs/jfs/xattr.c is pulled
        in via a composite jfs-y list, not a direct obj-$(CONFIG_X) rule
        of its own -- this is standard kbuild for any subsystem with
        more than one source file."""
        self._write_makefile(
            "fs/jfs",
            "obj-$(CONFIG_JFS_FS) += jfs.o\n"
            "jfs-y := super.o xattr.o ioctl.o\n",
        )
        self.assertEqual(find_config_symbol(str(self.kdir), "fs/jfs/xattr.c"), "JFS_FS")

    def test_composite_list_with_backslash_continuation(self):
        self._write_makefile(
            "fs/jfs",
            "obj-$(CONFIG_JFS_FS) += jfs.o\n"
            "jfs-y := super.o file.o \\\n"
            "         xattr.o ioctl.o\n",
        )
        self.assertEqual(find_config_symbol(str(self.kdir), "fs/jfs/xattr.c"), "JFS_FS")

    def test_header_never_resolves(self):
        """Headers have no obj- rule of their own -- this must stay
        None, not raise or guess."""
        self._write_makefile("fs/jfs", "obj-$(CONFIG_JFS_FS) += jfs.o\njfs-y := xattr.o\n")
        self.assertIsNone(find_config_symbol(str(self.kdir), "fs/jfs/jfs_xattr.h"))

    def test_no_makefile_returns_none(self):
        self.assertIsNone(find_config_symbol(str(self.kdir), "drivers/missing/foo.c"))

    def test_unrelated_object_in_composite_list_not_matched(self):
        self._write_makefile(
            "fs/jfs",
            "obj-$(CONFIG_JFS_FS) += jfs.o\n"
            "jfs-y := super.o\n"
            "jfs-$(CONFIG_JFS_POSIX_ACL) += acl.o\n",
        )
        # acl.o is gated by a composite $(CONFIG_X) condition, not a plain
        # -y list -- out of scope for this one-level resolver, so None,
        # not a wrong guess.
        self.assertIsNone(find_config_symbol(str(self.kdir), "fs/jfs/acl.c"))


if __name__ == "__main__":
    unittest.main()
