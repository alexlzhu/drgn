# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from collections import defaultdict
from pathlib import Path

from drgn.helpers.linux.kconfig import get_kconfig
from drgn.helpers.linux.slab import (
    find_slab_cache,
    for_each_slab_cache,
    slab_cache_for_each_allocated_object,
    slab_cache_is_merged,
)
from tests.linux_kernel import LinuxKernelTestCase


def get_proc_slabinfo_names():
    with open("/proc/slabinfo", "rb") as f:
        # Skip the version and header.
        f.readline()
        f.readline()
        return [line.split()[0] for line in f]


def fallback_slab_cache_names(prog):
    # SLOB does not provide /proc/slabinfo. It is also disabled for SLUB if
    # CONFIG_SLUB_DEBUG=n. Before Linux kernel commit 5b36577109be ("mm:
    # slabinfo: remove CONFIG_SLABINFO") (in v4.15), it could also be disabled
    # for SLAB. So, pick a few slab caches which we know exist to test against.
    # In case they were merged into other caches, get their names from the
    # structs rather than just returning the names.
    return {
        prog["dentry_cache"].name.string_(),
        prog["mm_cachep"].name.string_(),
        prog["uid_cachep"].name.string_(),
    }


class TestSlab(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            kconfig = get_kconfig(cls.prog)
        except LookupError:
            cls.allocator = None
        else:
            for allocator in ("SLUB", "SLAB", "SLOB"):
                if kconfig.get("CONFIG_" + allocator, "n") != "n":
                    break
            else:
                raise Exception("couldn't find slab allocator config option")
            cls.allocator = allocator

    def _slab_cache_aliases(self):
        slab_path = Path("/sys/kernel/slab")
        if not slab_path.exists():
            self.skipTest(f"{slab_path} does not exist")
        aliases = defaultdict(list)
        for child in slab_path.iterdir():
            if not child.name.startswith(":"):
                aliases[child.stat().st_ino].append(child.name)
        return aliases

    def test_slab_cache_is_merged_false(self):
        for aliases in self._slab_cache_aliases().values():
            if len(aliases) == 1:
                break
        else:
            self.skipTest("no unmerged slab caches")
        self.assertFalse(slab_cache_is_merged(find_slab_cache(self.prog, aliases[0])))

    def test_slab_cache_is_merged_true(self):
        for aliases in self._slab_cache_aliases().values():
            if len(aliases) > 1:
                break
        else:
            self.skipTest("no merged slab caches")
        for alias in aliases:
            slab_cache = find_slab_cache(self.prog, alias)
            if slab_cache is not None:
                break
        else:
            self.fail("couldn't find slab cache")
        self.assertTrue(slab_cache_is_merged(slab_cache))

    def test_for_each_slab_cache(self):
        try:
            slab_cache_names = get_proc_slabinfo_names()
        except FileNotFoundError:
            # The found names should be a superset of the fallback names.
            self.assertGreaterEqual(
                {s.name.string_() for s in for_each_slab_cache(self.prog)},
                fallback_slab_cache_names(self.prog),
            )
        else:
            self.assertCountEqual(
                [s.name.string_() for s in for_each_slab_cache(self.prog)],
                slab_cache_names,
            )

    def test_find_slab_cache(self):
        try:
            slab_cache_names = get_proc_slabinfo_names()
        except FileNotFoundError:
            slab_cache_names = fallback_slab_cache_names(self.prog)
        for name in slab_cache_names:
            slab = find_slab_cache(self.prog, name)
            self.assertEqual(name, slab.name.string_())

    def test_get_allocated_slab_objects(self):
        if self.allocator is None:
            self.skipTest("couldn't determine slab allocator")
        elif self.allocator == "SLOB":
            self.assertRaisesRegex(
                ValueError,
                "SLOB is not supported",
                next,
                slab_cache_for_each_allocated_object(
                    find_slab_cache(self.prog, "dentry"), "struct dentry"
                ),
            )
        else:
            self.assertIn(
                self.prog["init_fs"].root.dentry,
                slab_cache_for_each_allocated_object(
                    find_slab_cache(self.prog, "dentry"), "struct dentry"
                ),
            )
