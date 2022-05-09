# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn.helpers.linux.kconfig import get_kconfig
from drgn.helpers.linux.slab import (
    find_slab_cache,
    for_each_slab_cache,
    slab_cache_for_each_allocated_object,
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
