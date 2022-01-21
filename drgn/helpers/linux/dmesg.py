# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
dmesg-vmcore
-------

The ``drgn.helpers.linux.dmesg`` module provides helpers for reading the
Linux kernel log.
"""

from drgn import Program, cast, sizeof

__all__ = ("get_dmesg",)


def dump_dmesg_lockless(prog: Program) -> bytes:
    DESC_SV_BITS = sizeof(prog.type("uint64_t")) * 8
    DESC_FLAGS_SHIFT = DESC_SV_BITS - 2
    DESC_FLAGS_MASK = 3 << DESC_FLAGS_SHIFT
    DESC_ID_MASK = ~DESC_FLAGS_MASK

    DESC32_SV_BITS = sizeof(prog.type("uint32_t")) * 8
    DESC32_FLAGS_SHIFT = DESC32_SV_BITS - 2
    DESC32_FLAGS_MASK = 3 << DESC32_FLAGS_SHIFT
    DESC32_ID_MASK = ~DESC32_FLAGS_MASK

    bitmask = DESC32_ID_MASK
    if prog.platform.flags.IS_64_BIT.value:
        bitmask = DESC_ID_MASK

    printk_ringbuffer = prog['prb']
    desc_ring = printk_ringbuffer.desc_ring
    text_data_ring = printk_ringbuffer.text_data_ring
    text_data_ring_size = 1 << text_data_ring.size_bits

    tail_id = desc_ring.tail_id.counter
    head_id = desc_ring.head_id.counter
    out_buf = str.encode("")
    idx = 0

    while tail_id != head_id:
        text_len = desc_ring.infos[idx].text_len
        descs = desc_ring.descs[idx]
        lpos_begin = descs.text_blk_lpos.begin % text_data_ring_size
        lpos_next = descs.text_blk_lpos.next % text_data_ring_size
        lpos_begin += prog.type('long').size

        if lpos_begin == lpos_next:
            continue
        if lpos_begin > lpos_next:
            lpos_begin = 0
        if lpos_next - lpos_begin < text_len:
            text_len = lpos_next - lpos_begin

        out_buf += prog.read(text_data_ring.data + lpos_begin, text_len)
        out_buf += str.encode('\n')
        idx += 1
        tail_id += 1
        tail_id &= bitmask
    return out_buf

def dump_dmesg_structured(prog: Program) -> bytes:
    out_buf = str.encode("")
    current_idx = prog['log_first_idx']
    while current_idx != prog['log_next_idx']:
        log = cast("struct printk_log *", prog['log_buf'] + current_idx)
        out_buf += prog.read(prog['log_buf'] + current_idx + sizeof(prog.type("struct printk_log")), log.text_len)
        out_buf += str.encode('\n')
        current_idx += log.len
    return out_buf

def get_dmesg(prog: Program) -> bytes:
    """Get the contents of the kernel ring buffer."""
    try:
        return dump_dmesg_lockless(prog)
    except KeyError:
        return dump_dmesg_structured(prog)
