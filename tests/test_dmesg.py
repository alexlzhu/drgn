# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import sys, os, fcntl, errno, pprint

from drgn.helpers.linux import get_dmesg
from tests.helpers.linux import LinuxHelperTestCase


def read_kmsg():
    f = open("/dev/kmsg", "r")
    fd = os.dup(f.fileno())
    f.close()
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
    kmsg_buffer = ""
    while True:
        try:
            msg = os.read(fd, 512)
        except OSError as e:
            if e.errno == errno.EAGAIN:
                break
            else:
                raise e
        kmsg_buffer += msg.decode("unicode_escape")
    os.close(fd)
    kmsg_list = kmsg_buffer.split('\n')
    filtered_kmsg_list = []
    for line in kmsg_list:
        if len(line) > 0 and line[0] == ' ':
            continue
        append = line
        if line.find(';') != -1:
            append = line[line.find(';') + 1:]
        append = append.replace("â", "→")
        filtered_kmsg_list += [append]
    return '\n'.join(filtered_kmsg_list).encode()

class TestDmesg(LinuxHelperTestCase):
    def test_get_dmesg(self):
        self.assertEqual(read_kmsg().decode(), get_dmesg(self.prog).decode())
