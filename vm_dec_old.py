"""
Copyright (C) 2024  Catalpa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import os
import sys
import struct


def u32_b(data):
    return struct.unpack(">I", data)[0]


def extract_key_header(_disk_path):
    try:
        print("[*] extract information")
        os.system(f"dd if={_disk_path} of=.tmp_file bs=1 count=592")
        if not os.path.isfile(".tmp_file"):
            print("[-] Error: cannot read disk")
            exit()

        with open(".tmp_file", "rb") as f:
            _raw_data = f.read()

        if _raw_data == b"":
            print("[-] Error: unknown")
            exit()

        assert len(_raw_data) == 592
        key_len = u32_b(_raw_data[108:112])
        print(f"[*] Key length: {key_len}")
        assert key_len == 0x20

        return _raw_data

    except AssertionError:
        print("[-] Error: invalid disk")
        exit()
    except Exception as e:
        print(f"[-] Error: {e}")
        exit()


def get_enc_key(_raw_data):
    return _raw_data[0x70:0xa4]


def get_key(_enc_key):
    tmp1 = _enc_key
    tmp2 = _enc_key[::-1]
    dec_key = []
    i = 0
    while i < len(tmp1):
        _ch = (tmp1[i] ^ tmp2[i]) & 0xff
        if _ch <= 0x1f:
            _ch = (_ch | 0x20) & 0xff
        dec_key.append(_ch)
        i += 1

    return dec_key


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} disk_path")
        exit()

    if os.getuid() != 0:
        print("[-] This script can only be run with root permission")
        exit()

    disk_path = sys.argv[1]
    raw_data = extract_key_header(disk_path)
    enc_key = get_enc_key(raw_data)
    key = get_key(enc_key)
    try:
        with open("./key", "wb") as f:
            f.write(bytes(key))
        print("[+] Saved to ./key")
        os.remove(".tmp_file")
    except Exception as e:
        print(f"[-] Error: {e}")
