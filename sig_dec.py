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
import subprocess
from Crypto.Cipher import AES

AES_IV = b"\x0A\x25\x4C\x2F\xE7\xAE\x0B\x70\x47\x02\x8D\x6B\x4B\x2E\x69\x44"
AES_KEY = b"\xFE\x4C\x8C\x32\xFB\xAE\x1A\xF3\xC4\xA0\xAB\xC8\xE1\x86\x6C\xAD"
FIRMWARE_FILE = None
OPCODE_OFFSET = 0x85
PRODUCT_CODE_OFFSET = 0xa8
ROM_CODE_OFFSET = 0xac
BODY_LEN_OFFSET = 0x90
HEADER_LEN_OFFSET = 0x94
DSA_START = 0x84
DSA_VERIFY_OFFSET = 0x80
MAGIC = b"\x49\xAF\x08\x12"
DSA_KEY = (b"\x30\x82\x01\xA1\x02\x81\x80\x45\xBA\x71\x98\x87\xB7\x02\xC6\xFC"
           b"\x90\x3E\xCE\xA1\xD9\xB6\x9A\x57\xE8\x4C\xFE\x9B\x54\x89\xC4\x95"
           b"\xD3\x41\xBF\xE7\xB2\xD8\x17\x72\xEA\x54\x45\xC5\xE0\x3E\x7A\x20"
           b"\x9D\x29\x5B\x99\x67\xB2\x62\xA0\x80\x87\xE9\x67\xFB\xFB\xF9\x6C"
           b"\x3C\x15\x73\xFE\x98\xB0\xB5\x8C\x25\x77\xD4\x5D\xD8\xA3\xDB\x77"
           b"\x07\x85\x98\xEE\xA1\x1A\x17\x7E\x3E\x1B\xC8\xC7\x99\x9C\x2F\xAC"
           b"\x3D\xA3\x4A\x7F\x27\x48\xD5\xD3\xA9\xA4\x8E\x80\x0B\xDF\x0A\xF7"
           b"\x70\xCE\xD3\xF1\x71\x56\x2D\x86\xD2\x95\x34\xC0\x7D\x4B\x52\x5B"
           b"\x83\x1A\x13\x7C\x57\x51\x76\x02\x81\x81\x00\xE7\xB1\x78\xE1\xCE"
           b"\x11\x73\xCB\xC5\xFE\xFD\x77\x8B\xC0\x8A\xD1\xBB\xA7\xAE\xB6\x25"
           b"\x67\xEF\xEB\xC8\x24\x88\x6A\x40\x54\xAB\x28\xE4\xE0\x8D\xE8\x18"
           b"\x97\xA3\xF9\x26\x74\x67\xB4\x1C\x3D\xED\x8A\x1E\xA1\x4F\x34\xBE"
           b"\x29\x1F\xED\xB0\x05\x51\x8C\x85\xB2\xCD\x47\xA9\x3D\x5F\xC5\x88"
           b"\xC3\x46\xC7\x28\xE5\x8A\x09\x79\x44\x80\xC1\x24\x68\xAA\x04\x08"
           b"\xDF\x1B\x5B\xE6\x88\x33\x6A\xA5\x59\x32\x16\x42\x8A\x1F\xAF\x1D"
           b"\xA9\xDE\x67\x9F\x65\xA6\xAF\x62\xE3\xC6\x8C\xFF\xD1\x53\x08\x03"
           b"\xA0\x88\xAF\x1C\x94\xEB\x53\x3F\x36\xFD\x49\x02\x15\x00\x88\x2B"
           b"\x5B\x93\x8C\xD8\xDA\x89\xB3\x00\xA4\x68\x67\x74\x84\x01\xF1\xF1"
           b"\x85\x8D\x02\x81\x80\x55\x66\x97\x59\xD5\x33\x77\xE5\x75\x0D\xD1"
           b"\xCB\xE8\xDD\x10\x19\xF4\xDD\x6F\xDC\x6C\xFC\x2B\x08\xCC\x53\xCD"
           b"\x08\x91\xCC\xAC\x7F\x3A\x18\x58\x8E\x10\x02\x0D\xEC\x34\x89\x59"
           b"\x2C\x2F\x2D\x85\xC3\xE1\x3C\x8A\x05\x00\x9A\x97\x3B\x96\x30\xA4"
           b"\xA4\xCD\x02\x6D\x63\x8C\x74\x33\xBC\x55\x14\xD4\x2B\x69\x53\x85"
           b"\xAE\x68\x95\x3B\x8D\x0B\x2B\x01\xC7\xE3\xDC\x08\xF7\x0D\x24\x4A"
           b"\x98\x06\x82\xC6\xD0\x49\x4A\xE2\x81\xC7\xAE\x83\x29\x94\xE8\x90"
           b"\x5B\x68\x63\xC0\x39\xE8\x4C\x6E\xE1\x2B\xB0\xAE\xE1\x15\x23\x7A"
           b"\x49\x84\x6A\xC8\xE1")
TMP_SIG_FILE = ".sonic.sig"
TMP_DATA_FILE = ".sonic_data.bin"
TMP_DSA_DER_FILE = ".sonic_dsa.der"
TMP_DSA_PEM_FILE = ".sonic_dsa.pem"
HEADER_FILE = "FFWHDR.INF"


def u32(_data):
    return struct.unpack(">I", _data)[0]


def check_workspace():
    try:
        if os.path.isfile(TMP_SIG_FILE):
            print(f"[-] Error: {TMP_SIG_FILE} exists")
            exit(0)
        if os.path.isfile(TMP_DATA_FILE):
            print(f"[-] Error: {TMP_DATA_FILE} exists")
            exit(0)
        if os.path.isfile(TMP_DSA_DER_FILE):
            print(f"[-] Error: {TMP_DSA_DER_FILE} exists")
            exit(0)
        if os.path.isfile(TMP_DSA_PEM_FILE):
            print(f"[-] Error: {TMP_DSA_PEM_FILE} exists")
            exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        exit(0)


def clean_workspace():
    try:
        os.remove(TMP_SIG_FILE)
        os.remove(TMP_DATA_FILE)
        os.remove(TMP_DSA_DER_FILE)
        os.remove(TMP_DSA_PEM_FILE)
    except Exception as e:
        print(f"[-] Clean failed: {e}")


def read_data():
    try:
        print("[*] Reading data")
        with open(FIRMWARE_FILE, "rb") as f:
            _data = f.read()

        return _data
    except Exception as e:
        print(f"[-] Error: {e}")
        exit(0)


def get_opcode(_data):
    try:
        return _data[0x85]
    except Exception as e:
        print(f"[-] Error: {e}")
        exit(0)


def check_format(_data, _opcode):
    try:
        _magic = _data[0:4]
        if _magic != MAGIC:
            print("[-] Error: invalid file")
            exit(0)

        if _opcode > 0xb or _opcode == 4:
            print("[-] Error: invalid opcode")
            exit(0)

        _product_code = u32(_data[PRODUCT_CODE_OFFSET:PRODUCT_CODE_OFFSET + 4])
        print(f"[*] Product code is: {_product_code}")    # only one code
        _rom_version = u32(_data[ROM_CODE_OFFSET:ROM_CODE_OFFSET + 4])
        print(f"[*] Rom version is: {_rom_version}")
    except Exception as e:
        print(f"[-] Error: {e}")
        exit(0)


def dsa_verify_data(_data):
    try:
        print("[*] Validating file")
        dsa_signature_len = u32(_data[DSA_VERIFY_OFFSET:DSA_VERIFY_OFFSET + 4])
        print(f"[*] DSA signature length: {dsa_signature_len}")
        dsa_sig = _data[4:4 + dsa_signature_len]
        with open(TMP_SIG_FILE, "wb") as f:
            f.write(dsa_sig)

        with open(TMP_DATA_FILE, "wb") as f:
            f.write(_data[DSA_START:])

        with open(TMP_DSA_DER_FILE, "wb") as f:
            f.write(DSA_KEY)

        subprocess.run(["openssl", "dsa", "-inform", "DER",
                        "-in", TMP_DSA_DER_FILE,
                        "-pubin", "-outform", "PEM",
                        "-out", TMP_DSA_PEM_FILE], check=True)
        subprocess.run(["openssl", "dgst", "-sha1",
                        "-verify", TMP_DSA_PEM_FILE,
                        "-signature", TMP_SIG_FILE,
                        TMP_DATA_FILE], check=True)
        print("[+] Signature is valid.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Signature verify failed: {e}")
        exit(0)
    except Exception as e:
        print(f"[-] Signature is invalid: {e}")
        exit(0)
    finally:
        clean_workspace()


def split_header(_data):
    try:
        print("[*] Split header")
        _h_len = u32(_data[HEADER_LEN_OFFSET:HEADER_LEN_OFFSET + 4])
        _b_len = u32(_data[BODY_LEN_OFFSET:BODY_LEN_OFFSET + 4])
        print(f"[*] Header length is: {_h_len}")
        print(f"[*] Body length is: {_b_len}")
        _header_data = _data[:_h_len]
        remain_length = 1024 - _h_len
        if remain_length > 0:
            _header_data += b"\x00" * remain_length

        with open(HEADER_FILE, "wb") as f:
            f.write(_header_data)
        return _h_len, _b_len
    except Exception as e:
        print(f"[-] Error: {e}")
        exit(0)


def aes_dec(_enc_data):
    try:
        print("[*] Decrypting")
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        _dec_data = cipher.decrypt(_enc_data)
        with open("dec.bin", "wb") as f:
            f.write(_dec_data)

        print("[+] Saved to ./dec.bin")
    except Exception as e:
        print(f"[-] Error: {e}")
        exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: python3 {sys.argv[0]} <firmware_file>")
        exit(0)

    FIRMWARE_FILE = sys.argv[1]
    if not os.path.isfile(FIRMWARE_FILE):
        print(f"[-] Error: invalid file {FIRMWARE_FILE}")
        exit(0)

    check_workspace()
    data = read_data()
    opcode = get_opcode(data)
    check_format(data, opcode)
    dsa_verify_data(data)
    h_len, b_len = split_header(data)
    aes_dec(data[h_len:])
