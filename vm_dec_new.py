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
import io
import sys
import gzip
import shutil
import tarfile
import subprocess
from pathlib import Path


BOOT_DISK = None
DATA_DISK = None
WORK_PLACE = ".work_place"
BOOT_MTP = ".boot_disk"
DATA_MTP = ".data_disk"
SUNUP_KEY = "sunup.key"
SYSTEM_KEY = "system.key"
SYSTEM_HEADER_KEY = "system_header.key"
LUKS_HEADER = "luks_header.bin"


def mount_disk(disk_path, mount_point):
    try:
        print(f"[*] Mounting {disk_path}")
        if os.path.isdir(mount_point):
            print(f"[!] Error: local folder {mount_point} already exists")
            return False

        os.mkdir(mount_point)
        mounted = subprocess.run(["mount"], capture_output=True, text=True).stdout
        if disk_path in mounted:
            print(f"[-] Error: {disk_path} already mounted")
            return False

        subprocess.run(["mount", disk_path, mount_point], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: cannot mount BOOT_DISK {disk_path}, {e}")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def retrieve_boot_files():
    try:
        print("[*] Retrieve boot files")
        if not os.path.isfile(f"{BOOT_MTP}/SYSTEM.LIC"):
            print("[-] Missing SYSTEM.LIC, invalid disk")
            return False
        if not os.path.isfile(f"{BOOT_MTP}/SYSTEM.SYS"):
            print("[-] Missing SYSTEM.SYS, invalid disk")
            return False
        shutil.copy(f"{BOOT_MTP}/SYSTEM.LIC", f"{WORK_PLACE}/SYSTEM.LIC")
        shutil.copy(f"{BOOT_MTP}/SYSTEM.SYS", f"{WORK_PLACE}/SYSTEM.SYS")
        return True
    except IOError as e:
        print(f"[-] Error: cannot copy files, {e}")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def prepare_keys():
    try:
        print("[*] Set up keys")
        os.mkdir(f"{WORK_PLACE}/keys")
        os.mkdir(f"{WORK_PLACE}/p_keys")
        with tarfile.open(f"{WORK_PLACE}/SYSTEM.LIC", "r:gz") as f:
            f.extractall(path=f"{WORK_PLACE}/keys")

        _path = Path(f"{WORK_PLACE}/keys")
        _key_path = []
        for file_path in _path.rglob("*"):
            if file_path.is_file():
                if "KEY:SUNUP-crypt-release.key" in str(file_path) or \
                   "DATA:SUNUP-crypt-release.key" in str(file_path) or \
                   "LastBootMachineId-" in str(file_path) or \
                   "TINY:SYSTEM" in str(file_path):
                    shutil.copy(str(file_path), f"{WORK_PLACE}/p_keys/{file_path.name}")
                    _key_path.append(f"{WORK_PLACE}/p_keys/{file_path.name}")
        return _key_path
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def dec_key(_file_path, _uuid_key):
    try:
        print("[*] Decrypting key")
        with open(_file_path, "rb") as f:
            raw_data = f.read()

        with gzip.GzipFile(fileobj=io.BytesIO(raw_data[4:])) as gz:
            decom_data = gz.read()

        with open(f"{WORK_PLACE}/p_keys/k_tmp", "wb") as f:
            f.write(b"Salted__" + decom_data)

        subprocess.run(["openssl", "enc", "-aes-128-cbc", "-d", "-iter", "1000", "-salt",
                        "-k", _uuid_key, "-in", f"{WORK_PLACE}/p_keys/k_tmp",
                        "-out", f"{WORK_PLACE}/p_keys/dk_tmp"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] openssl decrypt failed: {e}")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def dec_luks_header(_file_path):
    try:
        print("[*] Decrypting LUKS header")
        with open(_file_path, "rb") as f:
            raw_data = f.read()

        with open(f"{WORK_PLACE}/d_tmp", "wb") as f:
            f.write(b"Salted__" + raw_data)

        subprocess.run(["openssl", "enc", "-d", "-pbkdf2", "-aes-256-cbc", "-nopad",
                        "-kfile", SYSTEM_HEADER_KEY,
                        "-in", f"{WORK_PLACE}/d_tmp",
                        "-out", LUKS_HEADER,], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: openssl decrypt failed: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def dec_data(_file_path):
    try:
        print("[*] Decrypting data")
        with open(_file_path, "rb") as f:
            raw_data = f.read()[4:]

        with open(f"{WORK_PLACE}/d_tmp", "wb") as f:
            f.write(raw_data)

        subprocess.run(["openssl", "enc", "-des-ecb", "-iter", "512", "-d",
                        "-kfile", f"{WORK_PLACE}/p_keys/dk_tmp",
                        "-in", f"{WORK_PLACE}/d_tmp",
                        "-out", f"{WORK_PLACE}/dd_tmp",
                        "-provider", "legacy",
                        "-provider", "default"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: openssl decrypt failed: {e}")
        print("[*] Maybe your openssl does not support -des-ecb decrypt")
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def get_uuid_key(_file_path):
    try:
        print("[*] Handling UUID key")
        with open(_file_path, "rb") as f:
            raw_data = f.read()

        return raw_data[4:]
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def decrypt_keys(_key_path):
    try:
        uuid_key = None
        for f in _key_path:
            if "LastBootMachineId" in f:
                uuid_key = get_uuid_key(f)
                print(f"[+] UUID key is: {uuid_key.decode()}")

        sunup_key = None
        sunup_data = None
        t_system = None
        t_header = None
        for f in _key_path:
            if "KEY:SUNUP-crypt-release.key" in f:
                sunup_key = f
            elif "DATA:SUNUP-crypt-release.key" in f:
                sunup_data = f
            elif "TINY:SYSTEM_HEADER" in f:
                t_header = f
            elif "TINY:SYSTEM-" in f:
                t_system = f

        if not dec_key(sunup_key, uuid_key):
            return False
        if not dec_data(sunup_data):
            return False
        shutil.copy(f"{WORK_PLACE}/dd_tmp", SUNUP_KEY)
        print(f"[+] SUNUP private key saved to ./{SUNUP_KEY}")

        if not dec_key(t_header, uuid_key):
            return False
        shutil.copy(f"{WORK_PLACE}/p_keys/dk_tmp", SYSTEM_HEADER_KEY)
        print(f"[+] SYSTEM_HEADER key saved to ./{SYSTEM_HEADER_KEY}")

        if not dec_key(t_system, uuid_key):
            return False
        shutil.copy(f"{WORK_PLACE}/p_keys/dk_tmp", SYSTEM_KEY)
        print(f"[+] SYSTEM key saved to ./{SYSTEM_KEY}")

        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def decrypt_disk():
    try:
        if not dec_luks_header(f"{WORK_PLACE}/SYSTEM.SYS"):
            return False
        print(f"[+] LUKS header saved to ./{LUKS_HEADER}")
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def init_work_place():
    try:
        print("[*] Init work place")
        if os.path.isdir(WORK_PLACE):
            print(f"[-] Work place {WORK_PLACE} already exists")
            return False
        os.mkdir(WORK_PLACE)
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def clean_work_place():
    try:
        subprocess.run(["umount", BOOT_MTP], check=True)
        shutil.rmtree(WORK_PLACE)
        shutil.rmtree(BOOT_MTP)
    except subprocess.CalledProcessError as e:
        print(f"[-] clean error: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <BOOT_DISK> <DATA_DISK>")
        exit()

    if os.getuid() != 0:
        print("[-] This script can only be run with root permission")
        exit()

    BOOT_DISK = sys.argv[1]
    DATA_DISK = sys.argv[2]
    try:
        if not init_work_place():
            raise Exception

        if not mount_disk(BOOT_DISK, BOOT_MTP):
            raise Exception

        if not retrieve_boot_files():
            raise Exception

        key_path = prepare_keys()
        if key_path is None:
            raise Exception

        if not decrypt_keys(key_path):
            raise Exception

        if not decrypt_disk():
            raise Exception

        print(f"[*] You can run: 'sudo cryptsetup open --header {LUKS_HEADER} --key-file {SYSTEM_KEY} {DATA_DISK} map' "
              f"to decrypt the disk")
        print("    Run: 'sudo lvdisplay' to find LVM(eg. /dev/.SECURE./A) and "
              "'sudo mount /dev/.SECURE./A xxx' to mount the disk")
    finally:
        clean_work_place()
