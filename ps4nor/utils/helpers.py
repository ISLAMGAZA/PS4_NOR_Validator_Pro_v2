import hashlib
import struct
import re
import os

def md5_hash(data):
    return hashlib.md5(data).hexdigest().upper()


def sha256_hash(data):
    return hashlib.sha256(data).hexdigest().upper()


def entropy(data):
    if not data:
        return 0.0
    import math
    from collections import Counter
    length = len(data)
    if length == 0:
        return 0.0
    freq = Counter(data)
    entropy_val = 0.0
    for count in freq.values():
        p_x = count / length
        entropy_val -= p_x * math.log2(p_x)
    return entropy_val


def all_same_byte(data):
    if not data:
        return True
    first = data[0]
    return all(b == first for b in data)


def is_all_zeros(data):
    return all(b == 0 for b in data)


def is_all_ff(data):
    return all(b == 0xFF for b in data)


def is_all_filled(data):
    return is_all_zeros(data) or is_all_ff(data)


def read_ascii_string(data, offset, length):
    end = data.find(b'\x00', offset, offset + length)
    if end == -1:
        end = offset + length
    try:
        return data[offset:end].decode('ascii', errors='replace')
    except:
        return repr(data[offset:end])


def read_le32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def read_be32(data, offset):
    return struct.unpack_from('>I', data, offset)[0]


def decode_nvs_fw(data):
    """Decode FW_VER at 0x1C906A using Wee Tools format: '{:X}.{:02X}'.format(fw[1], fw[0])"""
    if len(data) < 0x1C906C:
        return None
    fw = data[0x1C906A:0x1C906C]
    if fw[0] == 0xFF and fw[1] == 0xFF:
        return None
    return '{:X}.{:02X}'.format(fw[1], fw[0])


def detect_fw_version(data):
    """Wee Tools-compatible FW detection chain:
    1. FW_VER at 0x1C906A
    2. FW_V at 0x1CA606 (fallback if 0xFF)
    3. EAP_KBL MD5 (fallback if still 0xFF)
    4. Active slot EMC_IPL MD5 (last resort)
    5. String search (absolute last)
    """
    from .fw_db import EMC_IPL_MD5, EAP_KBL_MD5

    # 1. FW_VER
    fw = decode_nvs_fw(data)
    if fw:
        return fw

    # 2. FW_V at 0x1CA606 (ASCII)
    if len(data) >= 0x1CA608:
        fw_v = data[0x1CA606:0x1CA608]
        try:
            s = fw_v.decode('ascii').strip('\x00').strip()
            if s and '.' in s:
                return s
        except:
            pass

    # 3. EAP_KBL MD5
    eap = data[0x0C4000:0x144000]
    md5_eap = md5_hash(eap).lower()
    if md5_eap in EAP_KBL_MD5:
        fw_list = EAP_KBL_MD5[md5_eap]['fw']
        return fw_list[0] if len(fw_list) == 1 else (fw_list[0] + ' <-> ' + fw_list[-1])

    # 4. Active slot EMC_IPL MD5
    active = detect_active_slot(data)
    emc_ipl = data[0x004000:0x064000] if active == 'A' else data[0x064000:0x0C4000]
    md5_emc = md5_hash(emc_ipl).lower()
    if md5_emc in EMC_IPL_MD5:
        fw_list = EMC_IPL_MD5[md5_emc]['fw']
        return fw_list[0] if len(fw_list) == 1 else (fw_list[0] + ' <-> ' + fw_list[-1])

    # 5. String search
    fw_map = {
        b"01.01": "1.01", b"01.76": "1.76", b"02.00": "2.00",
        b"02.50": "2.50", b"02.57": "2.57", b"03.00": "3.00",
        b"03.10": "3.10", b"03.11": "3.11", b"03.15": "3.15",
        b"03.50": "3.50", b"03.55": "3.55", b"04.00": "4.00",
        b"04.01": "4.01", b"04.05": "4.05", b"04.06": "4.06",
        b"04.07": "4.07", b"04.50": "4.50", b"04.55": "4.55",
        b"04.70": "4.70", b"04.71": "4.71", b"04.73": "4.73",
        b"04.74": "4.74", b"05.00": "5.00", b"05.01": "5.01",
        b"05.05": "5.05", b"05.50": "5.50", b"05.55": "5.55",
        b"06.00": "6.00", b"06.02": "6.02", b"06.20": "6.20",
        b"06.50": "6.50", b"06.51": "6.51", b"06.52": "6.52",
        b"06.70": "6.70", b"06.71": "6.71", b"06.72": "6.72",
        b"07.00": "7.00", b"07.01": "7.01", b"07.02": "7.02",
        b"07.50": "7.50", b"07.51": "7.51", b"07.55": "7.55",
        b"08.00": "8.00", b"08.01": "8.01", b"08.03": "8.03",
        b"08.10": "8.10", b"08.50": "8.50", b"08.52": "8.52",
        b"09.00": "9.00", b"09.03": "9.03", b"09.04": "9.04",
        b"09.50": "9.50", b"09.51": "9.51", b"09.60": "9.60",
        b"10.00": "10.00", b"10.01": "10.01", b"10.50": "10.50",
        b"10.70": "10.70", b"10.71": "10.71", b"11.00": "11.00",
        b"11.02": "11.02", b"11.50": "11.50", b"11.52": "11.52",
        b"12.00": "12.00", b"12.50": "12.50", b"13.00": "13.00",
    }
    for pattern, version in fw_map.items():
        if pattern in data:
            return version
    return "Unknown"


def detect_active_slot(data):
    """Determine active slot. Primary indicator at 0x1000 (Wee Tools standard)."""
    if len(data) > 0x1000:
        b = data[0x1000]
        if b == 0x00:
            return "A"
        if b == 0x80:
            return "B"
    if len(data) > 0x201000:
        b = data[0x201000]
        if b == 0x00:
            return "A"
        if b == 0x80:
            return "B"
    return "?"


def detect_fw_per_slot(data):
    """Return per-slot FW info from EMC_IPL MD5 (uses new fw_db structure)."""
    from .fw_db import EMC_IPL_MD5
    emc_a = data[0x004000:0x064000]
    emc_b = data[0x064000:0x0C4000]
    md5_a = md5_hash(emc_a).lower()
    md5_b = md5_hash(emc_b).lower()

    def resolve(md5):
        result = EMC_IPL_MD5.get(md5)
        if result:
            return result['fw'][0], result['fw'][-1], result.get('t', 0)
        return None, None, None

    min_a, max_a, t_a = resolve(md5_a)
    min_b, max_b, t_b = resolve(md5_b)

    return {
        "slot_A": {"min": min_a, "max": max_a, "md5": md5_a, "type": t_a},
        "slot_B": {"min": min_b, "max": max_b, "md5": md5_b, "type": t_b},
    }


def detect_sku(data):
    sku_match = re.search(rb'CUH-\d{4}[A-Z0-9]?', data)
    if sku_match:
        return sku_match.group(0).decode('ascii')
    return "Unknown"


def detect_mobo_serial(data):
    for offset in [0x1CA000, 0x0A4000]:
        chunk = data[offset:offset+0x1000] if offset < len(data) else b''
        serial_match = re.search(rb'\d{10,16}', chunk)
        if serial_match:
            return serial_match.group(0).decode('ascii')
    return "Unknown"


def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def format_offset(offset):
    return f"0x{offset:06X}"


def load_md5_database():
    db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'md5_hashes.json')
    if os.path.exists(db_path):
        import json
        with open(db_path, 'r') as f:
            return json.load(f)
    return {}
