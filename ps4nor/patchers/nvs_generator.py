"""
NVS Generator - Rebuilds NVS areas (0x1C4000-0x1D0000) from scratch
using metadata extracted from target dump + best donor match.
"""
import os
import re
from ..utils.helpers import md5_hash, detect_sku, detect_fw_version
from ..utils.nor_defs import CID_REGIONS
from ..v2_features.smart_donor import SmartDonorMatcher

NVS_START = 0x1C4000
NVS_END = 0x1D0000
NVS_SIZE = NVS_END - NVS_START

FW_VER_OFFSET = 0x1C906A - NVS_START  # 0x506A

# NVS sub-region offsets (relative to NVS_START)
OFF_FLAGS0      = 0x0000  # 0x1C4000: model-specific flags
OFF_HDD_META    = 0x1000  # 0x1C5000: HDD metadata (identical across all dumps)
OFF_UNKNOWN     = 0x2000  # 0x1C6000: unknown/data
OFF_FLAGS1      = 0x3000  # 0x1C7000: model-specific flags
OFF_SERIAL      = 0x4000  # 0x1C8000: serial number ASCII at +0x20 (0x1C8020)
OFF_CID_CRC     = 0x5000  # 0x1C9000: 1C9 CID CRC
OFF_CID         = 0x6000  # 0x1CA000: 1CA CID
OFF_CB          = 0x7000  # 0x1CB000: 1CB (0xFF-filled)
OFF_CID_CRC_MIR = 0x8000  # 0x1CC000: 1CC mirror of 1C9
OFF_CID_MIR     = 0x9000  # 0x1CD000: 1CD mirror of 1CA
OFF_HDD_META_DUP = 0xA000  # 0x1CE000: HDD metadata duplicate
OFF_TAIL        = 0xB000  # 0x1CF000: 0xFF + 0x00 at start

CID_CRC_OFFSET  = 0x1CA000 - NVS_START  # 0x6000
CID_CRD_OFFSET  = 0x1CD000 - NVS_START  # 0x9000


def _is_region_valid(data, offset, size=0x1000, threshold=64):
    """Check if a region has meaningful data (>threshold non-0xFF/non-0x00 bytes)."""
    chunk = data[offset:offset+size]
    return sum(1 for b in chunk if b not in (0, 0xFF)) > threshold


def _find_donor(data, donors_dir="donors"):
    """Find best donor match using SmartDonorMatcher then fallback."""
    target_sku = detect_sku(data)
    target_fw = detect_fw_version(data)

    if not os.path.isdir(donors_dir):
        return None

    # Try SmartDonorMatcher first
    try:
        matcher = SmartDonorMatcher(donors_dir, use_cache=False)
        result = matcher.match(target_sku, target_fw)
        if result.best and result.best.score > 50:
            try:
                with open(result.best.filepath, 'rb') as f:
                    ddata = f.read()
                if len(ddata) == 0x2000000:
                    nvs = ddata[NVS_START:NVS_END]
                    nz = sum(1 for b in nvs if b not in (0, 0xFF))
                    if nz >= 512:
                        sku = detect_sku(ddata)
                        fw = detect_fw_version(ddata)
                        return (result.best.filepath, ddata, sku, fw)
            except Exception:
                pass
    except Exception:
        pass

    # Fallback: original scan
    best = None
    best_score = -1
    for fname in sorted(os.listdir(donors_dir)):
        if not fname.upper().endswith('.BIN'):
            continue
        path = os.path.join(donors_dir, fname)
        try:
            d = open(path, 'rb').read()
        except:
            continue
        if len(d) != 0x2000000:
            continue

        sku = detect_sku(d)
        fw = detect_fw_version(d)
        nvs = d[NVS_START:NVS_END]
        nz = sum(1 for b in nvs if b not in (0, 0xFF))
        if nz < 512:
            continue

        score = 0
        if target_sku != "Unknown" and sku != "Unknown":
            if sku == target_sku:
                score += 50
            elif sku[:7] == target_sku[:7]:
                score += 30
        if fw != "Unknown" and target_fw != "Unknown" and fw == target_fw:
            score += 40

        if score > best_score:
            best_score = score
            best = (path, d, sku, fw)

    return best


# SN is stored at absolute 0x1C8030 (NVS offset 0x4030),
# preceded by a 16-byte header at 0x1C8020-0x1C802F.
SN_ABS_OFFSET = 0x1C8030  # absolute NOR offset where SN string lives
SN_NVS_OFFSET = SN_ABS_OFFSET - 0x1C4000  # = 0x4030


def _read_serial(data, offset=SN_ABS_OFFSET):
    """Extract serial number as 16-char zero-padded string."""
    chunk = data[offset:offset+16]
    serial_match = re.search(rb'\d{10,18}', chunk)
    if serial_match:
        s = serial_match.group(0).decode('ascii')
        return s.zfill(16)[:16]
    return None


def _encode_fw_ver(fw_str):
    """Encode FW string '12.00' -> bytes [minor, major].
    Major stored as hex pair: FW 12.00 stores 0x12 (18), displayed as 'X' format '12'.
    Minor stored as hex byte: .50 stores 0x50 (80), displayed as '02X' format '50'."""
    if not fw_str or fw_str == "Unknown":
        return b'\xFF\xFF'
    first = fw_str.split('<->')[0].split('\u2192')[0].strip()
    parts = first.split('.')
    try:
        major = int(parts[0], 16)
        minor = int(parts[1][:2], 16) if len(parts) > 1 else 0
        return bytes([minor, major])
    except:
        return b'\xFF\xFF'


def _lookup_fw_from_partitions(data):
    """Determine FW version from unchanged EMC_IPL/EAP_KBL partitions (MD5-based)."""
    from ..utils.fw_db import EAP_KBL_MD5, EMC_IPL_MD5
    for label, start, size, db in [
        ("EAP_KBL",   0x0C4000, 0x080000, EAP_KBL_MD5),
        ("EMC_IPL_A", 0x004000, 0x060000, EMC_IPL_MD5),
        ("EMC_IPL_B", 0x064000, 0x060000, EMC_IPL_MD5),
    ]:
        chunk = data[start:start+size]
        m5 = md5_hash(chunk).lower()
        if m5 in db:
            return db[m5]['fw'][0]
    return None


class NVSGenerator:
    def __init__(self, data, donors_dir="donors"):
        self.data = bytearray(data)
        self.donors_dir = donors_dir
        self.donor_info = None
        self.report = []

    def find_best_donor(self):
        result = _find_donor(self.data, self.donors_dir)
        if result:
            self.donor_info = result
            self.report.append(f"Donor: {os.path.basename(result[0])} ({result[2]}, FW={result[3]})")
        else:
            self.report.append("No suitable donor found")
        return self.donor_info is not None

    @staticmethod
    def _region_is_viable(data, offset, size=0x1000, min_bytes=64):
        chunk = data[offset:offset+size]
        return sum(1 for b in chunk if b not in (0, 0xFF)) > min_bytes

    def regenerate(self):
        self.report = []

        if not self.donor_info and not self.find_best_donor():
            self.report.append("Aborted: no donor available")
            return False

        donor_path, donor_data, donor_sku, donor_fw = self.donor_info
        d = donor_data[NVS_START:NVS_END]
        result = bytearray(NVS_SIZE)

        # ── Flags 0x1C4000-1C4FFF ──
        if self._region_is_viable(self.data, NVS_START + OFF_FLAGS0):
            result[OFF_FLAGS0:OFF_FLAGS0+0x1000] = self.data[NVS_START+OFF_FLAGS0:NVS_START+OFF_FLAGS0+0x1000]
            self.report.append("Kept 0x1C4000-1C4FFF (flags) from target")
        else:
            result[OFF_FLAGS0:OFF_FLAGS0+0x1000] = d[OFF_FLAGS0:OFF_FLAGS0+0x1000]
            self.report.append("Regenerated 0x1C4000-1C4FFF (flags) from donor")

        # ── HDD metadata 0x1C5000-1C5FFF ──
        if self._region_is_viable(self.data, NVS_START + OFF_HDD_META):
            result[OFF_HDD_META:OFF_HDD_META+0x1000] = self.data[NVS_START+OFF_HDD_META:NVS_START+OFF_HDD_META+0x1000]
            self.report.append("Kept 0x1C5000-1C5FFF (HDD metadata) from target")
        else:
            result[OFF_HDD_META:OFF_HDD_META+0x1000] = d[OFF_HDD_META:OFF_HDD_META+0x1000]
            self.report.append("Regenerated 0x1C5000-1C5FFF (HDD metadata) from donor")

        # ── 0x1C6000-1C6FFF ──
        if self._region_is_viable(self.data, NVS_START + OFF_UNKNOWN):
            result[OFF_UNKNOWN:OFF_UNKNOWN+0x1000] = self.data[NVS_START+OFF_UNKNOWN:NVS_START+OFF_UNKNOWN+0x1000]
            self.report.append("Kept 0x1C6000-1C6FFF from target")
        else:
            result[OFF_UNKNOWN:OFF_UNKNOWN+0x1000] = d[OFF_UNKNOWN:OFF_UNKNOWN+0x1000]
            self.report.append("Regenerated 0x1C6000-1C6FFF from donor")

        # ── Flags 0x1C7000-1C7FFF ──
        if self._region_is_viable(self.data, NVS_START + OFF_FLAGS1):
            result[OFF_FLAGS1:OFF_FLAGS1+0x1000] = self.data[NVS_START+OFF_FLAGS1:NVS_START+OFF_FLAGS1+0x1000]
            self.report.append("Kept 0x1C7000-1C7FFF (flags) from target")
        else:
            result[OFF_FLAGS1:OFF_FLAGS1+0x1000] = d[OFF_FLAGS1:OFF_FLAGS1+0x1000]
            self.report.append("Regenerated 0x1C7000-1C7FFF (flags) from donor")

        # ── SN at absolute 0x1C8030 ──
        # Copy entire 0x1C8000-1C8FFF from donor as base (preserves header at 0x1C8020)
        result[OFF_SERIAL:OFF_SERIAL+0x1000] = d[OFF_SERIAL:OFF_SERIAL+0x1000]
        # Overwrite SN string at correct offset (NVS 0x4030 = absolute 0x1C8030)
        serial = _read_serial(self.data)
        if not serial:
            serial = _read_serial(donor_data)
        if serial:
            data_abs = result  # result is NVS sub-buffer
            offset = SN_NVS_OFFSET  # = 0x4030
            serial_bytes = serial.encode('ascii')[:16]
            data_abs[offset:offset+len(serial_bytes)] = serial_bytes
            self.report.append(f"Regenerated 0x1C8000-1C8FFF (SN: {serial})")
        else:
            self.report.append("Regenerated 0x1C8000-1C8FFF from donor")

        # ── 1C9 + 1CC (CID CRC + mirror) ──
        if self._region_is_viable(self.data, NVS_START + OFF_CID_CRC):
            result[OFF_CID_CRC:OFF_CID_CRC+0x1000] = self.data[NVS_START+OFF_CID_CRC:NVS_START+OFF_CID_CRC+0x1000]
            result[OFF_CID_CRC_MIR:OFF_CID_CRC_MIR+0x1000] = self.data[NVS_START+OFF_CID_CRC:NVS_START+OFF_CID_CRC+0x1000]
            self.report.append("Kept 1C9/1CC (CID CRC) from target")
        else:
            result[OFF_CID_CRC:OFF_CID_CRC+0x1000] = d[OFF_CID_CRC:OFF_CID_CRC+0x1000]
            result[OFF_CID_CRC_MIR:OFF_CID_CRC_MIR+0x1000] = d[OFF_CID_CRC:OFF_CID_CRC+0x1000]
            self.report.append("Regenerated 1C9/1CC (CID CRC) from donor")

        # ── 1CA + 1CD (CID + mirror) ──
        if self._region_is_viable(self.data, NVS_START + OFF_CID):
            result[OFF_CID:OFF_CID+0x1000] = self.data[NVS_START+OFF_CID:NVS_START+OFF_CID+0x1000]
            result[OFF_CID_MIR:OFF_CID_MIR+0x1000] = self.data[NVS_START+OFF_CID:NVS_START+OFF_CID+0x1000]
            self.report.append("Kept 1CA/1CD (CID) from target")
        else:
            result[OFF_CID:OFF_CID+0x1000] = d[OFF_CID:OFF_CID+0x1000]
            result[OFF_CID_MIR:OFF_CID_MIR+0x1000] = d[OFF_CID:OFF_CID+0x1000]
            self.report.append("Regenerated 1CA/1CD (CID) from donor")

        # ── 1CB (0xFF) ──
        result[OFF_CB:OFF_CB+0x1000] = b'\xFF' * 0x1000
        self.report.append("Regenerated 1CB (FF)")

        # ── HDD metadata duplicate 0x1CE000 ──
        # Should match 0x1C5000; prefer target if viable
        if self._region_is_viable(self.data, NVS_START + OFF_HDD_META_DUP):
            result[OFF_HDD_META_DUP:OFF_HDD_META_DUP+0x1000] = self.data[NVS_START+OFF_HDD_META_DUP:NVS_START+OFF_HDD_META_DUP+0x1000]
            self.report.append("Kept 0x1CE000-1CEFFF (HDD metadata dup) from target")
        else:
            result[OFF_HDD_META_DUP:OFF_HDD_META_DUP+0x1000] = d[OFF_HDD_META_DUP:OFF_HDD_META_DUP+0x1000]
            self.report.append("Regenerated 0x1CE000-1CEFFF (HDD metadata dup) from donor")

        # ── 0x1CF000-1CFFFF: FF + 00 at first byte ──
        if self._region_is_viable(self.data, NVS_START + OFF_TAIL):
            result[OFF_TAIL:OFF_TAIL+0x1000] = self.data[NVS_START+OFF_TAIL:NVS_START+OFF_TAIL+0x1000]
            self.report.append("Kept 0x1CF000-1CFFFF from target")
        else:
            result[OFF_TAIL:OFF_TAIL+0x1000] = b'\xFF' * 0x1000
            result[OFF_TAIL] = 0x00
            self.report.append("Regenerated 0x1CF000-1CFFFF (FF+00)")

        # ── FW_VER at 0x506A ──
        fw_str = _lookup_fw_from_partitions(self.data)
        if not fw_str:
            fw_str = detect_fw_version(self.data)
        if fw_str and fw_str != "Unknown":
            result[FW_VER_OFFSET:FW_VER_OFFSET+2] = _encode_fw_ver(fw_str)
            self.report.append(f"Set FW_VER: {fw_str}")
        else:
            result[FW_VER_OFFSET:FW_VER_OFFSET+2] = d[FW_VER_OFFSET:FW_VER_OFFSET+2]
            self.report.append("FW_VER from donor")

        self.data[NVS_START:NVS_END] = result
        self.report.append("NVS regeneration complete")
        return True

    def get_data(self):
        return bytes(self.data)

    def get_report(self):
        return "\n".join(self.report)
