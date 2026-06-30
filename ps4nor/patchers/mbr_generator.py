import os, struct
from ..utils.helpers import detect_sku, detect_fw_version, is_all_zeros, is_all_ff
from ..v2_features.smart_donor import SmartDonorMatcher

MBR1_OFF = 0x002000
MBR2_OFF = 0x003000
MBR_SIZE = 0x1000
BLOCK_SIZE = 0x200

PARTITIONS_TYPES = {
    0: "empty", 1: "idstorage", 2: "sam_ipl", 3: "core_os",
    6: "bd_hrl", 13: "emc_ipl", 14: "eap_kbl",
    32: "emc_ipl", 33: "eap_kbl", 34: "nvs", 38: "wifi",
    39: "vtrm", 40: "empty", 41: "C0050100",
}

SLOT0_PARTITIONS = [
    {"name": "EMC_IPL_A",  "start_lba": 0x10, "n_sectors": 0x300, "type": 0x20, "flag": 0x01},
    {"name": "EMC_IPL_B",  "start_lba": 0x310, "n_sectors": 0x300, "type": 0x20, "flag": 0x00},
    {"name": "EAP_KBL",    "start_lba": 0x610, "n_sectors": 0x400, "type": 0x21, "flag": 0x01},
    {"name": "Torus",      "start_lba": 0xA10, "n_sectors": 0x400, "type": 0x26, "flag": 0x01},
    {"name": "NVS",        "start_lba": 0xE10, "n_sectors": 0x060, "type": 0x22, "flag": 0x01},
    {"name": "Slot0_Spare","start_lba": 0xE70, "n_sectors": 0x180, "type": 0x00, "flag": 0x01},
]

MAGIC = b"Sony Computer Entertainment Inc."


def _pack_mbr(version, n_sectors, reserved, loader_start, loader_count, reserved2, partitions):
    parts_bin = b"".join(
        struct.pack("<IIBBHQ", p[0], p[1], p[2], p[3], p[4], p[5])
        for p in partitions
    )
    parts_bin = parts_bin[:16 * 20].ljust(16 * 20, b"\x00")
    mbr = (
        MAGIC +
        struct.pack("<II", version, n_sectors) +
        struct.pack("<Q", reserved) +
        struct.pack("<II", loader_start, loader_count) +
        struct.pack("<Q", reserved2) +
        parts_bin
    )
    return mbr.ljust(MBR_SIZE, b"\x00")


def _parse_mbr(data, offset, size=0x1000):
    chunk = data[offset:offset + size]
    if len(chunk) < 64:
        return None
    if chunk[:32] != MAGIC:
        return None

    version = struct.unpack_from("<I", chunk, 32)[0]
    n_sectors = struct.unpack_from("<I", chunk, 36)[0]
    loader_start = struct.unpack_from("<I", chunk, 48)[0]
    loader_count = struct.unpack_from("<I", chunk, 52)[0]

    parts = []
    for i in range(16):
        pos = 64 + i * 20
        if pos + 20 > len(chunk):
            break
        slba, ns, typ, flag, unk, pad = struct.unpack_from("<IIBBHQ", chunk, pos)
        if ns > 0:
            parts.append({
                "start_lba": slba, "n_sectors": ns, "type": typ, "flag": flag,
                "name": PARTITIONS_TYPES.get(typ, f"UNK_{typ}")
            })
    return {"version": version, "n_sectors": n_sectors,
            "loader_start": loader_start, "loader_count": loader_count,
            "partitions": parts}


def _sce_identify(data, offset, size=0x1000):
    chunk = data[offset:offset + size]
    if len(chunk) < size:
        return False
    if is_all_zeros(chunk) or is_all_ff(chunk):
        return False
    return MAGIC in chunk[:0x100]


def _section_occupied(data, offset, size=0x1000):
    chunk = data[offset:offset + size]
    if len(chunk) < size:
        return False
    nz = sum(1 for b in chunk if b not in (0, 0xFF))
    return nz > 32


def _find_donor(data, donors_dir="donors"):
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
                if len(ddata) == 0x2000000 and _section_occupied(ddata, MBR1_OFF):
                    return (result.best.filepath, ddata)
            except Exception:
                pass
    except Exception:
        pass

    # Fallback: original simple scan
    best, best_score = None, -1
    for fname in sorted(os.listdir(donors_dir)):
        if not fname.upper().endswith('.BIN'):
            continue
        path = os.path.join(donors_dir, fname)
        try:
            d = open(path, 'rb').read()
        except Exception:
            continue
        if len(d) != 0x2000000:
            continue
        if not _section_occupied(d, MBR1_OFF):
            continue
        sku = detect_sku(d)
        fw = detect_fw_version(d)
        score = 0
        if sku == target_sku:
            score += 60
        elif sku[:7] == target_sku[:7]:
            score += 30
        if fw == target_fw and fw != "Unknown":
            score += 40
        if score > best_score:
            best_score = score
            best = (path, d)
    return best


def _region_status(data, offset, label):
    if is_all_zeros(data[offset:offset + MBR_SIZE]):
        return f"{label}: ALL ZEROS"
    if is_all_ff(data[offset:offset + MBR_SIZE]):
        return f"{label}: ALL FF"
    parsed = _parse_mbr(data, offset)
    if parsed:
        parts_desc = ", ".join(p["name"] for p in parsed["partitions"][:4])
        return f"{label}: VALID ({len(parsed['partitions'])} partitions: {parts_desc}...)"
    if _sce_identify(data, offset):
        return f"{label}: PARTIAL (magic ok, structure corrupt)"
    nz = sum(1 for b in data[offset:offset + MBR_SIZE] if b not in (0, 0xFF))
    return f"{label}: CORRUPT ({nz} non-zero bytes)"


class MBRGenerator:
    def __init__(self, data, donors_dir="donors"):
        self.data = bytearray(data)
        self.donors_dir = donors_dir
        self.donor_info = None
        self.report = []

    def find_best_donor(self):
        result = _find_donor(self.data, self.donors_dir)
        if result:
            self.donor_info = result
            self.report.append(f"Donor: {os.path.basename(result[0])}")
        else:
            self.report.append("No suitable donor found")
        return self.donor_info is not None

    def _rebuild_from_layout(self, target_offset):
        sector_diff = (target_offset - MBR1_OFF) // BLOCK_SIZE
        is_mbr2 = target_offset == MBR2_OFF
        parts = []
        for p in SLOT0_PARTITIONS:
            adj_lba = p["start_lba"] - sector_diff
            flag = p["flag"]
            if is_mbr2 and p["name"] == "EMC_IPL_A":
                flag = 0x00
            elif is_mbr2 and p["name"] == "EMC_IPL_B":
                flag = 0x01
            parts.append((adj_lba, p["n_sectors"], p["type"], flag, 0, 0))
        loader_start = 0x309 if is_mbr2 else 0x11
        return _pack_mbr(
            version=4,
            n_sectors=0x1000,
            reserved=0,
            loader_start=loader_start,
            loader_count=0x267,
            reserved2=0,
            partitions=parts,
        )

    def _check_emc_ipl_flags(self, parsed_mbr, is_mbr2):
        emc = []
        for p in parsed_mbr["partitions"]:
            if p["type"] == 0x20:
                emc.append(p)
        if len(emc) < 2:
            return "missing emc_ipl partitions"
        flags = [p["flag"] for p in emc]
        expected_high = 0x00 if is_mbr2 else 0x01
        high_count = flags.count(expected_high)
        low_count = flags.count(1 - expected_high)
        if high_count != 1 or low_count != 1:
            return f"wrong emc_ipl flags for {'MBR2' if is_mbr2 else 'MBR1'}: expected one {expected_high} and one {1-expected_high}"
        starts = [p["start_lba"] for p in emc]
        if starts[1] <= starts[0]:
            return "EMC_IPL_B starts before A"
        return None

    def _has_critical_partitions(self, parsed_mbr):
        types_found = set(p["type"] for p in parsed_mbr["partitions"])
        critical = {0x20, 0x21, 0x22, 0x26}
        missing = critical - types_found
        if missing:
            return f"missing partition type(s): {', '.join(hex(t) for t in missing)}"
        return None

    def _mbr_valid(self, parsed):
        if not parsed:
            return False
        flag_err = None
        emc = [p for p in parsed["partitions"] if p["type"] == 0x20]
        if len(emc) >= 2:
            flags = [p["flag"] for p in emc]
            if not (0x00 in flags and 0x01 in flags):
                flag_err = "emc_ipl flags not opposite (need one 0x00 and one 0x01)"
        else:
            flag_err = "missing emc_ipl partitions"
        crit_err = self._has_critical_partitions(parsed)
        return flag_err is None and crit_err is None

    def regenerate(self):
        self.report = []
        mbr1_parsed = _parse_mbr(self.data, MBR1_OFF)
        mbr2_parsed = _parse_mbr(self.data, MBR2_OFF)

        self.report.append(_region_status(self.data, MBR1_OFF, "MBR1"))
        self.report.append(_region_status(self.data, MBR2_OFF, "MBR2"))

        mbr1_ok = self._mbr_valid(mbr1_parsed)
        mbr2_ok = self._mbr_valid(mbr2_parsed)

        for p, label in [(mbr1_parsed, "MBR1"), (mbr2_parsed, "MBR2")]:
            if p:
                for chk, name in [(self._check_emc_ipl_flags(p, is_mbr2=(label == "MBR2")), "flags"),
                                  (self._has_critical_partitions(p), "partitions")]:
                    if chk:
                        self.report.append(f"{label} {name}: {chk}")

        if mbr1_ok and mbr2_ok:
            self.report.append("Both MBR sections valid - no repair needed")
            return False

        if mbr1_ok and not mbr2_ok:
            parts = []
            for p in mbr1_parsed["partitions"]:
                adj_lba = p["start_lba"] - 0x08
                flag = 0x01 - p["flag"] if p["type"] == 0x20 else p["flag"]
                parts.append((adj_lba, p["n_sectors"], p["type"], flag, 0, 0))
            rebuilt = _pack_mbr(
                version=mbr1_parsed["version"],
                n_sectors=mbr1_parsed["n_sectors"],
                reserved=0,
                loader_start=0x309,
                loader_count=mbr1_parsed["loader_count"],
                reserved2=0,
                partitions=parts,
            )
            self.data[MBR2_OFF:MBR2_OFF + MBR_SIZE] = rebuilt
            self.report.append("MBR1 OK, rebuilt -> MBR2 (adjusted for base)")
            return True

        if mbr2_ok and not mbr1_ok:
            parts = []
            for p in mbr2_parsed["partitions"]:
                adj_lba = p["start_lba"] + 0x08
                flag = 0x01 - p["flag"] if p["type"] == 0x20 else p["flag"]
                parts.append((adj_lba, p["n_sectors"], p["type"], flag, 0, 0))
            rebuilt = _pack_mbr(
                version=mbr2_parsed["version"],
                n_sectors=mbr2_parsed["n_sectors"],
                reserved=0,
                loader_start=0x11,
                loader_count=mbr2_parsed["loader_count"],
                reserved2=0,
                partitions=parts,
            )
            self.data[MBR1_OFF:MBR1_OFF + MBR_SIZE] = rebuilt
            self.report.append("MBR2 OK, rebuilt -> MBR1 (adjusted for base)")
            return True

        self.report.append("Both MBR sections corrupt - rebuilding from layout")
        try:
            rebuilt1 = self._rebuild_from_layout(MBR1_OFF)
            rebuilt2 = self._rebuild_from_layout(MBR2_OFF)
            self.data[MBR1_OFF:MBR1_OFF + MBR_SIZE] = rebuilt1
            self.data[MBR2_OFF:MBR2_OFF + MBR_SIZE] = rebuilt2
            self.report.append("MBR rebuilt from known NOR layout")
            return True
        except Exception as e:
            self.report.append(f"Layout rebuild failed: {e}")

        self.report.append("Trying donor fallback...")
        if not self.donor_info and not self.find_best_donor():
            self.report.append("Aborted: no donor available")
            return False

        donor_path, donor_data = self.donor_info
        self.data[MBR1_OFF:MBR1_OFF + MBR_SIZE] = donor_data[MBR1_OFF:MBR1_OFF + MBR_SIZE]
        self.data[MBR2_OFF:MBR2_OFF + MBR_SIZE] = donor_data[MBR2_OFF:MBR2_OFF + MBR_SIZE]
        self.report.append(f"MBR restored from donor {os.path.basename(donor_path)}")
        return True

    def get_data(self):
        return bytes(self.data)

    def get_report(self):
        return "\n".join(self.report)
