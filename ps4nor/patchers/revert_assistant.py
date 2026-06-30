import os
from ..utils.helpers import detect_fw_version, detect_fw_per_slot, entropy, decode_nvs_fw
from ..utils.fw_db import ranges_are_distinct, fw_to_int, EMC_IPL_MD5, SWITCH_BLOBS, get_slot_switch_info
from ..utils.nor_defs import UART_OFFSET, UART_BACKUP_OFFSET
from .syscon_patcher import SysconSNVSPatcher


class RevertAssistant:
    ACT_SLOT = 0x1000
    CORE_SWCH = 0x201000

    EMC_IPL_A = (0x004000, 0x064000)
    EMC_IPL_B = (0x064000, 0x0C4000)
    COREOS_A = (0x3C0000, 0x1080000)
    COREOS_B = (0x1080000, 0x1D40000)

    SYSCON_SIZE = 0x40000

    def __init__(self, nor_data, syscon_data):
        self.nor = nor_data
        self.syscon = syscon_data
        self.analysis = {}
        self.slot_fw = {}
        self.snvs = SysconSNVSPatcher(syscon_data)

    def analyze_nor(self):
        act_slot = self.nor[self.ACT_SLOT] if len(self.nor) > self.ACT_SLOT else 0xFF
        core_swch = self.nor[self.CORE_SWCH:self.CORE_SWCH + 16] if len(self.nor) > self.CORE_SWCH + 16 else b''
        swch_name = get_slot_switch_info(self.nor)

        ipl_a = self.nor[self.EMC_IPL_A[0]:self.EMC_IPL_A[1]]
        ipl_b = self.nor[self.EMC_IPL_B[0]:self.EMC_IPL_B[1]]
        ipl_a_ok = not (all(b == 0 for b in ipl_a) or all(b == 0xFF for b in ipl_a))
        ipl_b_ok = not (all(b == 0 for b in ipl_b) or all(b == 0xFF for b in ipl_b))

        fw_current = detect_fw_version(self.nor)
        self.slot_fw = detect_fw_per_slot(self.nor)

        coreos_a_empty = self._region_empty(*self.COREOS_A)
        coreos_b_empty = self._region_empty(*self.COREOS_B)

        self.analysis = {
            "act_slot_byte": act_slot,
            "act_slot": "A" if act_slot == 0x00 else ("B" if act_slot == 0x80 else "?"),
            "core_swch": list(core_swch),
            "core_swch_name": swch_name,
            "ipl_a_ok": ipl_a_ok,
            "ipl_b_ok": ipl_b_ok,
            "fw_current": fw_current,
            "fw_current_nvs": decode_nvs_fw(self.nor),
            "fw_a_md5_min": self.slot_fw["slot_A"]["min"],
            "fw_a_md5_max": self.slot_fw["slot_A"]["max"],
            "fw_b_md5_min": self.slot_fw["slot_B"]["min"],
            "fw_b_md5_max": self.slot_fw["slot_B"]["max"],
            "fw_a_md5": self.slot_fw["slot_A"]["md5"],
            "fw_b_md5": self.slot_fw["slot_B"]["md5"],
            "use_md5_detection": self.slot_fw["slot_A"]["min"] is not None or self.slot_fw["slot_B"]["min"] is not None,
            "coreos_a_empty": coreos_a_empty,
            "coreos_b_empty": coreos_b_empty,
        }
        return self.analysis

    def _region_empty(self, start, end):
        data = self.nor[start:min(end, len(self.nor))]
        return all(b == 0 for b in data) or all(b == 0xFF for b in data)

    def _find_opposite_switch_pattern(self):
        current = list(self.nor[self.CORE_SWCH:self.CORE_SWCH + 16])
        if len(current) != 16:
            return [0xFF] * 16
        for i in range(0, len(SWITCH_BLOBS), 2):
            if i + 1 < len(SWITCH_BLOBS):
                if SWITCH_BLOBS[i]['v'] == current:
                    return SWITCH_BLOBS[i + 1]['v']
                if SWITCH_BLOBS[i + 1]['v'] == current:
                    return SWITCH_BLOBS[i]['v']
        return [0xFF] * 16

    def analyze_syscon(self):
        snvs_info = self.snvs.analyze_snvs()
        info = {
            "size_valid": len(self.syscon) == self.SYSCON_SIZE,
            "size": len(self.syscon),
            "entropy": entropy(self.syscon),
            "total_entries": snvs_info["total_entries"],
            "fw_record_count": snvs_info["fw_record_count"],
            "last_fw_record": snvs_info["last_fw"],
        }
        return info

    def _target_higher_slot(self):
        s = self.analysis
        range_a = (s["fw_a_md5_min"], s["fw_a_md5_max"])
        range_b = (s["fw_b_md5_min"], s["fw_b_md5_max"])
        if range_a[0] and range_b[0]:
            relation = ranges_are_distinct(range_a, range_b)
            if relation == "A_lower":
                return "B"
            if relation == "B_lower":
                return "A"
        if s["coreos_a_empty"] and not s["coreos_b_empty"]:
            return "B"
        if s["coreos_b_empty"] and not s["coreos_a_empty"]:
            return "A"
        return "B"

    def _enable_uart(self, result):
        if UART_OFFSET < len(result):
            result[UART_OFFSET] = 0x01
        bk = UART_OFFSET + UART_BACKUP_OFFSET
        if bk < len(result):
            result[bk] = 0x01

    def patch_nor(self, enable_uart=True):
        """CORE_SWCH pattern flip only (clean swap). No CoreOS corruption needed."""
        result = bytearray(self.nor)
        new_pattern = self._find_opposite_switch_pattern()
        result[self.CORE_SWCH:self.CORE_SWCH + 16] = bytes(new_pattern)
        if enable_uart:
            self._enable_uart(result)
        return bytes(result)

    def patch_syscon(self):
        self.snvs = SysconSNVSPatcher(self.syscon)
        return self.snvs.remove_last_fw_record()

    def generate_report(self, include_snvs=True):
        nor_info = self.analysis
        syscon_info = self.analyze_syscon()
        lines = []

        lines.append("Revert Assistant Report")
        lines.append("=" * 40)
        lines.append("")
        lines.append("NOR Analysis:")
        lines.append(f"  ACT_SLOT indicator @0x1000: {nor_info['act_slot']} (0x{nor_info['act_slot_byte']:02X})")
        lines.append(f"  CORE_SWCH @0x201000: {nor_info['core_swch_name']}")
        lines.append(f"  IPL A: {'OK' if nor_info['ipl_a_ok'] else 'EMPTY'}")
        lines.append(f"  IPL B: {'OK' if nor_info['ipl_b_ok'] else 'EMPTY'}")
        lines.append(f"  CoreOS A: {'has data' if not nor_info['coreos_a_empty'] else 'EMPTY'}")
        lines.append(f"  CoreOS B: {'has data' if not nor_info['coreos_b_empty'] else 'EMPTY'}")
        lines.append(f"  FW (NVS): {nor_info['fw_current_nvs'] or 'unset/0xFF'}")
        lines.append(f"  FW (detected): {nor_info['fw_current']}")

        if nor_info["use_md5_detection"]:
            fw_a_min = nor_info["fw_a_md5_min"] or "?"
            fw_a_max = nor_info["fw_a_md5_max"] or "?"
            fw_b_min = nor_info["fw_b_md5_min"] or "?"
            fw_b_max = nor_info["fw_b_md5_max"] or "?"
            same_range = (fw_a_min == fw_b_min and fw_a_max == fw_b_max)
            if same_range:
                if fw_a_min == fw_a_max:
                    lines.append(f"  EMC_IPL: both slots = FW {fw_a_min}")
                else:
                    lines.append(f"  EMC_IPL: both slots = FW {fw_a_min}-{fw_a_max}")
            else:
                lines.append(f"  EMC_IPL slot A: FW {fw_a_min}-{fw_a_max}")
                lines.append(f"  EMC_IPL slot B: FW {fw_b_min}-{fw_b_max}")
            target = self._target_higher_slot()
            lines.append(f"  Intelligent target: CoreOS_{target} (higher FW range)")

        if nor_info.get("coreos_b_empty", True) and nor_info.get("coreos_a_empty", True):
            lines.append("  WARNING: Both CoreOS slots appear empty!")

        nvs_fw = nor_info['fw_current_nvs']
        emc_min = nor_info['fw_a_md5_min'] or nor_info['fw_b_md5_min']
        if nvs_fw and emc_min and nvs_fw != emc_min:
            if emc_min not in nvs_fw and nvs_fw not in emc_min:
                lines.append(f"  NOTE: NVS FW ({nvs_fw}) != EMC_IPL FW ({emc_min}+)")

        lines.append("")
        lines.append("Syscon SNVS Analysis:")
        lines.append(f"  Total entries: {syscon_info['total_entries']}")
        lines.append(f"  FW records: {syscon_info['fw_record_count']}")
        last = syscon_info['last_fw_record']
        if last:
            lines.append(f"  Last FW record @{hex(last['fw_a'][0])}:")
            lines.append(f"    FW_A ctr={last['fw_a'][2]} data={last['fw_a'][3].hex()}")
            lines.append(f"    FW_B ctr={last['fw_b'][2]} data={last['fw_b'][3].hex()}")
        lines.append("")
        lines.append("Patch plan:")
        lines.append("  NOR:")
        lines.append("    - CORE_SWCH pattern flipped at 0x201000")
        lines.append("    - UART enabled at 0x1C931F")
        lines.append("  Syscon:")
        lines.append(f"    - Last FW record removed from SNVS ({'present' if last else 'N/A'})")
        lines.append("")
        lines.append("CORE_SWCH flipped (clean swap). Syscon SNVS cleaned.")
        lines.append("PS4 should boot the opposite CoreOS slot.")
        return "\n".join(lines)
