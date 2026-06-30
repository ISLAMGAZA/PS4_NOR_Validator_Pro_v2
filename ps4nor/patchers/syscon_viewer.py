import struct


class SysconVolumeViewer:
    SNVS_OFF = 0x60000
    AREA_SIZE = 0x1800
    AREA_COUNT = 9
    FLAT_SIZE = 0x400
    ENTRY_SIZE = 16

    TYPE_NAMES = {
        0x00: "MODE0", 0x01: "MODE1", 0x02: "MODE2", 0x03: "MODE3",
        0x04: "BOOT0", 0x05: "BOOT1", 0x06: "BOOT2", 0x07: "BOOT3",
        0x08: "FW_A", 0x09: "FW_B", 0x0A: "LIC1", 0x0B: "LIC2",
        0x0C: "PRE0", 0x0D: "PRE1", 0x0E: "PRE2", 0x0F: "PRE3",
        0x10: "POST0", 0x11: "POST1", 0x12: "POST2", 0x13: "POST3",
    }

    def __init__(self, data, logger=None):
        self.data = data
        self.log = logger or print

    def _iter_entries(self):
        for area_n in range(self.AREA_COUNT):
            astart = self.SNVS_OFF + 0x800 + area_n * self.AREA_SIZE
            for i in range(self.FLAT_SIZE, self.AREA_SIZE, self.ENTRY_SIZE):
                pos = astart + i
                if pos + self.ENTRY_SIZE > len(self.data):
                    break
                raw = self.data[pos:pos + self.ENTRY_SIZE]
                if raw[0] == 0xA5 and raw[7] == 0xC3:
                    typ = raw[1] | (raw[2] << 8)
                    ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                    data_bytes = bytes(raw[8:16])
                    yield (pos, area_n, typ, ctr, data_bytes)

    def view(self):
        self.log("")
        self.log("=" * 60)
        self.log("  Syscon Volume Viewer")
        self.log("=" * 60)

        snvs_data = self.data[self.SNVS_OFF:self.SNVS_OFF + 0x800]
        if all(b == 0xFF for b in snvs_data):
            self.log("  No SNVS data found (all 0xFF)")
            return

        self.log(f"  SNVS Base: {hex(self.SNVS_OFF)}")
        self.log(f"  SNVS Size: {hex(self.AREA_COUNT * self.AREA_SIZE + 0x800)}")
        self.log(f"  Areas: {self.AREA_COUNT} x {hex(self.AREA_SIZE)}")
        self.log("")

        entries = list(self._iter_entries())
        if not entries:
            self.log("  No valid entries found (magic A5..C3)")
            return

        header = f"  {'Idx':<5} {'Area':<6} {'Type':<7} {'Name':<10} {'Counter':<8} {'Data':<18}"
        self.log(header)
        self.log("  " + "-" * len(header))

        fw_records = []
        i = 0
        while i < len(entries):
            pos, area, typ, ctr, d = entries[i]
            name = self.TYPE_NAMES.get(typ, f"0x{typ:04X}")
            data_hex = d.hex()
            self.log(f"  {i:<5} {area:<6} 0x{typ:04X}  {name:<10} {ctr:<8} {data_hex}")
            if typ in (0x08, 0x09, 0x0A, 0x0B):
                fw_records.append((pos, area, typ, ctr, d))
            i += 1

        self.log("")
        self.log(f"  Total entries: {len(entries)}, FW records: {len(fw_records)}")

        self.log("")
        self.log("  Upgrade Chain:")
        fw_recs_sorted = sorted(fw_records, key=lambda x: x[3])
        for pos, area, typ, ctr, d in fw_recs_sorted:
            name = self.TYPE_NAMES.get(typ, f"0x{typ:04X}")
            self.log(f"    #{ctr:<4} {name:<8} area {area} @ {hex(pos)}")

        debug_off = self.SNVS_OFF + 0x0C3
        if debug_off < len(self.data):
            dv = self.data[debug_off]
            ds = "ENABLED" if dv in (0x85, 0x84) else ("DISABLED" if dv == 0x04 else f"0x{dv:02X}")
            self.log(f"")
            self.log(f"  DEBUG (0x{debug_off:06X}): {ds}")

        self.log("")
