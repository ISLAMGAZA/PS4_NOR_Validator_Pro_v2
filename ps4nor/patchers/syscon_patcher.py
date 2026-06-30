import struct


SNVS_OFF = 0x60000
AREA_SIZE = 0x1800
AREA_COUNT = 9
ENTRY_SIZE = 16
FLAT_SIZE = 0x400

FW_TYPES = (0x08, 0x09, 0x0A, 0x0B)  # FW_A, FW_B, LIC1, LIC2


class SysconSNVSPatcher:
    def __init__(self, syscon_data):
        self.data = bytearray(syscon_data)

    def _area_start(self, n):
        return SNVS_OFF + 0x800 + n * AREA_SIZE

    def _iter_entries(self, data):
        for area_n in range(AREA_COUNT):
            astart = self._area_start(area_n)
            flat_area = bytes(data[astart:astart + FLAT_SIZE])
            for i in range(FLAT_SIZE, AREA_SIZE, ENTRY_SIZE):
                pos = astart + i
                if pos + ENTRY_SIZE > len(data):
                    break
                raw = bytes(data[pos:pos + ENTRY_SIZE])
                if raw[0] == 0xA5 and raw[7] == 0xC3:
                    typ = raw[1] | (raw[2] << 8)
                    ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                    yield (pos, typ, ctr, bytes(raw[8:16]))

    def find_all_entries(self):
        entries = []
        for pos, typ, ctr, d in self._iter_entries(self.data):
            entries.append((pos, typ, ctr, d))
        return entries

    def find_fw_records(self):
        entries = self.find_all_entries()
        records = []
        i = 0
        while i < len(entries):
            pos, typ, ctr, d = entries[i]
            if typ == 0x08:
                if (i + 3 < len(entries) and
                    entries[i + 1][1] == 0x09 and
                    entries[i + 2][1] == 0x0A and
                    entries[i + 3][1] == 0x0B):
                    if (entries[i + 1][0] - entries[i][0] == ENTRY_SIZE and
                        entries[i + 2][0] - entries[i + 1][0] == ENTRY_SIZE and
                        entries[i + 3][0] - entries[i + 2][0] == ENTRY_SIZE):
                        records.append({
                            'fw_a': entries[i],
                            'fw_b': entries[i + 1],
                            'lic1': entries[i + 2],
                            'lic2': entries[i + 3],
                        })
                        i += 4
                        continue
            i += 1
        return records

    def remove_last_fw_record(self):
        records = self.find_fw_records()
        if len(records) < 2:
            return bytes(self.data)

        last = records[-1]
        fwa_pos = last['fw_a'][0]

        area_offset = fwa_pos - SNVS_OFF
        area_n = (area_offset - 0x800) // AREA_SIZE
        astart = self._area_start(area_n)

        for entry in [last['fw_a'], last['fw_b'], last['lic1'], last['lic2']]:
            pos = entry[0]
            if pos + ENTRY_SIZE <= len(self.data):
                self.data[pos:pos + ENTRY_SIZE] = b'\xFF' * ENTRY_SIZE

        new_last_fwa = records[-2]['fw_a']
        new_last_fwb = records[-2]['fw_b']

        flat_fwa_off = astart + 0x08 * 8
        flat_fwb_off = astart + 0x09 * 8
        if flat_fwa_off + 8 <= len(self.data):
            self.data[flat_fwa_off:flat_fwa_off + 8] = new_last_fwa[3]
        if flat_fwb_off + 8 <= len(self.data):
            self.data[flat_fwb_off:flat_fwb_off + 8] = new_last_fwb[3]

        return bytes(self.data)

    def rebuild_snvs(self):
        from copy import deepcopy
        flat_size = 0x400
        entry_size = 16
        area_size = 0x1800
        area_count = 9

        all_entries = []
        flat_areas = []

        for area_n in range(area_count):
            astart = SNVS_OFF + 0x800 + area_n * area_size
            flat = bytes(self.data[astart:astart + flat_size])
            flat_areas.append(flat)
            entries = []
            for i in range(flat_size, area_size, entry_size):
                pos = astart + i
                raw = bytes(self.data[pos:pos + entry_size])
                if raw[0] == 0xA5 and raw[7] == 0xC3:
                    entries.append(raw)
            all_entries.append(entries)

        max_entries = max(len(e) for e in all_entries)
        if max_entries == 0:
            return None, "No valid entries found - cannot rebuild"

        header = b'\xA5\x00\x00\xFF\xFF\xFF\xFF\xC3'
        data = b''
        for area_n in range(area_count):
            flat = flat_areas[area_n] if area_n < len(flat_areas) else b'\xFF' * flat_size
            if len(flat) < flat_size:
                flat += b'\xFF' * (flat_size - len(flat))
            data += flat

            entries = all_entries[area_n] if area_n < len(all_entries) else []
            for n, raw in enumerate(entries):
                entry = bytearray(raw)
                entry[3] = (n + 1) & 0xFF
                entry[4] = ((n + 1) >> 8) & 0xFF
                entry[5] = ((n + 1) >> 16) & 0xFF
                entry[6] = area_n
                data += bytes(entry)

            if not entries:
                continue

            first = bytearray(entries[0])
            first[3] = 1
            first[4] = 0
            first[5] = 0
            first[6] = area_n
            first[14] = area_n
            first[15] = area_n
            header += bytes(first[:14])

        hsize = 8 + area_count * 14
        if len(header) < hsize:
            header += b'\xFF' * (hsize - len(header))

        dsize = area_count * area_size
        if len(data) < dsize:
            data += b'\xFF' * (dsize - len(data))

        rebuilt = bytearray(self.data)
        rebuilt[SNVS_OFF + 0x800 - 0x800:SNVS_OFF + 0x800 - 0x800 + len(header)] = header
        rebuilt[SNVS_OFF + 0x800:SNVS_OFF + 0x800 + len(data)] = data[:dsize]

        return bytes(rebuilt), None

    def analyze_snvs(self):
        entries = self.find_all_entries()
        records = self.find_fw_records()
        type_counts = {}
        for _, typ, _, _ in entries:
            type_counts[typ] = type_counts.get(typ, 0) + 1
        return {
            "total_entries": len(entries),
            "fw_record_count": len(records),
            "type_counts": type_counts,
            "last_fw": records[-1] if records else None,
        }
