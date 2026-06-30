import os
from ..utils.nor_defs import NOR_LAYOUT, COREOS_SLOTS, CID_REGIONS
from ..utils.helpers import md5_hash, format_size
from ..utils.slb2 import parse_slb2, inspect_slb2


class Extractor:
    def __init__(self, data):
        self.data = data

    SLB2_PARTITIONS = {
        "EMC_IPL_A": (0x004000, 0x064000),
        "EMC_IPL_B": (0x064000, 0x0C4000),
        "EAP_KBL":   (0x0C4000, 0x144000),
        "Torus":     (0x144000, 0x1C4000),
    }

    def extract_by_sections(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        extracted = []
        for name, start, end, desc in NOR_LAYOUT:
            if start >= len(self.data):
                break
            end = min(end, len(self.data))
            chunk = self.data[start:end]
            safe_name = name.replace("/", "_").replace(" ", "_").replace("(", "").replace(")", "")
            fname = f"{safe_name}_{start:06X}-{end:06X}.bin"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, 'wb') as f:
                f.write(chunk)
            extracted.append((fname, len(chunk)))
        return extracted

    def extract_by_file_blocks(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        blocks = []
        offset = 0
        while offset < len(self.data):
            if offset + 16 > len(self.data):
                break
            magic = self.data[offset:offset + 4]
            try:
                magic_str = magic.decode('ascii', errors='replace')
            except:
                magic_str = repr(magic)

            if magic in [b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF']:
                offset += 0x1000
                continue

            if offset + 0x1000 > len(self.data):
                break

            chunk = self.data[offset:offset + 0x1000]
            fname = f"block_{offset:06X}_{magic_str}.bin"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, 'wb') as f:
                f.write(chunk)
            blocks.append((fname, len(chunk)))
            offset += 0x1000

        return blocks

    def extract_coreos(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        extracted = []
        for i, (start, end) in enumerate(COREOS_SLOTS):
            if start >= len(self.data):
                break
            end = min(end, len(self.data))
            chunk = self.data[start:end]
            fname = f"CoreOS_Slot{i}_{start:06X}-{end:06X}.bin"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, 'wb') as f:
                f.write(chunk)
            extracted.append((fname, len(chunk)))
        return extracted

    def extract_cid_areas(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        extracted = []
        for name, (start, end) in CID_REGIONS.items():
            if start >= len(self.data):
                continue
            end = min(end, len(self.data))
            chunk = self.data[start:end]
            fname = f"CID_{name}_{start:06X}-{end:06X}.bin"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, 'wb') as f:
                f.write(chunk)
            extracted.append((fname, len(chunk)))
        return extracted

    def extract_slb2_entries(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        extracted = []
        for pname, (start, end) in self.SLB2_PARTITIONS.items():
            chunk = self.data[start:end]
            if len(chunk) < 32 or chunk[:4] != b"SLB2":
                fname = f"{pname}_raw_{start:06X}-{end:06X}.bin"
                fpath = os.path.join(output_dir, fname)
                with open(fpath, 'wb') as f:
                    f.write(chunk)
                extracted.append((fname, len(chunk), "RAW"))
                continue
            try:
                hdr = parse_slb2(chunk)
            except ValueError:
                fname = f"{pname}_raw_{start:06X}-{end:06X}.bin"
                fpath = os.path.join(output_dir, fname)
                with open(fpath, 'wb') as f:
                    f.write(chunk)
                extracted.append((fname, len(chunk), "RAW"))
                continue
            for i, e in enumerate(hdr.entries):
                data_entry = hdr.extract(chunk, i)
                safe = e.name.replace('\x00', '').strip() or f"entry_{i}"
                fname = f"{pname}_{safe}_{i}_{start:06X}.bin"
                fpath = os.path.join(output_dir, fname)
                with open(fpath, 'wb') as f:
                    f.write(data_entry)
                extracted.append((fname, len(data_entry), "SLB2"))
        return extracted

    def inspect_slb2_partitions(self):
        lines = []
        for pname, (start, end) in self.SLB2_PARTITIONS.items():
            chunk = self.data[start:end]
            lines.append(f"--- {pname} (0x{start:06X}-0x{end:06X}) ---")
            if len(chunk) >= 32 and chunk[:4] == b"SLB2":
                lines.append(inspect_slb2(chunk))
            else:
                lines.append("  Not an SLB2 container")
            lines.append("")
        return "\n".join(lines)
