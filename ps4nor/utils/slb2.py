"""
SLB2 container parser for PS4 NOR firmware blobs.
Based on PSDevWiki structure:
  struct SceSlb2Header (32 bytes) + SceSlb2Entry (48 bytes each)
"""
import struct

SLB2_MAGIC = b"SLB2"
SECTOR_SIZE = 0x200

SLB2_ENTRY_STRUCT = struct.Struct("<IIII32s")

class Slb2Entry:
    __slots__ = ("sector_start", "size", "name")
    def __init__(self, sector_start, size, name):
        self.sector_start = sector_start
        self.size = size
        self.name = name

    def __repr__(self):
        return f"Slb2Entry({self.name}, sector={self.sector_start}, size=0x{self.size:X})"

class Slb2Header:
    __slots__ = ("version", "flags", "entry_count", "size_in_sectors", "entries")
    def __init__(self, version, flags, entry_count, size_in_sectors, entries):
        self.version = version
        self.flags = flags
        self.entry_count = entry_count
        self.size_in_sectors = size_in_sectors
        self.entries = entries

    @property
    def total_size(self):
        return self.size_in_sectors * SECTOR_SIZE

    def file_info(self, index):
        """Return (offset, size, name) for entry at index."""
        e = self.entries[index]
        return e.sector_start * SECTOR_SIZE, e.size, e.name

    def extract(self, data, index):
        """Extract entry data from raw SLB2 blob."""
        offset, size, _ = self.file_info(index)
        return data[offset:offset + size]

    def __repr__(self):
        return (f"Slb2Header(ver={self.version}, entries={self.entry_count}, "
                f"sectors={self.size_in_sectors}, total=0x{self.total_size:X})")


def parse_slb2(data):
    if len(data) < 32:
        raise ValueError("Too small for SLB2 header")
    if data[:4] != SLB2_MAGIC:
        raise ValueError(f"Not an SLB2 container (magic: {data[:4]!r})")

    magic, version, flags, entry_count, size_in_sectors = struct.unpack_from("<IIIlI", data, 0)
    entries = []
    off = 32
    for _ in range(entry_count):
        sec_start, fsize, _, _, raw_name = SLB2_ENTRY_STRUCT.unpack_from(data, off)
        name = raw_name.rstrip(b'\x00').decode("ascii", errors="replace")
        entries.append(Slb2Entry(sec_start, fsize, name))
        off += 48
    return Slb2Header(version, flags, entry_count, size_in_sectors, entries)


def extract_slb2(data, name_filter=None):
    hdr = parse_slb2(data)
    results = {}
    for i, e in enumerate(hdr.entries):
        if name_filter and e.name != name_filter:
            continue
        results[e.name] = hdr.extract(data, i)
    return results


def disassemble_slb2(data, out_dir):
    import os
    hdr = parse_slb2(data)
    os.makedirs(out_dir, exist_ok=True)
    for e in hdr.entries:
        blob = hdr.extract(data, hdr.entries.index(e))
        safe_name = e.name.replace('\x00', '').strip()
        path = os.path.join(out_dir, safe_name) if safe_name else os.path.join(out_dir, f"entry_{hdr.entries.index(e)}")
        with open(path, 'wb') as f:
            f.write(blob)
    return hdr


def inspect_slb2(data):
    try:
        hdr = parse_slb2(data)
    except ValueError:
        return "Not an SLB2 container"
    lines = [
        f"SLB2 Container",
        f"  Version:   {hdr.version}",
        f"  Flags:     0x{hdr.flags:08X}",
        f"  Entries:   {hdr.entry_count}",
        f"  Size:      {hdr.size_in_sectors} sectors ({hdr.total_size} bytes)",
    ]
    for i, e in enumerate(hdr.entries):
        off = e.sector_start * SECTOR_SIZE
        lines.append(f"    [{i}] {e.name}: offset=0x{off:X} size=0x{e.size:X}")
    return "\n".join(lines)
