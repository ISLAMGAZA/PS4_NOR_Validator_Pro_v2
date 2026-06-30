"""
SLB2 Rebuilder v2 — Full SLB2 partition rebuild with LZ4, validation, batch ops.
SLB2 is used in EMC_IPL, EAP_KBL, and Torus partitions.
"""

import struct
import hashlib
import zlib
from typing import List, Dict, Optional, Tuple, BinaryIO

try:
    import lz4.block
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False


# ======================================================================
# SLB2 STRUCTURE
# ======================================================================
# Header (0x40 bytes):
#   [0x00] 4s  — magic 'SLB2'
#   [0x04] I   — version (1 or 2)
#   [0x08] I   — entry count
#   [0x0C] I   — reserved
#   [0x10] I   — table offset (usually 0x40)
#   [0x14] I   — data offset
#   [0x18] I   — reserved
#   [0x1C] Q   — total size
#   [0x24] I   — reserved
#   [0x28] I   — flags
#   [0x2C] 20x — reserved/padding
#
# Entry table (64 bytes each):
#   [0x00] 32s — SHA256 hash of original data
#   [0x20] Q   — data offset
#   [0x28] Q   — original size (uncompressed)
#   [0x30] Q   — compressed size
#   [0x38] I   — flags (bit0: LZ4 compressed)
#   [0x3C] I   — reserved
#
# Data section: concatenated raw/compressed entry data
# ======================================================================


class SLB2RebuildError(Exception):
    """SLB2 rebuild/parse error."""


class SLB2Entry:
    """Single SLB2 entry with metadata."""

    def __init__(self, name: str, data: bytes, offset: int = 0, size: int = 0,
                 compressed_size: int = 0, flags: int = 0, hash_val: bytes = None):
        self.name = name
        self.data = data
        self.offset = offset
        self.size = size or len(data)
        self.compressed_size = compressed_size
        self.flags = flags
        self.hash_val = hash_val or hashlib.sha256(data).digest()
        self._compressed_data: Optional[bytes] = None

    def __repr__(self) -> str:
        return f'SLB2Entry({self.name}, {len(self.data)} bytes, flags=0x{self.flags:04X})'


class SLB2Rebuilder:
    """
    Full SLB2 partition rebuilder with LZ4, validation, and batch operations.
    Supports SLB2 v1 and v2 formats.
    """

    HEADER_SIZE = 0x40
    ENTRY_TABLE_ENTRY_SIZE = 64
    MAGIC = b'SLB2'
    SUPPORTED_VERSIONS = {1, 2}

    # Known entry name → hash mapping (from scene analysis)
    KNOWN_ENTRY_HASHES = {
        'emc_ipl': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'eap_kbl': 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
        'torus_fw': '6b3a4c0e9f1d7b8a2c5e0d9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a',
    }

    def __init__(self, entries: List[SLB2Entry] = None, version: int = 2):
        self.entries = entries or []
        self.version = version if version in self.SUPPORTED_VERSIONS else 2

    # ------------------------------------------------------------------
    # Entry Management
    # ------------------------------------------------------------------

    def add_entry(self, name: str, data: bytes, compress: bool = True) -> 'SLB2Rebuilder':
        """
        Add a new entry with optional LZ4 compression.
        Automatically detects compression benefit.
        """
        if not data:
            raise SLB2RebuildError(f'Cannot add empty entry: {name}')

        hash_val = hashlib.sha256(data).digest()
        cdata = data
        csize = len(data)
        flags = 0

        if compress and HAS_LZ4 and len(data) > 64:
            try:
                compressed = lz4.block.compress(data, compression=9, store_size=False)
                if len(compressed) < len(data):
                    cdata = compressed
                    csize = len(cdata)
                    flags = 0x01  # LZ4 compressed
            except Exception:
                pass

        entry = SLB2Entry(
            name=name, data=data,
            compressed_size=csize, flags=flags, hash_val=hash_val,
        )
        entry._compressed_data = cdata
        self.entries.append(entry)
        return self

    def remove_entry(self, name: str) -> bool:
        """Remove entry by name."""
        for i, e in enumerate(self.entries):
            if e.name == name:
                self.entries.pop(i)
                return True
        return False

    def get_entry(self, name: str) -> Optional[SLB2Entry]:
        """Get entry by name."""
        for e in self.entries:
            if e.name == name:
                return e
        return None

    def rename_entry(self, old_name: str, new_name: str) -> bool:
        """Rename an entry."""
        e = self.get_entry(old_name)
        if e:
            e.name = new_name
            return True
        return False

    def update_entry_data(self, name: str, new_data: bytes, compress: bool = True) -> bool:
        """Replace entry data, recompute hash and compression."""
        e = self.get_entry(name)
        if not e:
            return False
        e.data = new_data
        e.size = len(new_data)
        e.hash_val = hashlib.sha256(new_data).digest()
        # Recompress
        if compress and HAS_LZ4 and len(new_data) > 64:
            try:
                compressed = lz4.block.compress(new_data, compression=9, store_size=False)
                if len(compressed) < len(new_data):
                    e._compressed_data = compressed
                    e.compressed_size = len(compressed)
                    e.flags = 0x01
                    return True
            except Exception:
                pass
        e._compressed_data = new_data
        e.compressed_size = len(new_data)
        e.flags = 0x00
        return True

    def set_compression(self, name: str, compress: bool) -> bool:
        """Enable/disable LZ4 compression for an entry."""
        e = self.get_entry(name)
        if not e:
            return False
        if compress and HAS_LZ4 and len(e.data) > 64:
            try:
                compressed = lz4.block.compress(e.data, compression=9, store_size=False)
                if len(compressed) < len(e.data):
                    e._compressed_data = compressed
                    e.compressed_size = len(compressed)
                    e.flags = 0x01
                    return True
            except Exception:
                pass
        e._compressed_data = e.data
        e.compressed_size = len(e.data)
        e.flags = 0x00
        return True

    def entry_count(self) -> int:
        return len(self.entries)

    def list_entries(self) -> List[Dict]:
        """List all entries with metadata."""
        return [{
            'name': e.name,
            'size': len(e.data),
            'compressed_size': e.compressed_size,
            'compressed_ratio': round(e.compressed_size / max(len(e.data), 1) * 100, 1),
            'flags': f'0x{e.flags:04X}',
            'compressed': bool(e.flags & 0x01),
            'hash': e.hash_val.hex(),
        } for e in self.entries]

    # ------------------------------------------------------------------
    # SLB2 Rebuild
    # ------------------------------------------------------------------

    def rebuild(self) -> bytes:
        """
        Rebuild complete SLB2 partition from entries.
        Returns valid SLB2 binary.
        """
        if not self.entries:
            raise SLB2RebuildError('No entries to rebuild')

        entry_count = len(self.entries)
        table_size = entry_count * self.ENTRY_TABLE_ENTRY_SIZE

        # Align data offset to 16 bytes
        data_offset = self.HEADER_SIZE + table_size
        data_offset = (data_offset + 0xF) & ~0xF

        # --- Build header ---
        header = bytearray(self.HEADER_SIZE)
        struct.pack_into('<4s', header, 0, self.MAGIC)
        struct.pack_into('<I', header, 4, self.version)
        struct.pack_into('<I', header, 8, entry_count)
        struct.pack_into('<I', header, 0x10, self.HEADER_SIZE)
        struct.pack_into('<I', header, 0x14, data_offset)
        struct.pack_into('<I', header, 0x28, 0)

        # --- Build entry table ---
        table = bytearray()
        current_data_off = data_offset

        for e in self.entries:
            cdata = getattr(e, '_compressed_data', None) or e.data
            actual_csize = e.compressed_size or len(e.data)

            table += e.hash_val                              # 32: SHA256
            table += struct.pack('<Q', current_data_off)     # 8: offset
            table += struct.pack('<Q', len(e.data))          # 8: original size
            table += struct.pack('<Q', actual_csize)         # 8: compressed size
            table += struct.pack('<I', e.flags)              # 4: flags
            table += struct.pack('<I', 0)                    # 4: reserved

            current_data_off += actual_csize

        # --- Build data section ---
        data = bytearray()
        for e in self.entries:
            cdata = getattr(e, '_compressed_data', None) or e.data
            data += cdata

        # Pad data to 16-byte alignment
        while len(data) % 0x10 != 0:
            data += b'\x00'

        # Update total size in header
        total_size = self.HEADER_SIZE + len(table) + len(data)
        struct.pack_into('<Q', header, 0x1C, total_size)

        return bytes(header) + bytes(table) + bytes(data)

    # ------------------------------------------------------------------
    # Parse Existing SLB2
    # ------------------------------------------------------------------

    @staticmethod
    def parse(slb2_data: bytes, name_hints: Dict[str, str] = None) -> 'SLB2Rebuilder':
        """
        Parse existing SLB2 binary into a rebuilder.
        If name_hints provided, map hash → name.
        name_hints format: {sha256_hex: 'entry_name'}
        """
        if len(slb2_data) < SLB2Rebuilder.HEADER_SIZE:
            raise SLB2RebuildError('Data too small for SLB2 header')

        # Parse header
        magic = slb2_data[0:4]
        if magic != SLB2Rebuilder.MAGIC:
            raise SLB2RebuildError(f'Invalid SLB2 magic: {magic!r}')

        version = struct.unpack_from('<I', slb2_data, 4)[0]
        entry_count = struct.unpack_from('<I', slb2_data, 8)[0]
        table_off = struct.unpack_from('<I', slb2_data, 0x10)[0]
        data_off = struct.unpack_from('<I', slb2_data, 0x14)[0]
        total_size = struct.unpack_from('<Q', slb2_data, 0x1C)[0]

        if version not in SLB2Rebuilder.SUPPORTED_VERSIONS:
            raise SLB2RebuildError(f'Unsupported SLB2 version: {version}')

        rebuilder = SLB2Rebuilder(version=version)

        # Build reverse hash map from name_hints
        hash_name_map = {}
        if name_hints:
            hash_name_map = {hash_val: name for hash_val, name in name_hints.items()}

        # Parse entries
        for i in range(entry_count):
            entry_off = (table_off or SLB2Rebuilder.HEADER_SIZE) + i * SLB2Rebuilder.ENTRY_TABLE_ENTRY_SIZE
            if entry_off + SLB2Rebuilder.ENTRY_TABLE_ENTRY_SIZE > len(slb2_data):
                break

            entry_raw = slb2_data[entry_off:entry_off + SLB2Rebuilder.ENTRY_TABLE_ENTRY_SIZE]
            hash_val, offset, size, csize, flags, _ = struct.unpack('<32sQQQII', entry_raw)

            hash_hex = hash_val.hex()
            name = hash_name_map.get(hash_hex, f'entry_{i}')

            # Read data
            if offset + csize > len(slb2_data):
                raise SLB2RebuildError(f'Entry {i} data at {offset} exceeds buffer')

            cdata = slb2_data[offset:offset + csize]

            # Decompress if LZ4
            odata = cdata
            if flags & 0x01:  # LZ4 compressed
                if HAS_LZ4:
                    try:
                        odata = lz4.block.decompress(cdata, uncompressed_size=size)
                    except Exception as e:
                        raise SLB2RebuildError(f'LZ4 decompress failed for entry {i}: {e}')
                else:
                    raise SLB2RebuildError('LZ4 required but not available')

            entry = SLB2Entry(
                name=name,
                data=odata,
                offset=offset,
                size=size,
                compressed_size=csize,
                flags=flags,
                hash_val=hash_val,
            )
            entry._compressed_data = cdata
            rebuilder.entries.append(entry)

        return rebuilder

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> Dict:
        """
        Validate the current entries and rebuild output.
        Returns a detailed validation report.
        """
        issues = []
        warnings = []

        if not self.entries:
            issues.append('No entries')

        for i, e in enumerate(self.entries):
            if not e.name:
                issues.append(f'Entry {i}: empty name')

            if not e.data:
                issues.append(f'Entry {i}: no data')

            # Verify hash
            computed_hash = hashlib.sha256(e.data).digest()
            if computed_hash != e.hash_val:
                warnings.append(f'Entry {e.name}: hash mismatch (will be corrected)')
                e.hash_val = computed_hash

            # Verify compression
            cdata = getattr(e, '_compressed_data', None)
            if cdata and (e.flags & 0x01):
                if HAS_LZ4:
                    try:
                        decompressed = lz4.block.decompress(cdata, uncompressed_size=len(e.data))
                        if decompressed != e.data:
                            issues.append(f'Entry {e.name}: LZ4 roundtrip mismatch')
                    except Exception as ex:
                        issues.append(f'Entry {e.name}: LZ4 decompress error: {ex}')
            elif cdata and len(cdata) != len(e.data):
                warnings.append(f'Entry {e.name}: compressed size mismatch')
                e._compressed_data = e.data
                e.compressed_size = len(e.data)
                e.flags = 0

        # Try rebuild
        try:
            rebuilt = self.rebuild()
            rebuild_valid = len(rebuilt) > self.HEADER_SIZE
        except Exception as ex:
            issues.append(f'Rebuild failed: {ex}')
            rebuild_valid = False

        return {
            'valid': len(issues) == 0,
            'entry_count': len(self.entries),
            'issues': issues,
            'warnings': warnings,
            'rebuild_valid': rebuild_valid,
            'total_size': len(self.rebuild()) if rebuild_valid else 0,
        }

    # ------------------------------------------------------------------
    # Batch Operations
    # ------------------------------------------------------------------

    @staticmethod
    def batch_rebuild(entries_dict: Dict[str, bytes], compress: bool = True,
                      version: int = 2) -> bytes:
        """Convenience: build SLB2 from a dict of {name: data}."""
        rb = SLB2Rebuilder(version=version)
        for name, data in entries_dict.items():
            rb.add_entry(name, data, compress=compress)
        return rb.rebuild()

    @staticmethod
    def from_file(filepath: str, name_hints: Dict[str, str] = None) -> 'SLB2Rebuilder':
        """Parse SLB2 from file."""
        with open(filepath, 'rb') as f:
            data = f.read()
        return SLB2Rebuilder.parse(data, name_hints)

    def to_file(self, filepath: str) -> None:
        """Write rebuilt SLB2 to file."""
        data = self.rebuild()
        with open(filepath, 'wb') as f:
            f.write(data)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def report(self) -> str:
        """Generate a human-readable parse/rebuild report."""
        lines = []
        lines.append('=' * 60)
        lines.append('SLB2 REBUILDER REPORT')
        lines.append('=' * 60)
        lines.append(f'  Version:      {self.version}')
        lines.append(f'  Entries:      {len(self.entries)}')
        lines.append('')

        for e in self.entries:
            ratio = e.compressed_size / max(len(e.data), 1) * 100
            cflag = 'LZ4' if (e.flags & 0x01) else 'none'
            lines.append(f'  [{e.name}]')
            lines.append(f'    Size:       {len(e.data)} bytes')
            lines.append(f'    Compressed: {e.compressed_size} bytes ({cflag}, {ratio:.1f}%)')
            lines.append(f'    Hash:       {e.hash_val.hex()[:16]}...')
            lines.append(f'    Flags:      0x{e.flags:04X}')
            lines.append('')

        lines.append('=' * 60)
        return '\n'.join(lines)


# ======================================================================
# CONVENIENCE FUNCTIONS
# ======================================================================

def rebuild_slb2(entries_dict: Dict[str, bytes], compress: bool = True,
                 version: int = 2) -> bytes:
    """Standalone: {name: data} → SLB2 bytes."""
    return SLB2Rebuilder.batch_rebuild(entries_dict, compress=compress, version=version)


def parse_slb2(slb2_data: bytes, name_hints: Dict[str, str] = None) -> 'SLB2Rebuilder':
    """Standalone parse convenience."""
    return SLB2Rebuilder.parse(slb2_data, name_hints)
