import os
from ..utils.helpers import entropy, md5_hash, is_all_zeros, is_all_ff


class NVSViewer:
    NVS_REGIONS = [
        ("1C9", 0x1C9000, 0x1CA000, "CID CRC / Unknown"),
        ("1CA", 0x1CA000, 0x1CB000, "Console ID (primary)"),
        ("1CB", 0x1CB000, 0x1CC000, "Console ID CRC / Unknown"),
        ("1CC", 0x1CC000, 0x1CD000, "CID CRC / Unknown (backup)"),
        ("1CD", 0x1CD000, 0x1CE000, "Console ID (backup)"),
        ("1D0", 0x1D0000, 0x1D1000, "System flags / Unknown"),
        ("System FD", 0x1F0000, 0x200000, "System Flags Data"),
    ]

    def __init__(self, data):
        self.data = data

    def show_all(self):
        lines = []
        lines.append("NVS Analysis:")
        lines.append(f"  {'Name':8s} {'Start':>8s} - {'End':>8s} {'Size':>6s}  {'Status':12s} {'Entropy':>7s}  {'Details'}")
        lines.append("  " + "-" * 70)
        for name, start, end, desc in self.NVS_REGIONS:
            if start >= len(self.data):
                continue
            end = min(end, len(self.data))
            chunk = self.data[start:end]
            sz = end - start
            ent = entropy(chunk)
            zero_pct = chunk.count(0) / sz * 100 if sz > 0 else 0
            ff_pct = chunk.count(0xFF) / sz * 100 if sz > 0 else 0

            if is_all_zeros(chunk):
                status = "EMPTY"
            elif is_all_ff(chunk):
                status = "FILLED"
            elif ent < 1.0:
                status = "LOW_ENTROPY"
            elif ent > 6.0:
                status = "HIGH_ENTROPY"
            else:
                status = "OK"

            extra = desc
            if status == "OK":
                non_zero = sz - chunk.count(0) - chunk.count(0xFF)
                extra += f", {non_zero} non-zero bytes"

            lines.append(f"  {name:8s} {hex(start):>8s} - {hex(end):>8s} {sz//1024:>4d}KB  {status:12s} {ent:>7.2f}  {extra}")
        return "\n".join(lines)

    def show_region(self, name):
        for n, start, end, desc in self.NVS_REGIONS:
            if n == name:
                break
        else:
            return f"Unknown region: {name}"

        end = min(end, len(self.data))
        chunk = self.data[start:end]
        lines = []
        lines.append(f"Region {name} ({desc})")
        lines.append(f"  Offset: {hex(start)} - {hex(end)} ({end-start} bytes)")
        lines.append(f"  Entropy: {entropy(chunk):.2f}")
        lines.append(f"  MD5: {md5_hash(chunk)}")
        lines.append(f"  Zeros: {chunk.count(0)}/{end-start}, FF: {chunk.count(0xFF)}/{end-start}")
        lines.append("")
        lines.append("  Hex dump:")
        for i in range(0, min(len(chunk), 256), 16):
            row = chunk[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in row)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"  {start+i:08X}  {hex_part:48s}  {ascii_part}")
        if len(chunk) > 256:
            lines.append(f"  ... ({len(chunk) - 256} more bytes)")
        return "\n".join(lines)

    def show_summary(self):
        lines = []
        lines.append("NVS Summary:")
        for name, start, end, desc in self.NVS_REGIONS:
            if start >= len(self.data):
                continue
            end = min(end, len(self.data))
            chunk = self.data[start:end]
            status = "EMPTY" if is_all_zeros(chunk) or is_all_ff(chunk) else "OK"
            ent = entropy(chunk)
            lines.append(f"  {name}: {status} entropy={ent:.2f} md5={md5_hash(chunk)[:8]}")
        return "\n".join(lines)
