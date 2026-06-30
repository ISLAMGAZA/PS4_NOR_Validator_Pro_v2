"""
Donor validation utilities
"""


def is_valid_donor(data: bytes) -> bool:
    """EAP key area (0x24000, 32 bytes) or NVS (0x1C5000, 4KB) must have entropy > 1.0"""
    if len(data) < 0x1D0000:
        return False
    from .helpers import entropy
    return entropy(data[0x24000:0x24020]) > 1.0 or entropy(data[0x1C5000:0x1C6000]) > 1.0
