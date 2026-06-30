"""
Donor Repair Integration - Thin wrapper around enhanced AutoRepair.
SmartDonorMatcher is now integrated directly into auto_repair.py's _find_donor().
"""

CRITICAL_REGIONS = [
    ('SCE_Header',   0x000000, 0x002000, 'Boot Chain'),
    ('MBR',          0x002000, 0x004000, 'Boot Chain'),
    ('EMC_IPL_A',    0x004000, 0x064000, 'Firmware'),
    ('EMC_IPL_B',    0x064000, 0x0C4000, 'Firmware'),
    ('EAP_KBL',      0x0C4000, 0x144000, 'Firmware'),
    ('Torus',        0x144000, 0x1C4000, 'Firmware'),
    ('NVS',          0x1C4000, 0x1D0000, 'NVS/CID'),
    ('CID_1CA',      0x1CA000, 0x1CB000, 'NVS/CID'),
    ('CID_1CD',      0x1CD000, 0x1CE000, 'NVS/CID'),
    ('CoreOS_A',     0x3C0000, 0x1080000, 'CoreOS'),
    ('CoreOS_B',     0x1080000, 0x1D40000, 'CoreOS'),
]

SHARABLE_SECTIONS = {
    'SCE_Header': True, 'MBR': True,
    'CoreOS_A': False, 'CoreOS_B': False, 'Torus': True,
}

REGION_MIN_HEALTHY = {
    'SCE_Header': 32, 'MBR': 128,
    'EMC_IPL_A': 1024, 'EMC_IPL_B': 1024,
    'EAP_KBL': 512, 'Torus': 256,
    'NVS': 512, 'CID_1CA': 16, 'CID_1CD': 16,
    'CoreOS_A': 65536, 'CoreOS_B': 65536,
}


class SmartAutoRepair:
    """Lazy wrapper to avoid circular import at module level."""
    def __new__(cls, *args, **kwargs):
        from ..patchers.auto_repair import AutoRepair
        return AutoRepair(*args, **kwargs)


def smart_auto_repair(data, donors_dir='donors', fws_dir='fws', fix_warnings=False):
    repair = SmartAutoRepair(data, donors_dir, fws_dir)
    applied = repair.repair_all(fix_warnings=fix_warnings)
    return repair.get_data(), repair.get_report(), applied
