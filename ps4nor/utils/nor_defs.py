NOR_SIZE = 0x2000000  # 32MB

# Based on Wee Tools SFLASH_PARTITIONS layout (verified against psdevwiki)
# Slot 0 = unencrypted boot zone (2MB), Slot 1 = encrypted CoreOS zone (30MB)
NOR_LAYOUT = [
    # (name, start, end, description)
    ("Header",           0x000000, 0x001000, "NOR header"),
    ("Active Slot",      0x001000, 0x002000, "Active slot indicator (00=A / 80=B)"),
    ("MBR1",             0x002000, 0x003000, "MBR1: SCE static section"),
    ("MBR2",             0x003000, 0x004000, "MBR2: SCE backup section"),
    ("EMC_IPL_A",        0x004000, 0x064000, "EMC IPL slot A (384KB)"),
    ("EMC_IPL_B",        0x064000, 0x0C4000, "EMC IPL slot B (384KB)"),
    ("EAP_KBL",          0x0C4000, 0x144000, "EAP Key Blob + EAP fw (512KB)"),
    ("Torus (WiFi/BT)",  0x144000, 0x1C4000, "WiFi/BT firmware (512KB)"),
    ("NVS",              0x1C4000, 0x1D0000, "NVS / System flags region"),
    ("Slot0 Spare",      0x1D0000, 0x200000, "Slot 0 spare / unused"),
    # Slot 1 = encrypted
    ("S1 Header",        0x200000, 0x201000, "Slot 1 header (encrypted)"),
    ("S1 Active Slot",   0x201000, 0x202000, "Slot 1 active slot (encrypted)"),
    ("S1 MBR1",          0x202000, 0x203000, "Slot 1 MBR1 (encrypted)"),
    ("S1 MBR2",          0x203000, 0x204000, "Slot 1 MBR2 (encrypted)"),
    ("SAMU_IPL_A",       0x204000, 0x242000, "SAMU IPL slot A (encrypted)"),
    ("SAMU_IPL_B",       0x242000, 0x280000, "SAMU IPL slot B (encrypted)"),
    ("IDATA",            0x280000, 0x300000, "IDATA (encrypted)"),
    ("BD_HRL",           0x300000, 0x380000, "Blu-ray HRL (encrypted)"),
    ("VTRM",             0x380000, 0x3C0000, "VTRM thermal (encrypted)"),
    ("CoreOS_A",         0x3C0000, 0x1080000, "CoreOS slot A (13MB, encrypted)"),
    ("CoreOS_B",         0x1080000, 0x1D40000, "CoreOS slot B (13MB, encrypted)"),
    ("Slot1 Spare",      0x1D40000, 0x2000000, "Slot 1 spare / zero-filled"),
]

COREOS_SLOTS = [
    (0x3C0000, 0x1080000),  # CoreOS A
    (0x1080000, 0x1D40000), # CoreOS B
]

# NVS / CID regions within the Slot 0 NVS area (0x1C4000-0x1D0000)
NVS_START = 0x1C4000
NVS_END = 0x1D0000
NVS_SIZE = 0xC000

# Board ID: 8 bytes at NVS_START (0x1C4000)
# Format: 03:02:XX:01:01:YY:ZZ:01
#   Byte 0: 03 (Sony)
#   Byte 1: 02 (PS4)
#   Byte 2: motherboard variant (02=1102A, 05=2106A, 06=2216B)
#   Bytes 3-4: 01:01 (fixed)
#   Bytes 5-7: sub-revision flags
BOARD_ID_OFFSET = 0x1C4000
BOARD_ID_SIZE = 8

CID_REGIONS = {
    "1CA": (0x1CA000, 0x1CB000),
    "1CD": (0x1CD000, 0x1CE000),
    "1C9": (0x1C9000, 0x1CA000),
    "1CC": (0x1CC000, 0x1CD000),
}

# Known SCE header magic strings
SCE_MAGIC_STATIC_1 = b"SONY COMPUTER ENTERTAINMENT INC."
SCE_MAGIC_STATIC_2 = b"Sony Computer Entertainment Inc."

# UART flag offset (Wee Tools verified: 0x1C931F)
UART_OFFSET = 0x1C931F
UART_BACKUP_OFFSET = 0x3000

# EAP HDD key offsets (inside NVS)
EAP_MGC_OFF = 0x1C91FC  # 4 bytes magic (\xE5\xE5\xE5\x01)
EAP_KEY_OFF = 0x1C9200  # HDD wrapped key (0x40 or 0x60 bytes)
MAC_OFF = 0x1C4021       # 6 bytes MAC address
WIFI_5G_OFF = 0x1C7018   # 1 byte 5G support flag
TORUS_OFF = 0x144000     # Torus (WiFi/BT) firmware partition
TORUS_SIZE = 0x80000     # 512KB

# NVS identity regions — preserved during regeneration
NVS_IDENTITY_RANGES = [
    (0x1C4000, 0x1C4008),        # Board ID
    (0x1C4021, 0x1C4027),        # MAC
    (0x1C8000, 0x1C9000),        # Serial block
    (0x1C91FC, 0x1C9260),        # EAP HDD key primary
    (0x1C9C00, 0x1C9D00),        # HDD model/serial
    (0x1CA000, 0x1CD000),        # CID block
    (0x1CC1FC, 0x1CC260),        # EAP HDD key backup
    (0x1CCC00, 0x1CCD00),        # HDD model/serial backup
    (0x1CD000, 0x1CE000),        # CID mirror
    (0x1C5000, 0x1C6000),        # HDD metadata primary
    (0x1CE000, 0x1CF000),        # HDD metadata backup
]

def _build_sku_db():
    model_map = {
        100: "FAT", 110: "FAT", 111: "FAT",
        120: "Slim", 121: "Slim",
        200: "Slim", 201: "Slim", 210: "Slim", 211: "Slim", 220: "Slim", 221: "Slim",
        700: "Pro", 701: "Pro", 710: "Pro", 711: "Pro", 720: "Pro", 721: "Pro",
    }
    regions = {
        "0": "UK/EU", "1": "US", "2": "AU/NZ", "3": "UK/Ireland", "4": "EU",
        "6": "Russia", "8": "China", "9": "Japan",
    }
    db = {}
    for model_num, model_type in model_map.items():
        for region_code, region_name in regions.items():
            sku = f"CUH-{model_num}{region_code}"
            db[sku] = (model_type, region_name)
    return db

SKU_DATABASE = _build_sku_db()

REGION_CODES = {
    "B": "UK/EU",
    "C": "Japan",
    "E": "UK/EU",
    "F": "US",
    "G": "US",
    "H": "Asia",
    "J": "Japan",
    "K": "Japan",
    "L": "US/LATAM",
    "M": "US",
    "P": "EU",
    "Q": "UK",
    "S": "US",
    "T": "Asia",
    "U": "US",
    "V": "US",
    "X": "Russia",
}

SOUTHBRIDGE_TYPES = {
    "Aeolia":   b"\x00\x00\x00\x00",
    "Thor":     b"\x01\x00\x00\x00",
}

# Status indicators
STATUS_OK = "OK"
STATUS_WARNING = "WARNING"
STATUS_DANGER = "DANGER"
STATUS_UNLISTED = "UNLISTED"
