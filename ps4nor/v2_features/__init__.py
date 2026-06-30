"""
PS4 NOR Validator Pro v2 — Advanced Features Package
Syscon FW DB | Keys Extractor | SLB2 Rebuilder | Smart Donor Matcher
"""

# ======================================================================
# syscon_fw_db — Syscon Firmware Database & eFuse Checker
# ======================================================================
from .syscon_fw_db import (
    # Databases
    SYSCON_FW_MD5,
    EFUSE_MIN_FW,
    SYSCON_CHIPS,
    # Detection
    compute_md5,
    detect_syscon_fw,
    _scan_syscon_version,
    # eFuse
    check_efuse_downgrade_safety,
    read_efuse_bits,
    # Utilities
    get_fw_range_for_syscon,
    get_model_list_for_chip,
    format_syscon_report,
)

# ======================================================================
# keys_extractor — Per-Console Keys Extraction
# ======================================================================
from .keys_extractor import (
    # Offsets
    NVS_IDPS_OFFSET,
    NVS_PSID_OFFSET,
    EAP_KEY_SLOT_OFFSET,
    HDD_WRAPPED_KEY_OFFSET,
    SNVS_BASE,
    BLOCK_START,
    BLOCK_SIZE,
    NUM_BLOCKS,
    # Crypto
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    hmac_sha256,
    entropy,
    # Class
    ConsoleKeysExtractor,
    extract_console_keys,
)

# ======================================================================
# slb2_rebuilder — SLB2 Partition Rebuilder
# ======================================================================
from .slb2_rebuilder import (
    SLB2RebuildError,
    SLB2Entry,
    SLB2Rebuilder,
    rebuild_slb2,
    parse_slb2,
)

# ======================================================================
# smart_donor — Smart Donor Matching Engine
# ======================================================================
from .smart_donor import (
    DonorInfo,
    MatchResult,
    SmartDonorMatcher,
    find_best_donor,
    get_donor_suggestions,
)

# ======================================================================
# hdd_analyzer — HDD Metadata Analysis
# ======================================================================
from .hdd_analyzer import (
    analyze_hdd_metadata,
    repair_hdd_metadata,
    format_hdd_report,
    HDD_META_1,
    HDD_META_2,
    HDD_META_SIZE,
    HDD_KEY_MAGIC,
    HDD_KEY_BLOB,
    HDD_KEY_BACKUP_MAGIC,
    HDD_KEY_BACKUP_BLOB,
    HDD_INFO_OFF,
    HDD_INFO_MIRROR,
)

# ======================================================================
# donor_repair_integration — Thin wrapper around enhanced AutoRepair
# ======================================================================
from .donor_repair_integration import (
    SmartAutoRepair,
    smart_auto_repair,
    CRITICAL_REGIONS,
    SHARABLE_SECTIONS,
    REGION_MIN_HEALTHY,
)

# ======================================================================
# hybrid_repair — Hybrid Repair Engine v2.1 (FW Blob → Same-FW Donor → Cross-Donor → Byte-Level)
# ======================================================================
from .hybrid_repair import (
    HybridRepairV21,
)

# ======================================================================
# __all__ — Public API
# ======================================================================
__all__ = [
    # syscon_fw_db
    'SYSCON_FW_MD5', 'EFUSE_MIN_FW', 'SYSCON_CHIPS',
    'compute_md5', 'detect_syscon_fw', '_scan_syscon_version',
    'check_efuse_downgrade_safety', 'read_efuse_bits',
    'get_fw_range_for_syscon', 'get_model_list_for_chip', 'format_syscon_report',
    # hdd_analyzer
    'analyze_hdd_metadata', 'repair_hdd_metadata', 'format_hdd_report',
    'HDD_META_1', 'HDD_META_2', 'HDD_META_SIZE',
    'HDD_KEY_MAGIC', 'HDD_KEY_BLOB', 'HDD_KEY_BACKUP_MAGIC', 'HDD_KEY_BACKUP_BLOB',
    'HDD_INFO_OFF', 'HDD_INFO_MIRROR',
    # keys_extractor
    'NVS_IDPS_OFFSET', 'NVS_PSID_OFFSET', 'EAP_KEY_SLOT_OFFSET',
    'HDD_WRAPPED_KEY_OFFSET', 'SNVS_BASE', 'BLOCK_START', 'BLOCK_SIZE', 'NUM_BLOCKS',
    'aes_ecb_decrypt', 'aes_ecb_encrypt', 'aes_cbc_decrypt', 'aes_cbc_encrypt',
    'hmac_sha256', 'entropy',
    'ConsoleKeysExtractor', 'extract_console_keys',
    # slb2_rebuilder
    'SLB2RebuildError', 'SLB2Entry', 'SLB2Rebuilder', 'rebuild_slb2', 'parse_slb2',
    # smart_donor
    'DonorInfo', 'MatchResult', 'SmartDonorMatcher', 'find_best_donor', 'get_donor_suggestions',
    # hybrid_repair
    'HybridRepairV21',
]

__version__ = '2.2.0'
__author__ = 'PS4 NOR Validator Pro Team'
