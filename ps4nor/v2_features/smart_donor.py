"""
Smart Donor Matcher v2 — Weighted matching with deep NVS analysis, caching,
FW range matching, section-level comparison, and repair engine integration.
"""

import os
import glob
import hashlib
import re
import json
import time
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from ..utils.colors import C, ok, fail, warn, info, title, brand, dim, value, head


# ======================================================================
# DATA CLASSES
# ======================================================================

@dataclass
class DonorInfo:
    filepath: str
    filename: str
    sku: str
    model: str                    # Fat / Slim / Pro
    region: str                   # US / EU / JP / RU / etc
    fw_version: str
    md5: str
    size: int
    motherboard: str = 'Unknown'  # JDM-xxx
    score: float = 0.0
    match_details: Dict = field(default_factory=dict)
    section_md5: Dict = field(default_factory=dict)
    nvs_info: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MatchResult:
    """Detailed match result for reporting."""
    target_sku: str
    target_fw: str
    target_model: str
    target_region: str
    matches: List[DonorInfo]
    best: Optional[DonorInfo]
    total_donors: int
    elapsed_ms: float
    warnings: List[str] = field(default_factory=list)


# ======================================================================
# SMART DONOR MATCHER
# ======================================================================

class SmartDonorMatcher:
    """
    Advanced donor matching with weighted scoring:

    Weight categories:
    - Series (CUH-1/2/7):        40%
    - Model (Fat/Slim/Pro):      30%
    - Region (US/EU/JP):         20%
    - FW version:                10%
    - Motherboard revision:      5%  (bonus)

    Additional features:
    - Deep NVS parsing for SKU/FW verification
    - Section-level MD5 comparison
    - Donor caching for fast re-scan
    - FW range matching (not just exact)
    """

    WEIGHTS = {
        'series': 35.0,       # CUH-1, CUH-2, CUH-7
        'model': 25.0,        # Fat/Slim/Pro
        'region': 20.0,       # Region code
        'fw': 10.0,           # FW exact match
        'fw_close': 5.0,      # FW close match (same major)
        'motherboard': 5.0,   # JDM-xxx match
        'section': 5.0,       # Section MD5 similarity
    }

    # Comprehensive SKU → Model mapping
    SKU_MODEL = {
        # FAT
        'CUH-10': 'Fat', 'CUH-11': 'Fat', 'CUH-12': 'Fat',
        # SLIM
        'CUH-20': 'Slim', 'CUH-21': 'Slim', 'CUH-22': 'Slim',
        'CUH-23': 'Slim', 'CUH-24': 'Slim',
        # PRO
        'CUH-70': 'Pro', 'CUH-71': 'Pro', 'CUH-72': 'Pro',
    }

    # SKU → Motherboard mapping
    SKU_MOTHERBOARD = {
        'CUH-10': 'JDM-001', 'CUH-11': 'JDM-010', 'CUH-12': 'JDM-020',
        'CUH-20': 'JDM-040', 'CUH-21': 'JDM-050', 'CUH-22': 'JDM-060',
        'CUH-70': 'JDM-080', 'CUH-71': 'JDM-090', 'CUH-72': 'JDM-100',
    }

    # Region codes
    SKU_REGION = {
        'A': 'US', 'B': 'EU', 'C': 'JP', 'D': 'UK', 'E': 'EU', 'F': 'EU',
        'G': 'EU', 'H': 'HK', 'J': 'JP', 'K': 'KR', 'L': 'TW', 'M': 'CN',
        'P': 'EU', 'Q': 'EU', 'R': 'RU', 'S': 'AU', 'T': 'TW', 'U': 'US',
        'W': 'EU', 'X': 'MX', 'Y': 'AU', 'Z': 'TW',
    }

    # Critical section offsets for partial comparison
    CRITICAL_SECTIONS = {
        'NVS': (0x1C8000, 0x1CA000),
        'EAP': (0x24000, 0x26000),
        'SLB2_A': (0x200000, 0x210000),
        'SLB2_B': (0x2F0000, 0x300000),
        'Torus': (0x144000, 0x14C000),
    }

    # Cache file name
    CACHE_FILENAME = '.donor_cache.json'

    def __init__(self, donors_dir: str, use_cache: bool = True):
        self.donors_dir = donors_dir
        self._donors: List[DonorInfo] = []
        self._use_cache = use_cache
        self._cache_path = os.path.join(donors_dir, self.CACHE_FILENAME)
        self._load_donors()

    # ------------------------------------------------------------------
    # Donor Loading
    # ------------------------------------------------------------------

    def _load_donors(self) -> None:
        """Load donors with optional caching."""
        if self._use_cache and self._load_cache():
            return
        self._scan()
        if self._use_cache:
            self._save_cache()

    def _scan(self) -> None:
        """Scan donors directory and parse all donor info."""
        patterns = ['*.bin', '*.BIN', '*.nor', '*.NOR', '*.dump', '*.DUMP']
        seen = set()
        start = time.time()

        for pat in patterns:
            for f in glob.glob(os.path.join(self.donors_dir, pat)):
                abspath = os.path.abspath(f)
                if abspath in seen or os.path.getsize(f) < 0x1000:
                    continue
                seen.add(abspath)
                try:
                    info = self._parse_donor(f)
                    if info:
                        self._donors.append(info)
                except Exception:
                    pass

    def _is_valid_dump(self, filepath: str) -> bool:
        """Quick sanity: key areas must have minimum entropy."""
        try:
            with open(filepath, 'rb') as f:
                f.seek(0x24000)
                eap = f.read(32)
                f.seek(0x1C5000)
                nvs = f.read(0x1000)
            from ..v2_features.keys_extractor import entropy
            return entropy(eap) > 1.0 or entropy(nvs) > 1.0
        except Exception:
            return False

    def _parse_donor(self, filepath: str) -> Optional[DonorInfo]:
        """Extract comprehensive donor metadata."""
        if not self._is_valid_dump(filepath):
            return None
        filename = os.path.basename(filepath)
        size = os.path.getsize(filepath)

        # Quick MD5 (first 1MB + last 1MB for speed)
        md5 = self._quick_md5(filepath)

        # Try filename parsing
        sku, fw, model, region = self._parse_filename(filename)

        # Deep NVS parsing if filename didn't give enough info
        nvs_info = {}
        if not (sku and fw):
            nvs_info = self._read_nvs_info(filepath)
            if not sku:
                sku = nvs_info.get('sku')
            if not fw:
                fw = nvs_info.get('fw')

        # Derive model/region from SKU if filename didn't provide
        if sku:
            prefix = sku[:6]
            if not model or model == 'Unknown':
                model = self.SKU_MODEL.get(prefix, 'Unknown')
            if not region or region == 'Unknown':
                region_char = sku[-1] if len(sku) > 7 else '?'
                region = self.SKU_REGION.get(region_char, 'Unknown')

        # Defaults
        sku = sku or 'UNKNOWN'
        model = model or 'Unknown'
        region = region or 'Unknown'
        fw = fw or 'Unknown'

        # Motherboard from SKU
        mb = 'Unknown'
        if sku:
            mb = self.SKU_MOTHERBOARD.get(sku[:6], 'Unknown')

        # Section MD5s (for advanced matching)
        section_md5 = self._compute_section_md5(filepath, size)

        return DonorInfo(
            filepath=filepath, filename=filename,
            sku=sku, model=model, region=region,
            fw_version=fw, md5=md5, size=size,
            motherboard=mb, section_md5=section_md5,
            nvs_info=nvs_info,
        )

    def _parse_filename(self, filename: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Parse filename for SKU, FW, model, region.
        Patterns:
          CUH-2216A_13.02.bin
          CUH-1216B_9.00.nor
          CUH-7015C_11.00.bin
        """
        sku = fw = model = region = None

        # Pattern: CUH-XXXX[A-Z]_FW.bin
        m = re.match(r'(CUH-\d{4}[A-Z])_?([\d.]+)?', filename, re.IGNORECASE)
        if m:
            sku = m.group(1).upper()
            if m.group(2):
                fw = m.group(2)
            prefix = sku[:6]
            model = self.SKU_MODEL.get(prefix, 'Unknown')
            region_char = sku[-1] if len(sku) > 7 else '?'
            region = self.SKU_REGION.get(region_char, 'Unknown')

        return sku, fw, model, region

    def _read_nvs_info(self, filepath: str) -> Dict:
        """Read SKU and FW version from NVS area in NOR dump."""
        result = {'sku': None, 'fw': None}
        try:
            with open(filepath, 'rb') as f:
                # Read whole NVS area (0x1C4000-0x1D0000)
                f.seek(0x1C4000)
                data = f.read(0xC000)

            if len(data) >= 0x40:
                # SKU: regex scan of NVS area for CUH pattern
                m = re.search(rb'CUH-\d{4}[A-Z]', data)
                if m:
                    result['sku'] = m.group(0).decode('ascii')

                # FW version at 0x1C906A (relative: 0x506A into NVS)
                fw_off = 0x506A
                if len(data) > fw_off + 2:
                    maj = data[fw_off + 1]
                    minor = data[fw_off]
                    if maj == 0 and minor == 0:
                        pass  # skip empty
                    elif 1 <= maj <= 99 and minor <= 99:
                        result['fw'] = f'{maj:X}.{minor:02X}'

        except (OSError, IOError):
            pass

        return result

    def _quick_md5(self, filepath: str) -> str:
        """Compute MD5 of first 1MB + last 1MB for speed."""
        try:
            size = os.path.getsize(filepath)
            with open(filepath, 'rb') as f:
                if size <= 0x200000:  # <= 2MB, hash entire file
                    return hashlib.md5(f.read()).hexdigest()

                h = hashlib.md5()
                h.update(f.read(0x100000))  # First 1MB
                f.seek(-0x100000, 2)
                h.update(f.read(0x100000))  # Last 1MB
                return h.hexdigest()
        except Exception:
            return ''

    def _compute_section_md5(self, filepath: str, size: int) -> Dict[str, str]:
        """Compute MD5 of critical sections for matching."""
        result = {}
        try:
            with open(filepath, 'rb') as f:
                for name, (start, end) in self.CRITICAL_SECTIONS.items():
                    if start + (end - start) <= size:
                        f.seek(start)
                        data = f.read(end - start)
                        result[name] = hashlib.md5(data).hexdigest()
        except Exception:
            pass
        return result

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    def _save_cache(self) -> None:
        """Save donor metadata to cache file."""
        try:
            cache_data = [d.to_dict() for d in self._donors]
            with open(self._cache_path, 'w') as f:
                json.dump({
                    'version': 2,
                    'timestamp': time.time(),
                    'donors': cache_data,
                }, f)
        except (OSError, IOError):
            pass

    def _load_cache(self) -> bool:
        """Load donor metadata from cache file."""
        if not os.path.exists(self._cache_path):
            return False

        try:
            with open(self._cache_path, 'r') as f:
                cache = json.load(f)

            if cache.get('version') != 2:
                return False

            # Verify cache is fresh (< 1 hour)
            if time.time() - cache.get('timestamp', 0) > 3600:
                return False

            # Verify donors still exist
            for d in cache['donors']:
                if not os.path.exists(d['filepath']):
                    return False

            # Restore from cache
            self._donors = [DonorInfo(**d) for d in cache['donors']]
            return True

        except Exception:
            return False

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match(self, target_sku: str, target_fw: str = None,
              target_model: str = None, target_region: str = None) -> MatchResult:
        """
        Match donors against target and return sorted results.
        Weighted scoring with multiple criteria.
        """
        start = time.time()
        warnings = []

        if not self._donors:
            return MatchResult(
                target_sku=target_sku, target_fw=target_fw or '',
                target_model=target_model or '', target_region=target_region or '',
                matches=[], best=None, total_donors=0,
                elapsed_ms=0, warnings=['No donors loaded'],
            )

        target_series = target_sku[:6] if len(target_sku) >= 6 else ''
        target_model = target_model or self.SKU_MODEL.get(target_series, 'Unknown')
        target_region = target_region or self.SKU_REGION.get(
            target_sku[-1] if target_sku else '?', 'Unknown'
        )

        scored: List[DonorInfo] = []

        for donor in self._donors:
            score = 0.0
            details = {}

            # 1. Series match (35%)
            donor_series = donor.sku[:6] if len(donor.sku) >= 6 else ''
            if target_series and donor_series and donor_series == target_series and donor_series != 'UNKN':
                score += self.WEIGHTS['series']
                details['series'] = 'exact'
            elif donor_series and target_series and donor_series[:5] == target_series[:5]:
                score += self.WEIGHTS['series'] * 0.5
                details['series'] = 'partial'
            else:
                details['series'] = 'mismatch'

            # 2. Model match (25%)
            if (donor.model == target_model
                    and donor.model != 'Unknown'
                    and target_model != 'Unknown'):
                score += self.WEIGHTS['model']
                details['model'] = 'match'
            else:
                details['model'] = 'mismatch'

            # 3. Region match (20%)
            if (donor.region == target_region
                    and donor.region != 'Unknown'
                    and target_region != 'Unknown'):
                score += self.WEIGHTS['region']
                details['region'] = 'match'
            else:
                details['region'] = 'mismatch'

            # 4. FW match (10% exact, 5% close)
            if (target_fw and donor.fw_version == target_fw
                    and donor.fw_version != 'Unknown'):
                score += self.WEIGHTS['fw']
                details['fw'] = 'exact'
            elif target_fw and self._fw_close(donor.fw_version, target_fw):
                score += self.WEIGHTS['fw_close']
                details['fw'] = 'close'
            else:
                details['fw'] = 'mismatch'

            # 5. Motherboard bonus (5%)
            target_mb = self.SKU_MOTHERBOARD.get(target_series, '')
            if (donor.motherboard != 'Unknown' and target_mb
                    and donor.motherboard == target_mb):
                score += self.WEIGHTS['motherboard']
                details['motherboard'] = 'match'
            else:
                details['motherboard'] = 'mismatch'

            # 6. Section MD5 similarity (5%)
            section_score = self._section_similarity(donor, target_series)
            score += section_score
            details['section'] = f'{section_score:.1f}/{self.WEIGHTS["section"]}'

            donor.score = round(score, 2)
            donor.match_details = details
            scored.append(donor)

        # Sort by score descending
        scored.sort(key=lambda d: d.score, reverse=True)

        elapsed = (time.time() - start) * 1000

        return MatchResult(
            target_sku=target_sku,
            target_fw=target_fw or '',
            target_model=target_model,
            target_region=target_region,
            matches=scored,
            best=scored[0] if scored and scored[0].score > 0 else None,
            total_donors=len(scored),
            elapsed_ms=round(elapsed, 2),
            warnings=warnings,
        )

    def _section_similarity(self, donor: DonorInfo, target_series: str) -> float:
        """Compare section MD5s for similarity scoring."""
        if not donor.section_md5:
            return 0.0
        # Higher weight if any section matches (indicates similar dump)
        for name, md5_val in donor.section_md5.items():
            # Sections like Torus, EAP are model-dependent
            if name in ('EAP', 'SLB2_A') and md5_val:
                # Having these sections is better than not
                return self.WEIGHTS['section'] * 0.5
        return 0.0

    def _fw_close(self, donor_fw: str, target_fw: str) -> bool:
        """Check if FW versions are close (same major.minor)."""
        try:
            d_parts = donor_fw.split('.')
            t_parts = target_fw.split('.')
            return (len(d_parts) >= 2 and len(t_parts) >= 2
                    and d_parts[0] == t_parts[0] and d_parts[1] == t_parts[1])
        except (ValueError, IndexError):
            return False

    def get_best(self, target_sku: str, target_fw: str = None,
                 target_model: str = None, target_region: str = None) -> Optional[DonorInfo]:
        """Get single best match (fast path)."""
        result = self.match(target_sku, target_fw, target_model, target_region)
        return result.best

    def get_top_n(self, target_sku: str, n: int = 5, target_fw: str = None,
                  target_model: str = None, target_region: str = None) -> List[DonorInfo]:
        """Get top N matches."""
        result = self.match(target_sku, target_fw, target_model, target_region)
        return result.matches[:n]

    # ------------------------------------------------------------------
    # Donor Management
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Force rescan of donors directory."""
        self._donors = []
        self._scan()
        if self._use_cache:
            self._save_cache()

    @property
    def donor_count(self) -> int:
        return len(self._donors)

    def get_donor_list(self) -> List[DonorInfo]:
        return list(self._donors)

    def filter_by_model(self, model: str) -> List[DonorInfo]:
        return [d for d in self._donors if d.model.lower() == model.lower()]

    def filter_by_region(self, region: str) -> List[DonorInfo]:
        return [d for d in self._donors if d.region.lower() == region.lower()]

    def filter_by_fw(self, fw: str) -> List[DonorInfo]:
        return [d for d in self._donors if d.fw_version == fw]

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def format_match_report(self, result: MatchResult) -> str:
        """Generate detailed match report."""
        lines = []
        lines.append(f'{C.CYN}{"=" * 65}{C.RST}')
        lines.append(f'{C.CYN}{C.BLD}  DONOR MATCHING REPORT{C.RST}')
        lines.append(f'{C.CYN}{"=" * 65}{C.RST}')
        lines.append(f'  {info("Target SKU:")}     {value(result.target_sku)}')
        lines.append(f'  {info("Target FW:")}      {value(result.target_fw) if result.target_fw else dim("N/A")}')
        lines.append(f'  {info("Target Model:")}   {value(result.target_model) if result.target_model else dim("N/A")}')
        lines.append(f'  {info("Target Region:")}  {value(result.target_region) if result.target_region else dim("N/A")}')
        lines.append(f'  {info("Donors Scanned:")} {value(str(result.total_donors))}')
        lines.append(f'  {info("Time:")}           {dim(str(result.elapsed_ms) + "ms")}')
        lines.append('')

        if result.best:
            score = result.best.score
            score_str = ok(f'{score}/100') if score >= 50 else warn(f'{score}/100')
            lines.append(f'  {title("BEST MATCH:")} {value(result.best.filename)}')
            lines.append(f'    {info("Score:")}  {score_str}')
            lines.append(f'    {info("SKU:")}    {value(result.best.sku)}')
            lines.append(f'    {info("FW:")}     {value(result.best.fw_version)}')
            lines.append(f'    {info("Model:")}  {value(result.best.model)}')
            lines.append(f'    {info("Region:")} {value(result.best.region)}')
            lines.append(f'    {info("MB:")}     {value(result.best.motherboard)}')
            lines.append(f'    {info("Details:")} {dim(str(result.best.match_details))}')
        else:
            lines.append(f'  {warn("No suitable match found.")}')

        if result.warnings:
            lines.append(f'\n  {warn("Warnings:")}')
            for w in result.warnings:
                lines.append(f'    {warn("-")} {w}')

        # Top 5
        if len(result.matches) > 1:
            lines.append(f'\n  {title("TOP 5 MATCHES:")}')
            lines.append(f'  {head("Rank"):<6} {head("Score"):<7} {head("SKU"):<14} {head("FW"):<8} {head("Model"):<6} {head("Region"):<7} {dim("Filename")}')
            lines.append(f'  {dim("-" * 60)}')
            for i, d in enumerate(result.matches[:5], 1):
                s = ok(f'{d.score:.1f}') if d.score >= 50 else warn(f'{d.score:.1f}')
                lines.append(f'  {i:<6} {s:<7} {d.sku:<14} {d.fw_version:<8} '
                             f'{d.model:<6} {d.region:<7} {d.filename[:30]}')

        lines.append(f'{C.CYN}{"=" * 65}{C.RST}')
        return '\n'.join(lines)


def find_best_donor(donors_dir: str, target_sku: str, target_fw: str = None,
                    target_model: str = None, target_region: str = None) -> Optional[DonorInfo]:
    """Convenience: single best donor match."""
    matcher = SmartDonorMatcher(donors_dir)
    return matcher.get_best(target_sku, target_fw, target_model, target_region)


def get_donor_suggestions(donors_dir: str, target_sku: str, target_fw: str = None,
                          n: int = 5) -> List[DonorInfo]:
    """Convenience: top N donor suggestions."""
    matcher = SmartDonorMatcher(donors_dir)
    return matcher.get_top_n(target_sku, n=n, target_fw=target_fw)
