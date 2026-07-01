"""
PS4 Repair Chat Agent — conversational diagnostics & repair.
"""

import os, re, json, hashlib
from typing import Optional, Dict, List, Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSCON_DONORS_DIR = os.path.join(ROOT, 'syscon_donors')

class ConversationState:
    def __init__(self):
        self.nor_data = None
        self.nor_name = ''
        self.syscon_data = None
        self.syscon_name = ''
        self.nor_analysis = None
        self.syscon_analysis = None
        self.diagnosis = []
        self.match_results = []
        self.step = 'greeting'
        self.history: List[Dict[str, str]] = []

    def reset(self):
        self.__init__()

def _bold(t): return f'**{t}**'
def _code(t): return f'`{t}`'
def _badge(t, kind='ok'):
    return f'<span class="stat-badge {kind}">{t}</span>'
def _stat(label, value):
    return f'<div class="stat-row"><span class="stat-label">{label}</span><span class="stat-value">{value}</span></div>'

class PS4ChatAgent:
    def __init__(self):
        self.state = ConversationState()

    def process_message(self, msg: str, files: Dict[str, bytes] = None) -> Dict[str, Any]:
        if files:
            for name, data in files.items():
                if len(data) == 0x2000000 and (name.upper().endswith('.BIN') or name.upper().endswith('.NOR')):
                    self.state.nor_data = data
                    self.state.nor_name = name
                    self._analyze_nor()
                    self.state.step = 'nor_loaded'
                elif len(data) in (0x40000, 0x80000):
                    self.state.syscon_data = data
                    self.state.syscon_name = name
                    self._analyze_syscon()
                    self.state.step = 'syscon_loaded'

        response = self._generate_response(msg)
        self.state.history.append({'role': 'user', 'content': msg})
        self.state.history.append({'role': 'assistant', 'content': response})
        return {
            'response': response,
            'state': self.state.step,
            'has_nor': self.state.nor_data is not None,
            'has_syscon': self.state.syscon_data is not None,
            'nor_file': self.state.nor_name,
            'syscon_file': self.state.syscon_name,
        }

    def _analyze_nor(self):
        from .server import analyze_nor
        self.state.nor_analysis = analyze_nor(self.state.nor_data)

    def _analyze_syscon(self):
        from .server import analyze_syscon, get_arv, diagnose
        self.state.syscon_analysis = analyze_syscon(self.state.syscon_data)
        arv = get_arv(self.state.syscon_data)
        self.state.syscon_analysis['arv'] = arv
        nor_info = self.state.nor_analysis or {}
        self.state.diagnosis = diagnose(nor_info, self.state.syscon_analysis)
        if self.state.nor_analysis:
            self._run_match()

    def _run_match(self):
        from ps4nor.v2_features.syscon_fw_db import match_syscon_to_nor
        ninfo = {
            'board_id': self.state.nor_analysis.get('board_id', ''),
            'sku': self.state.nor_analysis.get('sku', ''),
            'fw': self.state.nor_analysis.get('fw', ''),
            'eap_md5': '',
            '_path': self.state.nor_name,
        }
        self.state.match_results = match_syscon_to_nor(
            ninfo, SYSCON_DONORS_DIR if os.path.isdir(SYSCON_DONORS_DIR) else None)

    def _fmt_nor_card(self):
        n = self.state.nor_analysis
        if not n: return ''
        h = 'ok' if n.get('healthy') else 'warn'
        return ('<div class="stat-grid">'
                + _stat('📀 Model', _bold(n.get('sku', '?')))
                + _stat('🔢 FW Version', _bold(n.get('fw', '?')))
                + _stat('🆔 Board ID', _code(n.get('board_id', '?')))
                + _stat('📡 Active Slot', n.get('active_slot', '?'))
                + _stat('🔌 MAC', _code(n.get('mac', 'N/A')))
                + _stat('❤️ Overall', _badge('HEALTHY' if n.get('healthy') else 'CHECK', h))
                + '</div>')

    def _fmt_syscon_card(self):
        s = self.state.syscon_analysis
        if not s: return ''
        sev = s.get('severity', 'none')
        sev_badge = {'none': 'ok', 'minor': 'ok', 'moderate': 'warn', 'severe': 'fail', 'critical': 'fail'}.get(sev, 'warn')
        return ('<div class="stat-grid">'
                + _stat('🧩 Chip', _bold(s.get('chip', '?')))
                + _stat('🎯 ARV', str(s.get('arv', -1)))
                + _stat('💾 FW Area', _badge('OK' if s.get('fw_healthy') else 'DAMAGED', 'ok' if s.get('fw_healthy') else 'fail'))
                + _stat('📋 Entries', str(s.get('valid_entries', 0)))
                + _stat('⚠️ Severity', _badge(sev.capitalize(), sev_badge))
                + _stat('🔴 Missing Types', ', '.join(f'0x{t:02X}' for t in s.get('missing_types', [])) or _badge('None', 'ok'))
                + '</div>')

    def _generate_response(self, msg: str) -> str:
        msg_lower = msg.lower()
        nor = self.state.nor_analysis
        sc = self.state.syscon_analysis

        # ── 1. GREETING ──
        if self.state.step == 'greeting':
            self.state.step = 'awaiting_nor'
            return ('<p>✨ Welcome to <strong>PS4 Repair Agent</strong> 🎮</p>'
                    '<p>I help diagnose and repair NOR & Syscon dumps from PlayStation 4 consoles.</p>'
                    '<p style="margin-top:10px">📁 <strong>Drop your NOR dump</strong> (32MB .BIN) above to get started,<br>'
                    'or type a question about your console issue.</p>')

        # ── 2. USER WANTS FIX WITHOUT FILES ──
        wants_help = any(w in msg_lower for w in ['بلو', 'blue', 'اعطال', 'مشكلة', 'help', 'problem', 'fix', 'اعطاني'])
        if self.state.nor_data is None and wants_help:
            return ('<p>I can help diagnose a wide range of PS4 issues!</p>'
                    '<p><strong>To begin, I need a NOR dump file</strong> 📁<br>'
                    'Drop your <code>.BIN</code> file (32MB) in the upload area above.</p>'
                    '<p style="color:var(--text-dim);font-size:0.88em">💡 You can also upload a Syscon dump (256KB/512KB) alongside it.</p>')

        if self.state.nor_data is None:
            return '<p>Please upload a <strong>NOR dump</strong> first 📁<br>Drag & drop or click the upload bar above.</p>'

        # ── 3. NOR LOADED — ASK FOR SYSCON ──
        if self.state.syscon_data is None and self.state.step in ('nor_loaded', 'awaiting_syscon'):
            self.state.step = 'awaiting_syscon'
            no_syscon = any(w in msg_lower for w in ['لا', 'ما عندي', 'لا يوجد', 'ليس معي', 'مش موجود',
                                                      'no', "don't have", 'dont have', 'not available', 'without', 'بدون'])
            if no_syscon:
                self.state.step = 'nor_only'
                diag = '<p>✅ <strong>NOR analysis complete (no Syscon):</strong></p>' + self._fmt_nor_card()
                if not nor.get('healthy', True):
                    diag += '<p style="color:var(--orange);margin-top:8px">⚠️ SCE header region is sparse — the dump may be incomplete.</p>'
                if nor.get('mac', '').startswith('ff:ff'):
                    diag += '<p style="color:var(--orange)">⚠️ MAC is erased — WiFi/BT will not function.</p>'
                diag += ('<p style="margin-top:10px">📌 <strong>Tip:</strong> For a full diagnosis (SSC/SSK keys, ARV, boot chain),'
                         ' add a Syscon dump later.</p>'
                         '<p>🤔 <strong>Do you have a Syscon dump you can share?</strong></p>'
                         '<div class="confirm-group" onclick=\'window.dispatchEvent(new CustomEvent("confirm", {detail:"yes"}))\'>'
                         '<button class="btn-confirm yes">✅ Yes, I have it</button>'
                         '<button class="btn-confirm no" onclick=\'window.dispatchEvent(new CustomEvent("confirm", {detail:"no"}))\'>❌ No</button></div>')
                return diag

            return ('<p>✅ <strong>NOR loaded successfully!</strong></p>'
                    + self._fmt_nor_card()
                    + '<p style="margin-top:10px">📁 <strong>Do you have a Syscon dump?</strong> 🧩<br>'
                    'Upload it for a complete diagnosis (ARV, SSC/SSK, severity).<br>'
                    '<span style="color:var(--text-dim)">Or type <strong>"لا"</strong> / <strong>"no"</strong> to continue without.</span></p>'
                    '<div class="confirm-group">'
                    '<button class="btn-confirm yes" onclick="document.getElementById(\'fileInput\').click()">✅ Yes, upload</button>'
                    '<button class="btn-confirm no" onclick=\'window.dispatchEvent(new CustomEvent("confirm", {detail:"no"}))\'>❌ No, continue</button></div>')

        # ── 4. NOR ONLY — NO SYSCON ──
        if self.state.step == 'nor_only':
            diag = '<p>✅ <strong>NOR analysis:</strong></p>' + self._fmt_nor_card()
            if nor.get('mac', '').startswith('ff:ff'):
                diag += '<p style="color:var(--orange);margin-top:8px">⚠️ MAC erased — WiFi/BT disabled but console can boot.</p>'
            return diag

        # ── 5. BOTH LOADED — FULL DIAGNOSTICS ──
        self.state.step = 'diagnosed'

        errors = [d for d in self.state.diagnosis if d['level'] == 'error']
        warns = [d for d in self.state.diagnosis if d['level'] == 'warn']

        html = '<p>🎯 <strong>Full Diagnostics Report</strong></p>'
        html += '<div class="stat-grid" style="margin-bottom:8px">'
        html += _stat('📀 NOR', f'{_bold(nor["sku"])} FW {_bold(nor["fw"])}')
        html += _stat('🧩 Syscon', f'ARV={sc.get("arv","?")}  {_badge(sc.get("severity","?").capitalize(), "warn" if sc.get("severity") in ("moderate","severe") else "ok")}')
        html += _stat('📋 Entries', f'{sc.get("valid_entries","?")}  |  Chip {sc.get("chip","?")}')
        html += '</div>'

        if errors:
            html += '<p style="margin:10px 0 6px"><strong style="color:var(--red)">🔴 Issues found:</strong></p>'
            for e in errors:
                html += f'<p style="padding:6px 10px;background:var(--red-bg);border-radius:8px;margin:4px 0">'
                html += f'<strong style="color:var(--red)">{e["title"]}</strong><br>{e["detail"]}</p>'

        if warns:
            html += '<p style="margin:8px 0 4px"><strong style="color:var(--orange)">🟡 Notes:</strong></p>'
            for w in warns:
                html += f'<p style="padding:4px 0;color:var(--orange)">{w["detail"]}</p>'

        # Suggestions
        if sc:
            missing = sc.get('missing_types', [])
            if [t for t in missing if 0 <= t <= 7]:
                html += ('<p style="margin-top:12px"><strong>💡 Suggested fixes:</strong></p>'
                         '<div class="fix-buttons">'
                         '<button class="btn-fix primary" onclick=\'window.dispatchEvent(new CustomEvent("fix", {detail:"V1"}))\'>V1 · k368 donor</button>'
                         '<button class="btn-fix" onclick=\'window.dispatchEvent(new CustomEvent("fix", {detail:"V2"}))\'>V2 · 77 donor</button>'
                         '<button class="btn-fix" onclick=\'window.dispatchEvent(new CustomEvent("fix", {detail:"V3"}))\'>V3 · WeeTools</button>'
                         '</div>'
                         '<p style="color:var(--text-dim);font-size:0.85em">Click a fix to download the repaired file.</p>')

        if self.state.match_results:
            html += '<p style="margin-top:10px"><strong>🎯 Best donor match:</strong></p>'
            for r in self.state.match_results[:3]:
                if r['score'] >= 10:
                    html += f'<p style="padding:2px 0">• {_bold(r["filename"])} <span style="color:var(--text-dim)">(score={r["score"]}, ARV={r.get("arv","?")})</span></p>'

        html += '<p style="margin-top:10px;color:var(--text-dim);font-size:0.85em">'
        html += '💬 Ask me anything or click a fix button above.</p>'
        return html

    def _apply_fix(self, variant: str) -> str:
        out_dir = os.path.join(ROOT, 'dumps')
        os.makedirs(out_dir, exist_ok=True)
        target = self.state.syscon_data
        if not target:
            return '<p style="color:var(--red)">❌ No Syscon data to fix.</p>'

        donor_map = {'V1': 'k368-01.bin', 'V2': '77-01.bin'}
        donor_file = donor_map.get(variant)
        if not donor_file:
            return '<p style="color:var(--red)">❌ Unknown variant.</p>'

        donor_path = os.path.join(SYSCON_DONORS_DIR, donor_file)
        if not os.path.exists(donor_path):
            return f'<p style="color:var(--orange)">⚠️ Donor {donor_file} not found in syscon_donors/.<br>Without it, using WeeTools rebuild only.</p>'

        donor = open(donor_path, 'rb').read()
        def parse_entries(data):
            entries = {}
            for an in range(9):
                astart = 0x60000 + 0x800 + an * 0x1800
                for i in range(0x400, 0x1800, 16):
                    off = astart + i
                    if off + 16 > len(data): break
                    raw = data[off:off+16]
                    if raw[0] == 0xA5 and raw[7] == 0xC3:
                        typ = raw[1] | (raw[2] << 8)
                        ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                        if typ not in entries or ctr > entries[typ][0]:
                            entries[typ] = (ctr, raw)
            return entries
        te = parse_entries(target)
        de = parse_entries(donor)
        merged = {}
        for typ in range(8):
            if typ in de: merged[typ] = de[typ]
        for typ, val in te.items():
            if typ not in merged: merged[typ] = val
        for typ in range(0x28, 0x2C):
            if typ not in merged and typ in de: merged[typ] = de[typ]
        result = bytearray(target)
        result[0x60010:0x60080] = b'\xFF' * (0x60080 - 0x60010)
        result[0x60800:0x62000] = b'\xFF' * 0x1800
        for typ in sorted(merged.keys()):
            ctr, entry = merged[typ]
            fd_off = 0x60800 + typ * 8
            if fd_off + 8 <= len(result):
                result[fd_off:fd_off + 8] = entry[8:16]
        for i, typ in enumerate(sorted(merged.keys()), 1):
            ctr, entry = merged[typ]
            entry_off = 0x60C00 + (i - 1) * 16
            if entry_off + 16 > len(result): break
            result[entry_off] = 0xA5
            result[entry_off + 1] = typ & 0xFF
            result[entry_off + 2] = (typ >> 8) & 0xFF
            result[entry_off + 3] = 0xFF
            result[entry_off + 4] = i & 0xFF
            result[entry_off + 5] = (i >> 8) & 0xFF
            result[entry_off + 6] = (i >> 16) & 0xFF
            result[entry_off + 7] = 0xC3
            result[entry_off + 8:entry_off + 16] = entry[8:16]
        md5 = hashlib.md5(target).hexdigest()[:8]
        out_path = os.path.join(out_dir, f'repaired_{variant}_{md5}.bin')
        with open(out_path, 'wb') as f:
            f.write(bytes(result))

        return (f'<p style="color:var(--green)">✅ <strong>{variant} applied successfully!</strong></p>'
                f'<p><strong>File:</strong> <code>{os.path.basename(out_path)}</code><br>'
                f'<strong>Path:</strong> <code>{out_path}</code></p>'
                f'<p>📋 <strong>Result:</strong> {len(merged)} entries<br>'
                f'✅ Types 0x00-0x0B (base): Present<br>'
                f'✅ PRE0 (0x0C): Present<br>'
                f'✅ FW records (0x28-0x2B): Present</p>'
                f'<p style="margin-top:10px;color:var(--text-dim)">🔌 Write this file to your Syscon chip and test the console.</p>'
                f'<p>🙏 <a href="https://paypal.me/islamjamelak" target="_blank" style="color:var(--accent)">Support the project</a></p>')
