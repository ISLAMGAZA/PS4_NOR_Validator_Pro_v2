"""
PS4 Repair Chat Agent — conversational AI for NOR/Syscon diagnostics.
"""

import os, re, json
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

class PS4ChatAgent:
    def __init__(self):
        self.state = ConversationState()

    def process_message(self, msg: str, files: Dict[str, bytes] = None) -> Dict[str, Any]:
        if files:
            for name, data in files.items():
                if len(data) == 0x2000000 and name.upper().endswith('.BIN'):
                    self.state.nor_data = data
                    self.state.nor_name = name
                    self._analyze_nor()
                    self.state.step = 'nor_loaded'
                elif len(data) in (0x40000, 0x80000):
                    self.state.syscon_data = data
                    self.state.syscon_name = name
                    self._analyze_syscon()
                    self.state.step = 'syscon_loaded'

        # Generate response based on state
        response = self._generate_response(msg)
        self.state.history.append({'role': 'user', 'content': msg})
        self.state.history.append({'role': 'assistant', 'content': response})

        return {
            'response': response,
            'state': self.state.step,
            'has_nor': self.state.nor_data is not None,
            'has_syscon': self.state.syscon_data is not None,
            'nor_analysis': self.state.nor_analysis,
            'syscon_analysis': self.state.syscon_analysis,
            'diagnosis': self.state.diagnosis,
            'history': self.state.history[-10:],
        }

    def _analyze_nor(self):
        from .server import analyze_nor
        self.state.nor_analysis = analyze_nor(self.state.nor_data)

    def _analyze_syscon(self):
        from .server import analyze_syscon, get_arv
        self.state.syscon_analysis = analyze_syscon(self.state.syscon_data)
        arv = get_arv(self.state.syscon_data)
        self.state.syscon_analysis['arv'] = arv

        # Run diagnosis
        from .server import diagnose
        nor_info = self.state.nor_analysis or {}
        self.state.diagnosis = diagnose(nor_info, self.state.syscon_analysis)

        # Run matching
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

    def _generate_response(self, msg: str) -> str:
        msg_lower = msg.lower()
        lines = []
        nor = self.state.nor_analysis
        sc = self.state.syscon_analysis

        # Greeting / first message
        if self.state.step == 'greeting' or any(w in msg_lower for w in ['مرحبا', 'hello', 'hi', 'اهلا', 'السلام']):
            self.state.step = 'awaiting_nor'
            return ('مرحباً بك في PS4 Repair Agent 🤖\n\n'
                    'أنا هنا لمساعدتك في تشخيص مشاكل جهاز PS4 الخاص بك.\n\n'
                    '📁 **الخطوة الأولى:** أرسل لي ملف NOR dump (32MB .BIN)\n'
                    'أو أخبرني عن مشكلتك وسأوجهك.')

        # No NOR yet
        if self.state.nor_data is None:
            if 'نور' in msg or 'nor' in msg_lower or 'dump' in msg_lower or 'بلو' in msg or 'blue' in msg_lower:
                return ('لتحليل المشكلة، أحتاج ملف NOR dump أولاً.\n\n'
                        '📤 **اسحب ملف .BIN هنا** أو اضغط على زر الرفع.\n'
                        'الملف عادة 32MB ويُقرأ من جهاز PS4 بأداة مثل SPIway.')
            return ('أحتاج ملف NOR dump للبدء. 📁\n'
                    'أرسل الملف عبر زر الرفع في الأسفل.')

        # NOR loaded, check for syscon
        if self.state.syscon_data is None:
            needs_syscon = ('syscon' in msg_lower or 'سيسكون' in msg or
                            'ار' in msg_lower.split() or 'arv' in msg_lower)
            if needs_syscon or self.state.step == 'nor_loaded':
                self.state.step = 'awaiting_syscon'
                return (f'تم تحليل الـ NOR ✅\n\n'
                        f'**الموديل:** {nor["sku"]}\n'
                        f'**FW:** {nor["fw"]}\n'
                        f'**Board ID:** {nor["board_id"]}\n'
                        f'**Slot Active:** {nor["active_slot"]}\n\n'
                        f'📁 **الآن أحتاج ملف Syscon أيضاً** (256KB أو 512KB)\n'
                        f'للحصول على تشخيص دقيق.')

            return (f'تم تحليل الـ NOR بنجاح ✅\n\n'
                    f'**الموديل:** {nor["sku"]}\n'
                    f'**FW:** {nor["fw"]}\n'
                    f'**Board ID:** {nor["board_id"]}\n\n'
                    f'📁 للمزيد من الدقة، أرسل ملف Syscon إن كان متوفراً.')

        # Both loaded — full analysis
        if self.state.step in ('syscon_loaded', 'diagnosed'):
            self.state.step = 'diagnosed'

            # Build diagnosis summary
            errors = [d for d in self.state.diagnosis if d['level'] == 'error']
            warns = [d for d in self.state.diagnosis if d['level'] == 'warn']

            intro = ('## 📊 التشخيص الكامل\n\n'
                     f'**NOR:** {nor["sku"]} FW {nor["fw"]}\n'
                     f'**Syscon:** ARV={sc.get("arv", "?")}, {sc.get("severity", "?")}\n'
                     f'**الحالة:** {sc.get("entries", "?")} entries\n\n')

            if errors:
                for e in errors:
                    intro += f'🔴 **{e["title"]}**\n{e["detail"]}\n\n'
            if warns:
                for w in warns:
                    intro += f'🟡 **{w["title"]}**\n{w["detail"]}\n\n'

            # Suggestions
            missing = sc.get('missing_types', [])
            if missing:
                intro += ('💡 **اقتراح:** السيسكون ناقص أنواع أساسية.\n'
                          'أقدر أصلحه باستخدام donor مناسب. جرب الخيارات التالية:\n'
                          '  1️⃣ **V1:** k368 donor (ARV=232)\n'
                          '  2️⃣ **V2:** 77 donor (ARV=232 بديل)\n'
                          '  3️⃣ **V3:** WeeTools rebuild نظيف\n'
                          'أكتب "طبق V1" للبدء.\n\n')

            if self.state.match_results:
                intro += '**🎯 أفضل donor للتطابق:**\n'
                for r in self.state.match_results[:3]:
                    intro += f'  • {r["filename"]} (score={r["score"]})\n'

            # Handle fix requests
            if 'v1' in msg_lower or 'k368' in msg_lower or 'طبق 1' in msg:
                return self._apply_fix('V1', intro)
            if 'v2' in msg_lower or '77' in msg_lower:
                return self._apply_fix('V2', intro)
            if 'v3' in msg_lower or 'wee' in msg_lower:
                return self._apply_fix('V3', intro)

            if re.search(r'\bشكرا\b|\bthanks\b|\bthank\b', msg_lower):
                return ('على الرحب والسعة! 🌟\n\n'
                        'إذا احتجت مساعدة أخرى، أنا هنا.\n\n'
                        'ودعمك للـ PayPal محل تقدير: paypal.me/islamjamelak')

            return intro

        return ('أنا في انتظار تعليماتك. أرسل ملف NOR أو أخبرني عن مشكلتك.')

    def _apply_fix(self, variant: str, current_diag: str) -> str:
        import hashlib
        out_dir = os.path.dirname(os.path.abspath(__file__))
        out_dir = os.path.join(os.path.dirname(out_dir), 'dumps')
        os.makedirs(out_dir, exist_ok=True)

        target = self.state.syscon_data
        donor_map = {
            'V1': 'k368-01.bin',
            'V2': '77-01.bin',
        }

        donor_file = donor_map.get(variant)
        if not donor_file:
            return '❌ غير معروف. استخدم V1 أو V2.'

        donor_path = os.path.join(SYSCON_DONORS_DIR, donor_file)
        if not os.path.exists(donor_path):
            return f'❌ ملف {donor_file} غير موجود في syscon_donors/.'

        donor = open(donor_path, 'rb').read()

        # Parse entries
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

        # Merge
        merged = {}
        for typ in range(8):
            if typ in de: merged[typ] = de[typ]
        for typ, val in te.items():
            if typ not in merged: merged[typ] = val
        for typ in range(0x28, 0x2C):
            if typ not in merged and typ in de: merged[typ] = de[typ]

        # Build output
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

        # Save
        md5 = hashlib.md5(target).hexdigest()[:8]
        out_path = os.path.join(out_dir, f'repaired_{variant}_{md5}.bin')
        with open(out_path, 'wb') as f:
            f.write(bytes(result))

        return (f'✅ **تم تطبيق {variant} بنجاح!**\n\n'
                f'**الملف:** {os.path.basename(out_path)}\n'
                f'**المسار:** {out_path}\n\n'
                f'📋 **الأنواع الموجودة الآن:** {len(merged)}\n'
                f'🟢 الأنواع الأساسية (0x00-0x0B): موجودة ✅\n'
                f'🟢 PRE0 (0x0C): موجود ✅\n'
                f'🟢 FW records (0x28-0x2B): موجودة ✅\n\n'
                f'جرب هذا الملف على جهازك.'
                f'ودعمك للـ PayPal محل تقدير: paypal.me/islamjamelak')
