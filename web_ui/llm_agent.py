"""
LLM-Powered PS4 Repair Agent — auto-downloads Ollama + phi3:mini.
Zero user configuration needed.
"""

import os, json, re, subprocess, time, threading, urllib.request, urllib.error, sys, platform
from typing import Optional, Dict, List, Any
from pathlib import Path

OLLAMA_URL = 'http://127.0.0.1:11434'
OLLAMA_DL = 'https://ollama.com/download/OllamaSetup.exe'
MODEL = 'phi3:mini'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SYSTEM_PROMPT = """You are PS4 Repair Agent, an expert on PlayStation 4 NOR and Syscon hardware diagnostics.

## PS4 Boot Chain Knowledge
- SCE Header (0x0000-0x0FFF): BootROM validation region
- Active Slot at 0x1000: 0x00=Slot A, 0x80=Slot B
- SLB2 at 0x2000: Secure boot partition marker, starts with 'Sony'
- EMC_IPL_A (0x4000-0x64000): Firmware region for Slot A
- EMC_IPL_B (0x64000-0xC4000): Firmware region for Slot B
- CoreOS_A (0x3C0000-0x1080000): Main OS for Slot A
- CoreOS_B (0x1080000-0x1D40000): Main OS for Slot B

## Syscon (SNVS) Structure
- SNVS Header at 0x60000: starts with A5 ... C3 markers
- Entries at 0x60C00+: 16-byte records, type at byte1, counter at bytes4-6
- Types: 0x00-0x0B (base), 0x0C-0x0F (PRE0-PRE3 eFuse), 0x28-0x2B (FW records)
- Types 0x00-0x07 = SSC/SSK keys (MODE0-3, BOOT0-3) — MISSING = BLUE LIGHT
- PRE0 (type 0x0C) at byte1 OR type 0x1B (alternate): ARV (anti-rollback) at raw[8]
- FW Area (0x000-0x60000): RL78 firmware, first bytes 0x80 0x01

## Chip Mapping
- CXD90025G: CUH-10xx/11xx (256KB syscon, FAT)
- CXD90044G: CUH-12xx/20xx/21xx/22xx (512KB syscon, Slim)
- CXD90068G: CUH-70xx/71xx/72xx (512KB syscon, Pro)

## Common Issues
1. Blue Light: Missing SSC/SSK types 0x00-0x07 in Syscon
2. No Boot: Corrupted EMC_IPL or CORE_SWCH
3. No WiFi/BT: MAC erased (ff:ff:ff:ff:ff:ff)
4. No HDD: Missing/damaged HDD metadata or EAP keys
5. Cannot Downgrade: CORE_SWCH mismatch or ARV too high

## Tools Available
1. analyze_nor(data) — SKU, FW, Board ID, MAC, active slot, health
2. analyze_syscon(data) — chip, ARV, entries, missing types, severity
3. diagnose(nor, syscon) — list of issues found
4. match_syscon_to_nor(nor_info) — ranked donor list
5. apply_fix(variant, syscon_data) — V1/V2/V3 fix, returns repaired file

## Conversation Style
- Be direct, professional. Use Arabic or English based on user language.
- When user uploads files, analyze them and report findings.
- When you suggest a fix, ALWAYS include FIX:V1 FIX:V2 FIX:V3 on a separate line.
"""


class OllamaManager:
    def __init__(self):
        self.available = False
        self.installing = False
        self.install_progress = ''
        self.model_ready = False
        self._check()

    def _check(self):
        try:
            r = urllib.request.urlopen(f'{OLLAMA_URL}/api/tags', timeout=2)
            if r.status == 200:
                self.available = True
                models = json.loads(r.read()).get('models', [])
                self.model_ready = any(MODEL in m.get('name', '') for m in models)
        except:
            self.available = False

    def auto_setup(self, status_callback=None):
        """Full auto-setup: install Ollama + pull model, no user interaction."""
        if self.available and self.model_ready:
            if status_callback: status_callback('ready', 'AI engine ready ✅')
            return True

        if not self.available:
            self.installing = True
            if status_callback: status_callback('downloading', 'Downloading Ollama... (180MB)')
            self._download_ollama(status_callback)
            if status_callback: status_callback('installing', 'Installing Ollama...')
            self._install_ollama_silent(status_callback)
            self._wait_for_ollama(status_callback)

        if self.available and not self.model_ready:
            if status_callback: status_callback('pulling', f'Downloading {MODEL} model... (2.3GB, first time only)')
            self._pull_model(status_callback)
            if status_callback: status_callback('ready', 'AI engine ready ✅')

        self.installing = False
        return self.available and self.model_ready

    def _download_ollama(self, cb=None):
        try:
            req = urllib.request.Request(OLLAMA_DL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=300) as src:
                data = src.read()
            installer = os.path.join(os.environ.get('TEMP', os.path.expanduser('~')), 'OllamaSetup.exe')
            with open(installer, 'wb') as f:
                f.write(data)
            if cb: cb('installing', 'Installing Ollama...')
            subprocess.run([installer, '/S'], shell=True, timeout=120)
            time.sleep(3)
            if cb: cb('starting', 'Starting Ollama...')
            subprocess.run(['taskkill', '/f', '/im', 'ollama.exe'], shell=True, timeout=5, capture_output=True)
            time.sleep(2)
            subprocess.Popen(['ollama', 'serve'], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(5)
        except Exception as e:
            if cb: cb('error', f'Download/install failed: {e}')

    def _install_ollama_silent(self, cb=None):
        try:
            installer = os.path.join(os.environ.get('TEMP', os.path.expanduser('~')), 'OllamaSetup.exe')
            if os.path.exists(installer):
                subprocess.run([installer, '/S'], shell=True, timeout=120)
                time.sleep(5)
                if cb: cb('starting', 'Starting Ollama...')
                subprocess.Popen(['ollama', 'serve'], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass

    def _wait_for_ollama(self, cb=None):
        for i in range(30):
            try:
                r = urllib.request.urlopen(f'{OLLAMA_URL}/api/tags', timeout=2)
                if r.status == 200:
                    self.available = True
                    return
            except:
                pass
            if cb: cb('waiting', f'Waiting for Ollama... ({i+1}/30)')
            time.sleep(2)

    def _pull_model(self, cb=None):
        try:
            payload = json.dumps({'name': MODEL, 'stream': False}).encode()
            r = urllib.request.urlopen(f'{OLLAMA_URL}/api/pull', data=payload, timeout=1800)
            result = json.loads(r.read())
            if result.get('status') == 'success':
                self.model_ready = True
        except Exception as e:
            if cb: cb('error', f'Model pull failed: {e}')
            self.model_ready = True  # try anyway


class LLMAgent:
    def __init__(self):
        self.ollama = OllamaManager()
        self.messages: List[Dict] = []
        self.setup_status = 'checking'
        self.state = {
            'nor_data': None, 'nor_name': '',
            'syscon_data': None, 'syscon_name': '',
            'nor_analysis': None, 'syscon_analysis': None,
            'diagnosis': [], 'match_results': [],
        }
        # Auto-setup in background
        threading.Thread(target=self._auto_setup_bg, daemon=True).start()

    def _auto_setup_bg(self):
        self.ollama.auto_setup(status_callback=self._on_setup_status)

    def _on_setup_status(self, status: str, msg: str):
        self.setup_status = f'{status}:{msg}'

    def get_setup_status(self) -> str:
        return self.setup_status

    def process(self, msg: str, files: Dict[str, bytes] = None) -> Dict[str, Any]:
        if files:
            for name, data in files.items():
                if len(data) == 0x2000000:
                    self.state['nor_data'] = data
                    self.state['nor_name'] = name
                elif len(data) in (0x40000, 0x80000):
                    self.state['syscon_data'] = data
                    self.state['syscon_name'] = name

        # Refresh ollama check
        self.ollama._check()

        if self.ollama.available and self.ollama.model_ready:
            response = self._llm_chat(msg)
            fix_match = re.search(r'FIX:(\w+)', response)
            if fix_match:
                fix_result = self._execute_fix(fix_match.group(1))
                response = response.replace(fix_match.group(0), '') + '\n\n' + fix_result
        elif self.ollama.installing:
            response = '⏳ AI engine is being set up automatically...\nThis may take a few minutes on first run.\nPlease wait, analysis still works without AI.'
        else:
            if files:
                response = self._fallback_analysis(msg, files)
            elif any(w in msg.lower() for w in ['سلام', 'hello', 'hi', 'مرحبا', 'welcome']):
                response = ('🎮 Welcome to **PS4 Repair Agent**!\n\n'
                            '🤖 **AI engine is setting up automatically...**\n'
                            'Installing Ollama + phi3:mini model (~2.3GB first run).\n'
                            'Meanwhile, upload your NOR dump for instant analysis!')
            else:
                self.ollama.auto_setup()
                response = '🤖 AI engine is setting up... Upload your NOR dump and I\'ll analyze it right away!'

        self.messages.append({'role': 'user', 'content': msg})
        self.messages.append({'role': 'assistant', 'content': response})
        return {
            'response': self._format_html(response),
            'has_nor': self.state['nor_data'] is not None,
            'has_syscon': self.state['syscon_data'] is not None,
            'setup_status': self.setup_status,
        }

    def _llm_chat(self, msg: str) -> str:
        tool_results = ''
        if self.state['nor_data'] and not self.state['nor_analysis']:
            from .server import analyze_nor
            self.state['nor_analysis'] = analyze_nor(self.state['nor_data'])
            n = self.state['nor_analysis']
            tool_results += f'[NOR: SKU={n["sku"]} FW={n["fw"]} Board={n["board_id"]} MAC={n["mac"]} Active={n["active_slot"]} Healthy={n["healthy"]}]\n'
        if self.state['syscon_data'] and not self.state['syscon_analysis']:
            from .server import analyze_syscon, get_arv, diagnose
            self.state['syscon_analysis'] = analyze_syscon(self.state['syscon_data'])
            arv = get_arv(self.state['syscon_data'])
            self.state['syscon_analysis']['arv'] = arv
            s = self.state['syscon_analysis']
            tool_results += f'[Syscon: Chip={s["chip"]} ARV={arv} Sev={s["severity"]} Entries={s["valid_entries"]} Missing={s["missing_types"]}]\n'
            self.state['diagnosis'] = diagnose(self.state['nor_analysis'] or {}, self.state['syscon_analysis'])

        system_msg = {'role': 'system', 'content': SYSTEM_PROMPT}
        msgs = [system_msg] + self.messages[-6:] + [{'role': 'user', 'content': tool_results + msg}]
        reply = self.ollama.generate(msgs)
        return reply or 'Analysis complete. Please check the results below.'

    def _format_html(self, text: str) -> str:
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
        text = re.sub(r'FIX:(\w+)', r'<button class="btn-fix primary" onclick="window.dispatchEvent(new CustomEvent(\'fix\',{detail:\'\1\'}))">Apply \1</button>', text)
        return '<p>' + text.replace('\n', '<br>') + '</p>'

    def _fallback_analysis(self, msg: str, files: Dict[str, bytes]) -> str:
        from .server import analyze_nor, analyze_syscon, get_arv, diagnose
        r = ''
        if self.state['nor_data']:
            n = analyze_nor(self.state['nor_data'])
            self.state['nor_analysis'] = n
            r += f'📀 NOR: {n["sku"]} FW {n["fw"]}\nBoard: {n["board_id"]}\n'
        if self.state['syscon_data']:
            s = analyze_syscon(self.state['syscon_data'])
            s['arv'] = get_arv(self.state['syscon_data'])
            self.state['syscon_analysis'] = s
            r += f'🧩 Syscon: ARV={s["arv"]} Severity={s["severity"]}\n'
            self.state['diagnosis'] = diagnose(n, s) if n else []
            missing = [t for t in s.get('missing_types', []) if 0 <= t <= 7]
            if missing:
                r += '\n🔴 SSC/SSK keys missing — blue light cause!\nFIX:V1  FIX:V2  FIX:V3'
        if not r:
            r = 'Upload a NOR dump to begin analysis.'
        return r

    def _execute_fix(self, variant: str) -> str:
        if not self.state['syscon_data']:
            return '❌ No syscon data loaded.'
        from .chat_agent import PS4ChatAgent
        a = PS4ChatAgent()
        a.state.syscon_data = self.state['syscon_data']
        return a._apply_fix(variant)

    def generate(self, messages: list, tools_desc: str = '') -> str:
        """Convenience wrapper for OllamaClient.generate."""
        return self.ollama.generate(messages)
