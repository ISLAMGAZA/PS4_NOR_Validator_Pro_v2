"""
LLM-Powered PS4 Repair Agent — uses Ollama (phi3:mini) locally.
Falls back to rule-based agent when Ollama is unavailable.
"""

import os, json, re, subprocess, time, threading, urllib.request, urllib.error
from typing import Optional, Dict, List, Any
from pathlib import Path

OLLAMA_URL = 'http://127.0.0.1:11434'
MODEL = 'phi3:mini'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SYSTEM_PROMPT = f"""You are PS4 Repair Agent, an expert on PlayStation 4 NOR and Syscon hardware diagnostics.

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

## NOR NVS Regions (identity)
- Board ID: 0x1C4000-0x1C4008
- MAC: 0x1C4010-0x1C4016
- Serial block: 0x1C8000-0x1C9000
- CID: 0x1CA000-0x1CD000
- CID CRC: 0x1C9000-0x1CA000
- HDD Metadata: 0x1C5000 (primary) and 0x1CE000 (mirror)
- EAP HDD Key: 0x1C91FC-0x1C9260
- NVS FW_VER at 0x1C906A

## Common Issues
1. Blue Light: Missing SSC/SSK types 0x00-0x07 in Syscon
2. No Boot: Corrupted EMC_IPL or CORE_SWCH
3. No WiFi/BT: MAC erased (ff:ff:ff:ff:ff:ff)
4. No HDD: Missing/damaged HDD metadata or EAP keys
5. Cannot Downgrade: CORE_SWCH mismatch or ARV too high

## Your Capabilities (TOOLS)
You have access to these functions that you can request:
1. analyze_nor(data) — returns SKU, FW, Board ID, MAC, active slot, health
2. analyze_syscon(data) — returns chip, ARV, entries, missing types, severity
3. get_arv(data) — returns anti-rollback version
4. diagnose(nor_info, syscon_info) — returns list of issues
5. match_syscon_to_nor(nor_info) — returns ranked donor list
6. apply_fix(variant, syscon_data) — applies V1/V2/V3 fix, returns repaired file

## Conversation Style
- Be direct and professional
- Use Arabic or English based on user language
- Ask for files when needed ("Please upload your NOR dump")
- Explain diagnostics clearly
- Suggest fixes with buttons

## Tools Implementation
When the user uploads files, call the appropriate analysis functions. When you need to suggest a fix, format it as:
FIX:V1
FIX:V2
FIX:V3
"""

class OllamaClient:
    def __init__(self):
        self.available = False
        self._check_ollama()

    def _check_ollama(self):
        try:
            r = urllib.request.urlopen(f'{OLLAMA_URL}/api/tags', timeout=2)
            if r.status == 200:
                self.available = True
        except:
            self.available = False

    def is_available(self):
        return self.available

    def generate(self, messages: list, tools_desc: str = '') -> str:
        if not self.available:
            return ''

        payload = json.dumps({
            'model': MODEL,
            'messages': messages,
            'stream': False,
            'options': {'temperature': 0.3, 'num_predict': 2048}
        }).encode()

        try:
            r = urllib.request.urlopen(
                f'{OLLAMA_URL}/api/chat',
                data=payload,
                timeout=60
            )
            result = json.loads(r.read())
            return result.get('message', {}).get('content', '')
        except Exception as e:
            return f'[LLM error: {e}]'

    def install_ollama(self):
        """Try to install Ollama silently or provide instructions."""
        return ('⚠️ Ollama is not installed. To enable AI-powered repair:\n\n'
                '1. Download Ollama from https://ollama.com\n'
                '2. Install and run it\n'
                '3. Open terminal and run: ollama pull phi3:mini\n'
                '4. Restart this application\n\n'
                'Without Ollama, basic rule-based analysis is still available.')

class LLMAgent:
    def __init__(self):
        self.ollama = OllamaClient()
        self.messages: List[Dict] = []
        self.state = {
            'nor_data': None, 'nor_name': '',
            'syscon_data': None, 'syscon_name': '',
            'nor_analysis': None, 'syscon_analysis': None,
            'diagnosis': [], 'match_results': [],
        }

    def process(self, msg: str, files: Dict[str, bytes] = None) -> Dict[str, Any]:
        # Store files in state
        if files:
            for name, data in files.items():
                if len(data) == 0x2000000:
                    self.state['nor_data'] = data
                    self.state['nor_name'] = name
                elif len(data) in (0x40000, 0x80000):
                    self.state['syscon_data'] = data
                    self.state['syscon_name'] = name

        # If Ollama is available, use it
        if self.ollama.is_available():
            response = self._llm_chat(msg)
            fix_match = re.search(r'FIX:(\w+)', response)
            if fix_match:
                fix_result = self._execute_fix(fix_match.group(1))
                response = response.replace(fix_match.group(0), '') + '\n\n' + fix_result
        else:
            # Fallback: try to install or use rule-based
            if not self.ollama.is_available():
                if files and any(len(d) == 0x2000000 for d in files.values()):
                    response = self._fallback_analysis(msg, files)
                elif any(w in msg.lower() for w in ['سلام', 'hello', 'hi', 'مرحبا']):
                    response = '🎮 Welcome to PS4 Repair Agent!\n\n' + self.ollama.install_ollama()
                else:
                    response = self.ollama.install_ollama()

        self.messages.append({'role': 'user', 'content': msg})
        self.messages.append({'role': 'assistant', 'content': response})

        return {
            'response': self._format_html(response),
            'has_nor': self.state['nor_data'] is not None,
            'has_syscon': self.state['syscon_data'] is not None,
            'state': 'diagnosed' if self.state['syscon_analysis'] else 'awaiting',
        }

    def _llm_chat(self, msg: str) -> str:
        # Analyze files if present
        tool_results = ''
        if self.state['nor_data'] and not self.state['nor_analysis']:
            from .server import analyze_nor
            self.state['nor_analysis'] = analyze_nor(self.state['nor_data'])
            n = self.state['nor_analysis']
            tool_results += f'[NOR Analysis: SKU={n["sku"]}, FW={n["fw"]}, Board={n["board_id"]}, MAC={n["mac"]}, Active={n["active_slot"]}, Healthy={n["healthy"]}]\n'
        if self.state['syscon_data'] and not self.state['syscon_analysis']:
            from .server import analyze_syscon, get_arv, diagnose
            self.state['syscon_analysis'] = analyze_syscon(self.state['syscon_data'])
            arv = get_arv(self.state['syscon_data'])
            self.state['syscon_analysis']['arv'] = arv
            s = self.state['syscon_analysis']
            tool_results += f'[Syscon Analysis: Chip={s["chip"]}, ARV={arv}, Severity={s["severity"]}, Entries={s["valid_entries"]}, Missing={s["missing_types"]}]\n'
            self.state['diagnosis'] = diagnose(self.state['nor_analysis'] or {}, self.state['syscon_analysis'])

        # Build message history
        system_msg = {'role': 'system', 'content': SYSTEM_PROMPT}
        msgs = [system_msg] + self.messages[-6:] + [{'role': 'user', 'content': tool_results + msg}]
        response = self.ollama.generate(msgs)
        return response or 'I encountered an error processing your request.'

    def _format_html(self, text: str) -> str:
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
        text = re.sub(r'\n', '<br>', text)
        text = re.sub(r'FIX:(\w+)', r'<button class="btn-fix primary" onclick="window.dispatchEvent(new CustomEvent(\'fix\',{detail:\'\1\'}))">Apply \1</button>', text)
        return f'<p>{text}</p>'

    def _fallback_analysis(self, msg: str, files: Dict[str, bytes]) -> str:
        """Rule-based fallback when Ollama is unavailable."""
        from .server import analyze_nor, analyze_syscon, get_arv, diagnose
        response = ''
        if self.state['nor_data']:
            n = analyze_nor(self.state['nor_data'])
            self.state['nor_analysis'] = n
            response += f'📀 NOR: {n["sku"]} FW {n["fw"]}\nBoard: {n["board_id"]}\n'
        if self.state['syscon_data']:
            s = analyze_syscon(self.state['syscon_data'])
            arv = get_arv(self.state['syscon_data'])
            s['arv'] = arv
            self.state['syscon_analysis'] = s
            response += f'🧩 Syscon: ARV={arv} Severity={s["severity"]}\n'
            self.state['diagnosis'] = diagnose(n, s) if n else []
            missing = [t for t in s.get('missing_types', []) if 0 <= t <= 7]
            if missing:
                response += '\n🔴 SSC/SSK keys missing — blue light cause!\nFIX:V1  FIX:V2  FIX:V3'
        if not response:
            response = self.ollama.install_ollama()
        return response

    def _execute_fix(self, variant: str) -> str:
        if not self.state['syscon_data']:
            return '❌ No syscon data loaded.'
        from .chat_agent import PS4ChatAgent
        # Reuse the fix logic from chat_agent
        agent = PS4ChatAgent()
        agent.state.syscon_data = self.state['syscon_data']
        return agent._apply_fix(variant)
