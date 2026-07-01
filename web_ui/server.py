"""
PS4 Repair Agent — Local Web UI + Chat AI
"""

import os, sys, json, webbrowser
from flask import Flask, request, jsonify, render_template, send_from_directory

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024

_agent = None

def get_agent():
    global _agent
    if _agent is None:
        from .llm_agent import LLMAgent
        _agent = LLMAgent()
    return _agent

def analyze_nor(data: bytes) -> dict:
    from ps4nor.utils.helpers import detect_sku, detect_fw_version, detect_active_slot
    mac = data[0x1C4010:0x1C4016].hex(':') if len(data) > 0x1C4016 else 'N/A'
    bid = data[0x1C4000:0x1C4008].hex() if len(data) > 0x1C4008 else 'N/A'
    active = detect_active_slot(data)
    nz = sum(1 for b in data[:0x1000] if b not in (0,0xFF))
    healthy = nz > 20
    return {
        'sku': detect_sku(data) or 'Unknown',
        'fw': detect_fw_version(data) or 'Unknown',
        'board_id': bid,
        'mac': mac,
        'active_slot': active,
        'healthy': healthy,
    }

def analyze_syscon(data: bytes) -> dict:
    from ps4nor.v2_features.syscon_analyzer import analyze_syscon
    r = analyze_syscon(data)
    return {
        'chip': 'CXD90044G' if len(data) == 0x80000 else 'CXD90025G',
        'arv': -1,
        'fw_healthy': r.firmware['healthy'],
        'valid_entries': r.entries['valid'],
        'severity': r.severity,
        'missing_types': r.entries.get('missing_types', []),
        'summary': r.summary,
        'entries': r.entries['detail'],
    }

def get_arv(data: bytes) -> int:
    pre0_types = {0x0C, 0x1B, 0x14, 0x18}
    best_arv, best_ctr = -1, -1
    for area_n in range(9):
        astart = 0x60000 + 0x800 + area_n * 0x1800
        for i in range(0x400, 0x1800, 16):
            off = astart + i
            if off + 16 > len(data): break
            raw = data[off:off+16]
            if raw[0] == 0xA5 and raw[7] == 0xC3:
                typ = raw[1] | (raw[2] << 8)
                ctr = raw[4] | (raw[5] << 8) | (raw[6] << 16)
                if typ in pre0_types and ctr > best_ctr:
                    best_ctr = ctr
                    best_arv = raw[8]
    return best_arv

def diagnose(nor: dict, syscon: dict) -> list:
    issues = []
    if not nor['healthy']:
        issues.append({'level': 'error', 'title': 'NOR header corrupt',
                       'detail': 'SCE header region (0x000-0x1000) has invalid data. The NOR dump may be incomplete or damaged.'})
    if syscon:
        mt = syscon.get('missing_types', [])
        missing_ssc = [t for t in mt if 0 <= t <= 7]
        if missing_ssc:
            issues.append({'level': 'error', 'title': 'Syscon missing SSC/SSK keys',
                           'detail': f'Types {[hex(t) for t in missing_ssc]} are missing. This causes blue light — the syscon cannot generate boot keys.'})
        if syscon['severity'] in ('severe', 'critical'):
            issues.append({'level': 'error', 'title': 'Syscon severely damaged',
                           'detail': syscon['summary']})
        if syscon.get('arv', -1) < 0:
            issues.append({'level': 'warn', 'title': 'ARV not detected',
                           'detail': 'Anti-rollback version not found. Syscon may be from an unknown firmware or damaged.'})
    if nor.get('mac', '').startswith('ff:ff'):
        issues.append({'level': 'warn', 'title': 'MAC address erased',
                       'detail': 'WiFi/Bluetooth will not function. The console can still boot but network features are disabled.'})
    return issues

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

@app.route('/analyze', methods=['POST'])
def analyze():
    nor_data = request.files.get('nor').read() if 'nor' in request.files else None
    syscon_data = request.files.get('syscon').read() if 'syscon' in request.files else None
    if not nor_data:
        return jsonify({'error': 'NOR file required'}), 400

    nor = analyze_nor(nor_data)
    syscon = analyze_syscon(syscon_data) if syscon_data else None

    # Get ARV
    arv = -1
    if syscon_data:
        arv = get_arv(syscon_data)
        if syscon:
            syscon['arv'] = arv

    # Match
    from ps4nor.v2_features.syscon_fw_db import match_syscon_to_nor
    nor_info = {
        'board_id': nor['board_id'], 'sku': nor['sku'],
        'fw': nor['fw'], 'eap_md5': '', '_path': '',
    }
    donors_dir = os.path.join(ROOT, 'syscon_donors')
    match_results = match_syscon_to_nor(nor_info, donors_dir if os.path.isdir(donors_dir) else None)
    status = 'matched' if match_results and match_results[0]['score'] >= 60 else 'unknown'
    detail = 'Best donor: ' + match_results[0]['filename'] if match_results else 'No donors found'

    return jsonify({
        'nor': nor,
        'syscon': syscon,
        'diagnosis': diagnose(nor, syscon),
        'match': {
            'status': status,
            'detail': detail,
            'donors': match_results[:5] if match_results else [],
        },
    })

@app.route('/chat', methods=['POST'])
def chat():
    msg = request.form.get('message', '')
    files = {}
    if 'nor' in request.files:
        f = request.files['nor']
        files[f.filename] = f.read()
    if 'syscon' in request.files:
        f = request.files['syscon']
        files[f.filename] = f.read()

    agent = get_agent()
    result = agent.process(msg, files)
    return jsonify(result)

@app.route('/fix', methods=['POST'])
def fix():
    variant = request.json.get('variant', 'V1')
    agent = get_agent()
    result = agent._execute_fix(variant)
    return jsonify({'response': result})

def main(port=5050):
    print(f'  PS4 Repair Agent — http://localhost:{port}')
    webbrowser.open(f'http://localhost:{port}')
    app.run(host='127.0.0.1', port=port, debug=False)

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050
    main(port)
