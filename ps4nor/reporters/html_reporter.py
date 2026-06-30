import os
import time


class HTMLReporter:
    def __init__(self, result):
        self.result = result

    CSS_STYLE = """
    <style>
    body {
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        padding: 20px 50px 150px;
        font-size: 12px;
        text-align: left;
        margin-left: auto;
        margin-right: auto;
        background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
        background-size: 400% 400%;
        animation: gradient 15s ease infinite;
    }
    @keyframes gradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    .box {
        width: 800px;
        margin-left: auto;
        margin-right: auto;
        padding: 21px;
        background-color: #FFFFFF;
        word-break: break-all;
    }
    .ok { color: green; }
    .warning { color: orange; }
    .danger { color: red; font-weight: bold; }
    .unlisted { color: blue; }
    a:link { color: #A4A4A4; }
    a:visited { color: #A4A4A4; }
    a:hover { color: #A4A4A4; }
    </style>
    """

    def generate(self):
        r = self.result
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PS4 NOR Validator Pro - Report</title>
    {self.CSS_STYLE}
</head>
<body>
    <a name="Top"></a>
    <table class="box"><tr><td>
    <h2>PS4 NOR Validator Pro - Validation Report</h2>
    <hr>
    <b>Filename:</b> {r.filename}<br>
    <b>File Size:</b> {r.file_size:,} bytes<br>
    <b>MD5:</b> {r.md5}<br>
    <b>SKU:</b> {r.sku}<br>
    <b>Model:</b> {r.model_type}<br>
    <b>Region:</b> {r.region}<br>
    <b>Firmware:</b> {r.fw_version}<br>
    <b>MB Serial:</b> {r.mobo_serial}<br>
    <b>SHA256:</b> {r.sha256[:32]}...<br>
    <b>Overall Entropy:</b> {r.entropy_overall:.2f}<br>
    <b>Validation Date:</b> {r.validation_date}<br>
    <b>Validator Version:</b> 1.0.0<br>
    <hr>
    <h3>Summary</h3>
    <b>OK:</b> <span class="ok">{r.ok_count}</span><br>
    <b>Warning:</b> <span class="warning">{r.warning_count}</span><br>
    <b>Danger:</b> <span class="danger">{r.danger_count}</span><br>
    <b>Unlisted:</b> <span class="unlisted">{r.unlisted_count}</span><br>
    <hr>
    <h3>Diagnosis</h3>
"""

        if r.diagnosis:
            for diag in r.diagnosis:
                html += f'<span class="danger">&#9888;</span> {diag}<br>\n'
            if r.suggestions:
                html += '<br><b>Suggestions:</b><br>\n'
                for s in r.suggestions:
                    html += f'<span class="ok">&#9654;</span> {s}<br>\n'
        else:
            html += '<span class="ok">No critical issues detected</span><br>\n'

        html += """<hr>
    <h3>Detailed Results</h3>
    """

        for res in r.results:
            cls = res["status"].lower()
            icon = {"ok": "&#10004;", "warning": "&#9888;", "danger": "&#10008;", "unlisted": "&#9888;"}.get(cls, "&#10004;")
            offset_str = f"0x{res['offset_start']:06X} -> 0x{res['offset_end']:06X}"
            html += f'<span class="{cls}">[{res["status"]}]</span> <b>{res["section"]}</b> ({offset_str}): {res["message"]}<br>\n'

        html += f"""
    <hr>
    <b>Time to calculate:</b> {r.elapsed:.3f} seconds.
    <br><br>
    <div style="text-align:right; float:right"><a href="#Top">Return</a></div>
    </td></tr></table>
</body>
</html>"""
        return html

    def save(self, output_path):
        html = self.generate()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path
