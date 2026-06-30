import json


class JSONReporter:
    def __init__(self, result):
        self.result = result

    def generate(self):
        r = self.result
        return json.dumps({
            "filename": r.filename,
            "filepath": r.filepath,
            "file_size": r.file_size,
            "md5": r.md5,
            "sha256": r.sha256,
            "sku": r.sku,
            "model_type": r.model_type,
            "region": r.region,
            "fw_version": r.fw_version,
            "mobo_serial": r.mobo_serial,
            "entropy_overall": r.entropy_overall,
            "validation_date": r.validation_date,
            "elapsed": r.elapsed,
            "summary": {
                "ok": r.ok_count,
                "warning": r.warning_count,
                "danger": r.danger_count,
                "unlisted": r.unlisted_count,
                "total": len(r.results),
            },
            "results": r.results,
            "diagnosis": r.diagnosis,
            "suggestions": r.suggestions,
        }, indent=2)

    def save(self, output_path):
        data = self.generate()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(data)
        return output_path
