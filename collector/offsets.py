import json
from pathlib import Path


class OffsetStore:
    def __init__(self, path: Path):
        self.path = path
        try: self.values = {k: int(v) for k, v in json.loads(path.read_text()).items()}
        except (FileNotFoundError, json.JSONDecodeError): self.values = {}
    def get(self, path: Path): return self.values.get(str(path.resolve()))
    def set(self, path: Path, offset: int):
        self.values[str(path.resolve())] = offset
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(self.values)); temp.replace(self.path)
