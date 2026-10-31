"""Identity metadata from the authoritative HR schema, never a second table copy."""
from pathlib import Path
import yaml
_MANIFEST = yaml.safe_load((Path(__file__).parent / "schemas/hr.yaml").read_text(encoding="utf-8"))
WORLD_ID = _MANIFEST["world_id"]
WORLD_VERSION = _MANIFEST["world_version"]
REFERENCE_DATE = _MANIFEST["organization"]["reference_date"]
SERVER_PERSONAS = _MANIFEST["server_personas"]

HR_TABLE_COUNTS = {name: table["row_count"] for name, table in _MANIFEST["tables"].items()}
