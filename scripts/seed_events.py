from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.api.routes import detector, store  # noqa: E402
from app.core.simulator import generate_events  # noqa: E402


def main() -> None:
    created = []
    for event in generate_events(mode="mixed", count=12):
        result = detector.analyze(event)
        store.append_event(result.event.model_dump(mode="json"))
        if result.alert:
            store.append_alert(result.alert.model_dump(mode="json"))
        created.append(result.model_dump(mode="json"))

    print(json.dumps({"generated": len(created)}, indent=2))


if __name__ == "__main__":
    main()
