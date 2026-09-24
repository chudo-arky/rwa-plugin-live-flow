"""Текст релиза: раздел CHANGELOG.md этой версии + установка + sha256 файлов из dist/.

Запускается workflow ``release``; версия берётся из pyproject.toml.
"""
from __future__ import annotations

import hashlib
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = "https://github.com/chudo-arky/rwa-plugin-live-flow"


def version() -> str:
    with open(ROOT / "pyproject.toml", "rb") as f:
        return tomllib.load(f)["project"]["version"]


def changelog_section(ver: str) -> str:
    """Тело раздела ``## [ver]`` без самого заголовка, до следующего ``## [``."""
    lines = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
    head = f"## [{ver}]"
    start = next((i for i, ln in enumerate(lines) if ln.startswith(head)), None)
    if start is None:
        raise SystemExit(f"CHANGELOG.md: нет раздела {head}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
    return "\n".join(lines[start + 1:end]).strip()


def main() -> None:
    ver = version()
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(ver)
        return
    files = sorted((ROOT / "dist").glob(f"rwa_plugin_live_flow-{ver}*"))
    if not files:
        raise SystemExit("dist/: нет собранных файлов этой версии")
    wheel = f"rwa_plugin_live_flow-{ver}-py3-none-any.whl"
    rows = "\n".join(f"| `{p.name}` | `{hashlib.sha256(p.read_bytes()).hexdigest()}` |" for p in files)
    print(f"""{changelog_section(ver)}

Подробности по каждой версии — в [CHANGELOG]({REPO}/blob/main/CHANGELOG.md).

### Установка и обновление
Скачайте `{wheel}` и поставьте через страницу «Плагины» админки (или положите в `plugins/` и перезапустите backend). Требования — в разделе «Совместимость» README; для списков «по факту» нужны remnawave-admin ≥ 4.8.3 и агент нод ≥ 1.8.3.

| Файл | sha256 |
|---|---|
{rows}""")


if __name__ == "__main__":
    main()
