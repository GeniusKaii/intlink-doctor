"""统一入口：python -m intlink_doctor [gui|analyze|...]"""
from __future__ import annotations

import sys


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("gui", "--gui", "-g"):
        from .gui import main as gui_main
        return gui_main()
    from .cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
