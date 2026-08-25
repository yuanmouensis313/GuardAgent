from __future__ import annotations

import uvicorn

from guardd.api import create_app
from guardd.config import Settings


def run(settings: Settings | None = None) -> None:
    settings = settings or Settings.from_env()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, access_log=False)


def main() -> None:
    run()


if __name__ == "__main__":
    main()
