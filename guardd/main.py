from __future__ import annotations

import uvicorn

from guardd.api import create_app
from guardd.config import Settings


def main() -> None:
    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, access_log=False)


if __name__ == "__main__":
    main()
