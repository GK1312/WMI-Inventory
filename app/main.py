import uvicorn

from api.app import create_app
from config import settings
from core.logging import setup_logging


def main() -> None:
    setup_logging(settings)
    uvicorn.run(
        create_app(settings),
        host=settings.api_host,
        port=settings.api_port,
        server_header=False,
        date_header=False,
        log_config=None,
        proxy_headers=True,
        forwarded_allow_ips='127.0.0.1',
    )


if __name__ == '__main__':
    main()
