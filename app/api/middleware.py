from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_DOCS_PATHS = ('/docs', '/redoc', '/openapi.json')


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, hsts: bool) -> None:
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers['X-Content-Type-Options'] = 'nosniff'
        headers['X-Frame-Options'] = 'DENY'
        headers['Referrer-Policy'] = 'no-referrer'
        headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
        headers.setdefault('Cache-Control', 'no-store')
        if not request.url.path.startswith(_DOCS_PATHS):
            headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        if self.hsts:
            headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response


class _BodyTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413, detail='request body too large')


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        length = dict(scope['headers']).get(b'content-length')
        if length is not None:
            if not length.isdigit():
                await JSONResponse({'detail': 'invalid Content-Length'}, status_code=400)(scope, receive, send)
                return
            if int(length) > self.max_bytes:
                await JSONResponse({'detail': 'request body too large'}, status_code=413)(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message['type'] == 'http.request':
                received += len(message.get('body', b''))
                if received > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message['type'] == 'http.response.start':
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if response_started:
                raise
            await JSONResponse({'detail': 'request body too large'}, status_code=413)(scope, receive, send)
