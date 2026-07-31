import re
import uuid
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from backend.app.core.config import settings

REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing bounded Request IDs on all requests and response headers."""
    async def dispatch(self, request: Request, call_next):
        incoming_id = request.headers.get("X-Request-ID")
        if incoming_id and REQUEST_ID_REGEX.match(incoming_id):
            request_id = incoming_id
        else:
            request_id = str(uuid.uuid4())
        
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing Content-Type application/json and MAX_REQUEST_BODY_BYTES (413 & 415)."""
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            path = request.url.path
            request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

            # Check content type for events ingestion endpoints
            if "/api/v1/events" in path:
                content_type = request.headers.get("Content-Type", "")
                if "application/json" not in content_type.lower():
                    return JSONResponse(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        content={"detail": "Unsupported Media Type: Content-Type must be application/json"},
                        headers={"X-Request-ID": request_id}
                    )

            content_length = request.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
                        return JSONResponse(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            content={"detail": f"Payload Too Large. Maximum allowed size is {settings.MAX_REQUEST_BODY_BYTES} bytes"},
                            headers={"X-Request-ID": request_id}
                        )
                except ValueError:
                    pass

            body = await request.body()
            if len(body) > settings.MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": f"Payload Too Large. Maximum allowed size is {settings.MAX_REQUEST_BODY_BYTES} bytes"},
                    headers={"X-Request-ID": request_id}
                )

        return await call_next(request)
