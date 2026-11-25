"""One error format for every response: {"error": {"code": ..., "message": ...}}.

Messages are written for people and never include stack traces, SQL or input
values.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

log = logging.getLogger("whence.api")

STATUS_CODES = {404: "not_found", 405: "method_not_allowed"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def error_response(status: int, code: str, message: str) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    body = {"error": {"code": code, "message": message}}
    return JSONResponse(body, status_code=status, headers=headers)


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def api_error(_: Request, error: ApiError) -> JSONResponse:
        return error_response(error.status, error.code, error.message)

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, error: RequestValidationError) -> JSONResponse:
        # Name the fields that failed, never the values that were sent.
        fields = sorted({".".join(map(str, e["loc"][1:])) for e in error.errors()})
        message = "The request is not valid."
        body = {
            "error": {"code": "invalid_request", "message": message, "fields": fields}
        }
        return JSONResponse(body, status_code=422)

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, error: HTTPException) -> JSONResponse:
        code = STATUS_CODES.get(error.status_code, "http_error")
        return error_response(
            error.status_code, code, "That address does not exist here."
        )

    @app.exception_handler(Exception)
    async def unexpected(_: Request, error: Exception) -> JSONResponse:
        log.exception("Unhandled error", exc_info=error)
        return error_response(500, "internal_error", "Something went wrong. Try again.")
