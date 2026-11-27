"""Exceptions raised by the Frigidaire client."""

from __future__ import annotations


class FrigidaireException(Exception):
    """Base class for every error the client raises.

    ``status_code`` and ``error_code`` carry the HTTP status and the platform error code
    (for example ``cas_3403``) when the failure came from an API response.
    """

    def __init__(self, message: str, *, status_code: int | None = None, error_code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class LoginError(FrigidaireException):
    """The identity provider rejected the login for any reason (bad credentials, an account in a
    transient state, an account without a password). Setup flows can treat this as "check your
    login"; only the ``AuthenticationError`` subclass is certain enough to prompt for new credentials."""


class AuthenticationError(LoginError):
    """The account credentials were rejected. Retrying will not help; new credentials are needed."""


class SessionCapError(FrigidaireException):
    """Electrolux's active-session cap (``cas_3403``) was hit.

    Minting another session makes this worse. Back off and retry later on the same session.
    """


class QuotaExceededError(FrigidaireException):
    """The API's request quota is used up (HTTP 429 after the backend's own retries).

    ``retry_after`` is the server's hint, in seconds, for when to try again, or ``None`` when it
    gave none. Back off at least that long; retrying sooner spends quota without succeeding.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        status_code: int | None = None,
        error_code: str | None = None,
    ):
        super().__init__(message, status_code=status_code, error_code=error_code)
        self.retry_after = retry_after


class CommandRejectedError(FrigidaireException):
    """The appliance refused a command it cannot accept in its current state, for example a target
    humidity outside Dry mode. Retrying the same command will not help; the message says what was
    refused."""
