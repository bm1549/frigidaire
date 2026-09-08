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


class AuthenticationError(FrigidaireException):
    """The account credentials were rejected. Retrying will not help; new credentials are needed."""


class SessionCapError(FrigidaireException):
    """Electrolux's active-session cap (``cas_3403``) was hit.

    Minting another session makes this worse. Back off and retry later on the same session.
    """
