"""Tests for RateLimiter and wrap_session_request."""

from unittest.mock import MagicMock

import pytest

from frigidaire.rate_limit import RateLimiter, _parse_retry_after_seconds, wrap_session_request

# --- _parse_retry_after_seconds ---


@pytest.mark.parametrize(
    "value,expected",
    [("2", 2.0), ("0.5", 0.5), ("0", 0.0), ("", None), (None, None), ("not-a-number", None)],
)
def test_parse_retry_after(value: str | None, expected: float | None) -> None:
    assert _parse_retry_after_seconds(value) == expected


# --- RateLimiter ---


class FakeClock:
    """Monkey-patchable replacement for time.monotonic and time.sleep."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleep_calls: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    c = FakeClock()
    monkeypatch.setattr("frigidaire.rate_limit.time.monotonic", c.monotonic)
    monkeypatch.setattr("frigidaire.rate_limit.time.sleep", c.sleep)
    return c


def test_first_wait_does_not_sleep(clock: FakeClock) -> None:
    """The very first call has no prior timestamp to honor."""
    RateLimiter(min_interval=1.0).wait()
    assert clock.sleep_calls == []


def test_second_wait_sleeps_for_min_interval(clock: FakeClock) -> None:
    limiter = RateLimiter(min_interval=1.25)
    limiter.wait()  # establishes next_ok_at = 1.25
    clock.now = 0.5  # 0.75s too early
    limiter.wait()
    assert clock.sleep_calls == [pytest.approx(0.75)]


def test_wait_after_interval_elapsed_does_not_sleep(clock: FakeClock) -> None:
    limiter = RateLimiter(min_interval=1.0)
    limiter.wait()
    clock.now = 5.0  # well past next_ok_at
    limiter.wait()
    assert clock.sleep_calls == []


def test_cool_down_extends_next_ok(clock: FakeClock) -> None:
    limiter = RateLimiter(min_interval=0.0)
    limiter.cool_down(3.0)
    limiter.wait()
    assert clock.sleep_calls == [pytest.approx(3.0)]


def test_cool_down_negative_is_noop(clock: FakeClock) -> None:
    limiter = RateLimiter(min_interval=0.0)
    limiter.cool_down(-5.0)
    limiter.wait()
    assert clock.sleep_calls == []


# --- wrap_session_request ---


def _ok_response(status: int = 200, retry_after: str | None = None) -> MagicMock:
    headers = {"Retry-After": retry_after} if retry_after else {}
    return MagicMock(status_code=status, headers=headers)


def test_wrapped_request_pass_through(clock: FakeClock) -> None:
    inner = MagicMock(return_value=_ok_response(200))
    limiter = RateLimiter(min_interval=0.0)
    wrapped = wrap_session_request(inner, limiter)

    resp = wrapped("GET", "https://example.com")
    assert resp.status_code == 200
    inner.assert_called_once()


def test_wrapped_request_injects_default_timeout(clock: FakeClock) -> None:
    inner = MagicMock(return_value=_ok_response(200))
    wrapped = wrap_session_request(inner, RateLimiter(0.0), default_timeout=7.5)
    wrapped("GET", "https://example.com")
    inner.assert_called_with("GET", "https://example.com", timeout=7.5)


def test_wrapped_request_preserves_caller_timeout(clock: FakeClock) -> None:
    inner = MagicMock(return_value=_ok_response(200))
    wrapped = wrap_session_request(inner, RateLimiter(0.0), default_timeout=15.0)
    wrapped("GET", "https://example.com", timeout=2.0)
    inner.assert_called_with("GET", "https://example.com", timeout=2.0)


def test_wrapped_request_rate_limits_writes(clock: FakeClock) -> None:
    inner = MagicMock(return_value=_ok_response(200))
    limiter = RateLimiter(min_interval=1.5)
    wrapped = wrap_session_request(inner, limiter)

    wrapped("POST", "https://example.com")
    wrapped("POST", "https://example.com")
    # Second call should have slept ~1.5s before firing
    assert clock.sleep_calls == [pytest.approx(1.5)]


def test_wrapped_request_does_not_rate_limit_reads(clock: FakeClock) -> None:
    inner = MagicMock(return_value=_ok_response(200))
    wrapped = wrap_session_request(inner, RateLimiter(min_interval=1.5), default_timeout=None)
    wrapped("GET", "https://example.com")
    wrapped("GET", "https://example.com")
    assert clock.sleep_calls == []


def test_429_with_retry_after_sleeps_then_retries(clock: FakeClock) -> None:
    inner = MagicMock(side_effect=[_ok_response(429, retry_after="2"), _ok_response(200)])
    limiter = RateLimiter(min_interval=0.0)
    wrapped = wrap_session_request(inner, limiter, max_retries_on_429=4)

    resp = wrapped("GET", "https://example.com")
    assert resp.status_code == 200
    assert clock.sleep_calls == [pytest.approx(2.0)]
    assert inner.call_count == 2


def test_429_max_retries_returns_429(clock: FakeClock) -> None:
    inner = MagicMock(return_value=_ok_response(429, retry_after="1"))
    wrapped = wrap_session_request(inner, RateLimiter(0.0), max_retries_on_429=2)

    resp = wrapped("GET", "https://example.com")
    assert resp.status_code == 429
    # 2 retries means 3 attempts total (initial + 2 retries)
    assert inner.call_count == 3


def test_retry_after_capped_by_max_retry_after(clock: FakeClock) -> None:
    inner = MagicMock(side_effect=[_ok_response(429, retry_after="9999"), _ok_response(200)])
    wrapped = wrap_session_request(inner, RateLimiter(0.0), max_retry_after=5.0, max_retries_on_429=4)

    wrapped("GET", "https://example.com")
    assert clock.sleep_calls == [pytest.approx(5.0)]
