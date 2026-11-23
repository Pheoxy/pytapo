"""Hub children against an offline fake H200 that runs the real pyTapo transport.

test_hub_shared_session.py replaces Transport entirely. These tests only replace
requests.session (see fake_hub.py), so the real securePassthrough login, Seq,
Tapo_tag, retries, send lock and session clearing all run.

Run with -s to see the measured numbers.
"""

import asyncio
import concurrent.futures
import threading
import time

import pytest
import requests

from fake_hub import CHILD_ID, fake_hub, offline  # noqa: F401  (pytest fixtures)

SLOW = ("child", "searchDateWithVideo")


def counts(hub):
    s = hub.snapshot()
    return s["logins"], s["stale"]


def poll(hub_tapo, child_tapo, rounds):
    for _ in range(rounds):
        hub_tapo.getTime()
        child_tapo.getTime()


# --------------------------------------------------------------------------- #
#  a / b: login ping-pong
# --------------------------------------------------------------------------- #
def test_a_separate_transports_ping_pong(fake_hub):
    hub = fake_hub.hub
    parent = fake_hub.make_tapo()
    child = fake_hub.make_tapo(childID=CHILD_ID)
    assert child.transport is not parent.transport
    logins0, stale0 = counts(hub)
    poll(parent, child, 5)
    logins, stale = counts(hub)
    print(f"\n[a] separate: logins +{logins - logins0}, -40401 +{stale - stale0}")
    # every switch between hub and child ends the other's session
    assert logins - logins0 == 10
    assert stale - stale0 == 10
    assert hub.requests[("child", "getClockStatus")] == 5
    assert hub.requests[("hub", "getClockStatus")] == 5


def test_b_shared_transport_keeps_one_login(fake_hub):
    hub = fake_hub.hub
    parent = fake_hub.make_tapo()
    child = fake_hub.make_tapo(childID=CHILD_ID, transport=parent.transport)
    assert child.transport is parent.transport
    assert child.deviceType == "SMART.IPCAMERA"
    poll(parent, child, 5)
    s = hub.snapshot()
    print(f"\n[b] shared: logins {s['logins']}, -40401 {s['stale']}")
    assert s["logins"] == 1
    assert s["stale"] == 0
    assert s["seq_errors"] == s["tag_errors"] == 0
    assert hub.requests[("child", "getClockStatus")] == 5


def test_child_methods(fake_hub):
    parent = fake_hub.make_tapo()
    child = fake_hub.make_tapo(childID=CHILD_ID, transport=parent.transport)
    assert child.getRecordingsList() == [{"date": "20261122"}, {"date": "20261123"}]
    with pytest.raises(Exception, match="not supported"):
        parent.getRecordingsList()  # the hub itself answers {}
    with pytest.raises(Exception, match="-10008"):
        child.getHubStorage()  # unknown to the child


# --------------------------------------------------------------------------- #
#  c / d: slow child search times out while the hub keeps polling
# --------------------------------------------------------------------------- #
def slow_search_while_hub_polls(harness, shared, use_hass, delay=1.0):
    """Child getRecordingsList() takes `delay` s on the hub (client timeout is
    0.5 s) while hub getTime() polls run from another thread. Returns numbers."""
    hub = harness.hub
    hass = harness.make_hass() if use_hass else None
    parent = harness.make_tapo(hass=hass)
    if shared:
        child = harness.make_tapo(childID=CHILD_ID, transport=parent.transport, hass=hass)
    else:
        child = harness.make_tapo(childID=CHILD_ID, hass=hass)
    parent.getTime()
    child.getTime()
    hub.delays[SLOW] = delay
    before = hub.snapshot()
    child_done = threading.Event()
    polls = []  # (started, latency, error or None)

    def search():
        t0 = time.monotonic()
        try:
            child.getRecordingsList()
            err = None
        except Exception as e:  # noqa: BLE001
            err = e
        finally:
            child_done.set()
        return time.monotonic() - t0, err

    def poller():
        # keep polling until the child is done, then two more
        extra = 2
        while extra:
            if child_done.is_set():
                extra -= 1
            t0 = time.monotonic()
            try:
                parent.getTime()
                err = None
            except Exception as e:  # noqa: BLE001
                err = e
            polls.append((t0, time.monotonic() - t0, err))
            time.sleep(0.05)

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        child_future = pool.submit(search)
        assert hub.slow_arrived.wait(5), "slow request never reached the hub"
        poll_future = pool.submit(poller)
        # a deadlock shows up here as a TimeoutError
        child_time, child_err = child_future.result(timeout=15)
        poll_future.result(timeout=15)
    hub.delays.pop(SLOW)
    during = hub.snapshot()

    # does everything recover?
    parent.getTime()
    child.getTime()
    after = hub.snapshot()

    errors = [e for _, _, e in polls if e is not None]
    return {
        "child_time": child_time,
        "child_err": child_err,
        "polls": len(polls),
        "poll_max": max(l for _, l, _ in polls),
        "poll_errors": [type(e).__name__ + ": " + str(e)[:80] for e in errors],
        "logins": during["logins"] - before["logins"],
        "stale": during["stale"] - before["stale"],
        "seq_errors": during["seq_errors"] - before["seq_errors"],
        "tag_errors": during["tag_errors"] - before["tag_errors"],
        "timeouts": during["timeouts"] - before["timeouts"],
        "max_in_flight": during["max_in_flight"],
        "searches": during["requests"][SLOW] - before["requests"].get(SLOW, 0),
        "recovery_logins": after["logins"] - during["logins"],
    }


def report(label, r):
    print(
        f"\n[{label}] child {r['child_time']:.2f}s -> {type(r['child_err']).__name__}, "
        f"searches sent {r['searches']}, timeouts {r['timeouts']}; "
        f"hub polls {r['polls']}, max latency {r['poll_max']:.2f}s, "
        f"errors {r['poll_errors']}; logins +{r['logins']}, -40401 +{r['stale']}, "
        f"seq errors {r['seq_errors']}, tag errors {r['tag_errors']}, "
        f"max in flight {r['max_in_flight']}, logins to recover {r['recovery_logins']}"
    )


def test_c_shared_transport_hass_loop(fake_hub):
    """As in Home Assistant: both Tapo objects run on one hass.loop."""
    r = slow_search_while_hub_polls(fake_hub, shared=True, use_hass=True)
    report("c shared, hass", r)
    assert isinstance(r["child_err"], requests.exceptions.ReadTimeout)
    # ReadTimeout -> clear session, back off, log in again, retry once, raise
    assert r["searches"] == 2 and r["timeouts"] == 2
    assert r["logins"] == 1
    # the send lock serialises: one request at a time, no seq races
    assert r["max_in_flight"] == 1
    assert r["seq_errors"] == r["tag_errors"] == 0
    assert r["poll_errors"] == []
    # the hub poll waits for the whole child call (2 timeouts + backoff + login)
    assert r["poll_max"] > 0.9
    assert r["recovery_logins"] == 0


def test_c_shared_transport_own_loops(fake_hub):
    """hass=None: each Tapo has its own AsyncHandler loop, so the shared
    transport's asyncio send lock is re-created per loop and guards nothing."""
    r = slow_search_while_hub_polls(fake_hub, shared=True, use_hass=False)
    report("c shared, no hass", r)
    assert isinstance(r["child_err"], requests.exceptions.ReadTimeout)
    # no deadlock, and the hub works again afterwards (checked inside)
    # hub polls are not blocked: they run while the child request is in flight
    assert r["max_in_flight"] >= 2
    assert r["poll_max"] < 0.9


def test_d_separate_transports_hass_loop(fake_hub):
    r = slow_search_while_hub_polls(fake_hub, shared=False, use_hass=True)
    report("d separate, hass", r)
    assert isinstance(r["child_err"], requests.exceptions.ReadTimeout)
    assert r["seq_errors"] == r["tag_errors"] == 0


def test_d_separate_transports_own_loops(fake_hub):
    r = slow_search_while_hub_polls(fake_hub, shared=False, use_hass=False)
    report("d separate, no hass", r)
    assert isinstance(r["child_err"], requests.exceptions.ReadTimeout)
    assert r["seq_errors"] == r["tag_errors"] == 0


def test_c_shared_own_loops_hub_poll_in_flight_during_timeout(fake_hub):
    """hass=None, with hub polls slow enough (0.1 s) to be in flight when the
    child's ReadTimeout clears the shared session and logs in again. The hub
    poll can then decrypt with the new keys (seen: UnicodeDecodeError) or log
    in itself. Timing dependent, so only no deadlock and recovery are asserted;
    run with -s to see what happened."""
    fake_hub.hub.delays[("hub", "getClockStatus")] = 0.1
    r = slow_search_while_hub_polls(fake_hub, shared=True, use_hass=False)
    report("c shared, no hass, hub poll in flight", r)
    assert isinstance(r["child_err"], requests.exceptions.ReadTimeout)


@pytest.mark.xfail(
    strict=True,
    reason="pyTapo._ensure_send_lock makes a new asyncio.Lock whenever the "
    "running loop changes, so two loops sharing one transport are not serialised",
)
def test_send_lock_serialises_across_event_loops(fake_hub):
    parent = fake_hub.make_tapo()
    transport = parent.transport
    held = threading.Event()
    release = threading.Event()

    def holder():
        async def hold():
            await transport._acquire_send_lock()
            held.set()
            while not release.is_set():
                await asyncio.sleep(0.01)
            await transport._release_send_lock()

        asyncio.run(hold())

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert held.wait(5)

        async def try_acquire():
            await asyncio.wait_for(transport._acquire_send_lock(), 0.3)

        # wanted: the second loop waits while the first loop holds the lock
        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(try_acquire())
    finally:
        release.set()
        thread.join(5)
