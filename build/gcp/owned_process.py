"""Closure of ONE owner-created process group (issue #365).

Python 3.12 stdlib, Linux only. The process must be the exact ``subprocess.Popen``
returned by a call using ``start_new_session=True``; its positive PID is the only
group ID this module ever signals. There is no PID/name input, no global
``wait(-1)``, no ``poll()``, no ``Popen.send_signal/terminate/kill`` (they poll
internally and may reap) and no context-manager exit.

Safety argument. While the leader is an unreaped child, its numeric ID cannot be
reused, so ``killpg`` addresses only the original group. Therefore the leader is
observed with non-reaping ``waitid(WNOWAIT)`` (never stored in ``returncode``),
every destructive signal is sent while it is still unreaped, and the single final
``Popen.wait`` is the sole reaper. After that only signal-0 existence probes are
allowed, because an absent group may free its ID for unrelated reuse. This needs
normal child-wait semantics: no ``SIGCHLD=SIG_IGN``/``SA_NOCLDWAIT``, custom
reaper or foreign waiter. Observed loss of ownership (ECHILD, vanished anchored
group, unexpected status) refuses all further signals and reports uncertainty.

A killed group with a zombie leader still answers signal 0, so early whole-group
absence is not observable; ``TERM`` always consumes its bounded grace. ESRCH
after the reap is the only positive group absence. EPERM, other errors,
a persistent/reused group, a deadline or lost ownership are uncertainty, never
absence. Leader exit never proves group absence. Escaped sessions are outside
this boundary.
"""
from __future__ import annotations

import os
import signal
import threading
import time

CLEANUP_SECONDS = 3.0      # final shared reap + group-convergence budget
TERM_GRACE_SECONDS = 5.0   # Master only; command() keeps its immediate KILL policy
_EXITED = (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)


class OwnershipUncertain(RuntimeError):
    """Exclusive ownership of the original leader/group can no longer be shown."""


def monotonic():
    return time.monotonic()


def sleep(seconds):
    time.sleep(seconds)


class OwnedGroup:
    def __init__(self, proc):
        if type(proc.pid) is not int or proc.pid <= 1 or proc.returncode is not None:
            raise OwnershipUncertain('owned child identity refused')
        self.proc, self.pgid = proc, proc.pid
        self.outcome = None
        self.reaping = False
        self.ownership_lost = False
        self._lock = threading.Lock()

    def status(self):
        """Non-reaping observation: None while running, else exit code (-signal)."""
        if self.reaping or self.ownership_lost or self.proc.returncode is not None:
            raise OwnershipUncertain('owned child already settled')
        try:
            info = os.waitid(os.P_PID, self.pgid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            self.ownership_lost = True
            raise OwnershipUncertain('owned child no longer waitable') from None
        except BaseException:
            self.ownership_lost = True
            raise
        if info is None:
            return None
        if (info.si_pid != self.pgid or info.si_code not in _EXITED
                or type(info.si_status) is not int
                or not (0 <= info.si_status <= 255 if info.si_code == os.CLD_EXITED
                        else 0 < info.si_status < signal.NSIG)):
            self.ownership_lost = True
            raise OwnershipUncertain('unexpected child status')
        return info.si_status if info.si_code == os.CLD_EXITED else -info.si_status

    def _signal(self, number, until):
        self.status()  # refuses once reaping/lost; ECHILD sends nothing
        if monotonic() >= until:
            raise OwnershipUncertain('signal deadline exhausted')
        try:
            os.killpg(self.pgid, number)
        except ProcessLookupError:
            # An unreaped leader keeps its group visible; ESRCH means the model broke.
            self.ownership_lost = True
            raise OwnershipUncertain('anchored group vanished') from None

    def close(self, term_grace, final=CLEANUP_SECONDS, *, until=None):
        """One idempotent bounded transition; True only on positive group absence."""
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self.outcome is not None:
                return self.outcome
            self.outcome = False  # any exception/reentry leaves the conservative result
            started = monotonic()
            finish = started + term_grace + final
            if until is not None:
                finish = min(finish, until)
            grace_end = min(started + term_grace, finish)
            ok = True
            if term_grace:
                try:
                    if monotonic() >= finish:
                        raise OwnershipUncertain('closure deadline exhausted')
                    self._signal(signal.SIGTERM, finish)
                    while True:
                        left = grace_end - monotonic()
                        if left <= 0:
                            break
                        sleep(min(.1, left))
                except BaseException:
                    ok = False
            try:
                if monotonic() >= finish:
                    raise OwnershipUncertain('closure deadline exhausted')
                self._signal(signal.SIGKILL, finish)  # still anchored, even if leader already exited
            except BaseException:
                ok = False
            finish = min(finish, monotonic() + final)
            self.reaping = True  # no destructive signal can follow
            try:
                left = finish - monotonic()
                if left <= 0:
                    raise OwnershipUncertain('reap deadline exhausted')
                self.proc.wait(timeout=left)
            except BaseException:
                ok = False
            if self.proc.returncode is None or self.ownership_lost:
                ok = False
            while ok:
                if monotonic() >= finish:
                    ok = False
                    break
                try:
                    os.killpg(self.pgid, 0)
                except ProcessLookupError:
                    ok = monotonic() < finish  # late ESRCH is not within-budget evidence
                    break
                except BaseException:
                    ok = False
                    break
                if monotonic() >= finish:
                    ok = False
                    break
                sleep(min(.05, max(0, finish - monotonic())))
            self.outcome = ok
            return ok
        finally:
            self._lock.release()
