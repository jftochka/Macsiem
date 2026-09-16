"""Sensor normalization and diffing."""

from __future__ import annotations

import threading
import unittest

from macsiem.correlate import proctree
from macsiem.sensors import eslogger as eslogger_mod
from macsiem.sensors.base import Sensor
from macsiem.sensors.procpoll import ProcPollSensor
from macsiem.sensors.state import PostureSensor
from macsiem.util.proc import FixtureRunner

ES_EXEC = {
    "time": "2026-09-11T21:00:01.123456789Z", "seq_num": 42, "version": 8,
    "process": {"audit_token": {"pid": 500, "euid": 501}, "ppid": 400,
                "executable": {"path": "/bin/zsh"}, "signing_id": "com.apple.zsh",
                "is_platform_binary": True},
    "event": {"exec": {
        "target": {"audit_token": {"pid": 501, "euid": 501}, "ppid": 500,
                   "executable": {"path": "/usr/bin/osascript"},
                   "signing_id": "com.apple.osascript", "cdhash": "abc",
                   "is_platform_binary": True},
        "args": ["/usr/bin/osascript", "-e", "do shell script \"id\""]}},
}


class TestEsloggerNormalization(unittest.TestCase):
    def test_exec_event(self):
        event = eslogger_mod.normalize(ES_EXEC)
        self.assertEqual(event["kind"], "exec")
        self.assertEqual(event["pid"], 501)
        self.assertEqual(event["ppid"], 500)
        self.assertEqual(event["binary_path"], "/usr/bin/osascript")
        self.assertEqual(event["argv"][1], "-e")
        self.assertEqual(event["parent_path"], "/bin/zsh")
        self.assertTrue(event["ts"].endswith("Z"))

    def test_malformed_messages_do_not_raise(self):
        """A schema change between macOS releases must not be an outage."""
        for payload in (None, "garbage", {}, {"event": {}}, {"event": {"exec": None}},
                        {"event": {"exec": {"target": "not-a-dict"}}},
                        {"event": {"unknown_future_event": {"a": 1}}}):
            eslogger_mod.normalize(payload)

    def test_sequence_gaps_become_events(self):
        emitted = []
        sensor = eslogger_mod.EsloggerSensor({}, emitted.append, None)
        sensor._last_seq = {}
        sensor._check_sequence({"seq_num": 10}, {"kind": "exec"})
        sensor._check_sequence({"seq_num": 15}, {"kind": "exec"})
        gaps = [e for e in emitted if e.get("kind") == "telemetry_gap"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["detail"]["missed"], 4)


class TestProcPoll(unittest.TestCase):
    PS = ("  PID  PPID   UID USER     %CPU %MEM STARTED       TTY STAT COMMAND\n"
          "    1     0     0 root      0.0  0.1 Thu Sep 11  ??  Ss  /sbin/launchd\n"
          "  500     1   501 alice     0.0  0.1 Thu Sep 11 ttys000 S /bin/zsh\n")
    PS2 = PS + "  501   500   501 alice     0.0  0.1 Thu Sep 11 ttys000 S /usr/bin/csrutil disable\n"

    def test_new_processes_become_exec_events(self):
        runner = FixtureRunner().add(["/bin/ps"], stdout=self.PS)
        sensor = ProcPollSensor({}, lambda e: None, runner)
        first = sensor.snapshot()
        runner.add(["/bin/ps"], stdout=self.PS2)
        second = sensor.snapshot()
        events = sensor.diff(first, second)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["binary_path"], "/usr/bin/csrutil")
        self.assertEqual(events[0]["argv"], ["/usr/bin/csrutil", "disable"])

    def test_fidelity_is_labelled_low(self):
        self.assertEqual(ProcPollSensor.fidelity, "low")

    def test_ancestry_from_a_ps_snapshot(self):
        table = proctree.parse_ps(self.PS2)
        chain = proctree.ancestry(501, {}, table)
        self.assertEqual([node["name"] for node in chain], ["zsh"])


class TestPostureSensor(unittest.TestCase):
    def test_sip_flip_is_reported_as_critical(self):
        runner = FixtureRunner(default={"stdout": "", "returncode": 0})
        runner.add(["/usr/bin/csrutil", "status"],
                   stdout="System Integrity Protection status: enabled.")
        sensor = PostureSensor({}, lambda e: None, runner)
        before = sensor.snapshot()
        runner.add(["/usr/bin/csrutil", "status"],
                   stdout="System Integrity Protection status: disabled.")
        after = sensor.snapshot()
        changes = sensor.diff(before, after)
        self.assertTrue(changes)
        self.assertEqual(changes[0]["severity_hint"], "critical")


class TestSupervision(unittest.TestCase):
    def test_a_dying_sensor_emits_an_event_and_restarts(self):
        """Killing the monitoring is itself one of the documented techniques."""
        emitted = []

        class Flaky(Sensor):
            name = "flaky"
            calls = 0

            def run(self):
                Flaky.calls += 1
                if Flaky.calls < 3:
                    raise RuntimeError("boom")
                self.stop_event.wait(5)

        sensor = Flaky({"agent": {"sensor_restart_backoff": [0.01]}},
                       emitted.append)
        sensor.start()
        deadline = threading.Event()
        deadline.wait(1.0)
        sensor.stop()
        downs = [e for e in emitted if e.get("kind") == "sensor_down"]
        self.assertGreaterEqual(len(downs), 2)
        self.assertEqual(downs[0]["detail"]["sensor"], "flaky")


if __name__ == "__main__":
    unittest.main()
