import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import check


class MonitoringTests(unittest.TestCase):
    def test_transient_failure_dedup_and_recovery(self):
        state, sent = {}, []
        send = lambda name, failed: sent.append((name, failed))
        for healthy in [False, False, True, False, False, False, False, True, True]:
            check.report({'bao': healthy}, state, send)
        self.assertEqual(sent, [('bao', True), ('bao', False)])

    def test_failed_delivery_retried(self):
        state = {}
        def fail(*args):
            raise OSError('offline')
        with self.assertRaises(OSError):
            check.report({'bao': False}, state, fail, threshold=1)
        self.assertFalse(state['bao']['open'])
        sent = []
        check.report({'bao': False}, state, lambda *args: sent.append(args), threshold=1)
        self.assertEqual(sent, [('bao', True)])

    def test_no_heartbeat_on_critical_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(check, 'internal_checks', return_value=({'bao': False}, {})), \
                 patch.object(check, 'request') as request:
                check.run_internal({'critical_key': 'secret', 'warning_key': 'secret',
                                    'heartbeat_url': 'private'}, Path(folder) / 'state')
                request.assert_not_called()

    def test_warning_failure_does_not_suppress_healthy_heartbeat(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(check, 'internal_checks', return_value=({'bao': True}, {'disk': False})), \
                 patch.object(check, 'request') as request:
                check.run_internal({'critical_key': 'secret', 'warning_key': 'secret',
                                    'heartbeat_url': 'private'}, Path(folder) / 'state')
                request.assert_called_once_with('private')

    def test_payload_is_fixed_and_does_not_include_logs(self):
        with patch.object(check, 'request') as request:
            check.event('credential', 'openbao', True, 'HIGH')
        payload = json.loads(request.call_args.args[1])
        self.assertEqual(set(payload), {'integrationKey', 'alertKey', 'eventType', 'priority', 'summary'})
        self.assertEqual(payload['summary'], 'Harbor: openbao check failed')


if __name__ == '__main__':
    unittest.main()
