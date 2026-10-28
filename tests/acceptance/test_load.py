#!/usr/bin/env python3
"""Synthetic outage-boundary regressions; no Docker or live services."""

import unittest

from load import expected_response


class FaultBoundaryTests(unittest.TestCase):
    def test_request_crossing_outage_start_is_exposed(self):
        self.assertTrue(expected_response(403, 0.02, 200, 49.99, 50.01, True))

    def test_request_dispatched_at_outage_start_is_exposed(self):
        self.assertTrue(expected_response(403, 0.01, 200, 50.0, 50.01, True))

    def test_request_crossing_recovery_deadline_retains_exposure(self):
        self.assertTrue(expected_response(403, 0.02, 200, 59.99, 60.01, True))

    def test_new_request_after_recovery_deadline_must_succeed(self):
        self.assertFalse(expected_response(403, 0.01, 200, 60.0, 60.01, True))

    def test_request_finishing_before_outage_must_succeed(self):
        self.assertFalse(expected_response(403, 0.01, 200, 49.98, 49.99, True))

    def test_later_outage_cycle_uses_the_same_boundaries(self):
        self.assertTrue(expected_response(403, 0.02, 200, 109.99, 110.01, True))
        self.assertFalse(expected_response(403, 0.01, 200, 120.0, 120.01, True))

    def test_failures_without_injected_faults_are_rejected(self):
        self.assertFalse(expected_response(403, 0.02, 200, 49.99, 50.01, False))

    def test_banned_clients_cannot_pass_during_outages(self):
        self.assertFalse(expected_response(200, 0.01, 403, 50.0, 50.01, True))

    def test_transport_errors_are_not_excused_by_outages(self):
        for code in (0, 500, 503):
            with self.subTest(code=code):
                self.assertFalse(expected_response(code, 0.01, 200, 50.0, 50.01, True))

    def test_three_second_budget_still_applies_during_outages(self):
        self.assertFalse(expected_response(403, 3.01, 200, 50.0, 53.01, True))
        self.assertFalse(expected_response(200, 3.01, 200, 50.0, 53.01, True))

    def test_expected_responses_are_accepted(self):
        self.assertTrue(expected_response(200, 0.01, 200, 0.0, 0.01, False))
        self.assertTrue(expected_response(403, 0.01, 403, 0.0, 0.01, False))


if __name__ == "__main__":
    unittest.main()
