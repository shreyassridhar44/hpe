# -*- coding: utf-8 -*-
"""
test_login_scenarios.py — Showcase unit tests for user login threat scenarios.
Simulates and validates standard login, brute force, geographic mismatch,
and impossible travel scenarios.
"""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.threat_engine import process_event, determine_action
from app.schemas import NetworkEvent, ThreatAction

class TestUserLoginScenarios:
    """Showcases core test cases for user login authentication anomalies."""

    def test_scenario_1_clean_login_allow(self):
        """
        Test Case 1: Clean, Authorized User Login.
        Expects:
          - Threat score < 0.3
          - Threat action = ALLOW
          - Threat reasons = None / Empty
        """
        event = NetworkEvent(
            event_id="test-clean-01",
            user_id="legit_developer",
            source_ip="192.168.1.100",
            ip_region="US-East",
            user_region="US-East",
            action="login",
            login_hour=10,
            data_downloaded_mb=12.5,
            failed_attempts_last_15m=0,
            success=True,
            geo_mismatch=False,
            impossible_travel=False,
            event_source="live_portal"
        )
        
        result = process_event(event)
        assert result.is_threat is False
        assert result.threat_action == ThreatAction.ALLOW
        assert len(result.event_summary.get("threat_reasons", [])) == 0

    def test_scenario_2_brute_force_block(self):
        """
        Test Case 2: Brute Force Attempt (5+ failed logins).
        Expects:
          - Threat action = BLOCK
          - Threat reasons include: 'Brute Force Attack Pattern' or 'High Volume of Failed Authentication Attempts'
        """
        event = NetworkEvent(
            event_id="test-brute-02",
            user_id="compromised_user",
            source_ip="198.51.100.12",
            ip_region="Europe-West",
            user_region="US-East",
            action="login",
            login_hour=15,
            data_downloaded_mb=0.0,
            failed_attempts_last_15m=6,
            success=False,
            geo_mismatch=True,
            impossible_travel=False,
            anomaly_type="brute_force",
            event_source="live_portal"
        )
        
        result = process_event(event)
        assert result.is_threat is True
        assert result.threat_action == ThreatAction.BLOCK
        reasons = result.event_summary.get("threat_reasons", [])
        assert any("Failed Authentication Attempts" in r or "Brute Force" in r for r in reasons)

    def test_scenario_3_geo_mismatch_monitor(self):
        """
        Test Case 3: Geographic Mismatch (user typical region vs connection IP region mismatch).
        Expects:
          - Threat score >= 0.3 (MONITOR status)
          - Threat reasons include: 'Geographic Mismatch'
        """
        event = NetworkEvent(
            event_id="test-geo-03",
            user_id="us_finance_officer",
            source_ip="203.0.113.88",
            ip_region="Asia-Pacific",
            user_region="US-East",
            action="login",
            login_hour=14,
            data_downloaded_mb=5.0,
            failed_attempts_last_15m=0,
            success=True,
            geo_mismatch=True,
            impossible_travel=False,
            event_source="live_portal"
        )
        
        result = process_event(event)
        assert result.is_threat is True
        reasons = result.event_summary.get("threat_reasons", [])
        assert any("Geographic Mismatch" in r for r in reasons)

    def test_scenario_4_impossible_travel_critical(self):
        """
        Test Case 4: Impossible Travel Anomaly (logins from US and Asia within minutes).
        Expects:
          - Threat action = CRITICAL_ALERT
          - Threat reasons include: 'Impossible Travel'
        """
        event = NetworkEvent(
            event_id="test-travel-04",
            user_id="remote_admin",
            source_ip="198.51.100.55",
            ip_region="Asia-Pacific",
            user_region="US-West",
            action="login",
            login_hour=2,
            data_downloaded_mb=120.0,
            failed_attempts_last_15m=0,
            success=True,
            geo_mismatch=True,
            impossible_travel=True,
            event_source="live_portal"
        )
        
        result = process_event(event)
        assert result.is_threat is True
        assert result.threat_action == ThreatAction.CRITICAL_ALERT
        reasons = result.event_summary.get("threat_reasons", [])
        assert any("Impossible Travel" in r for r in reasons)
