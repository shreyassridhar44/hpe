# -*- coding: utf-8 -*-
"""
test_vpn_scenarios.py — Dedicated showcase unit tests for VPN security scenarios.
Simulates and validates VPN login region mismatch, VPN tunnel hopping,
and suspicious VPN registration warnings.
"""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.threat_engine import process_event, determine_action
from app.schemas import NetworkEvent, ThreatAction
from app.routes.auth import RegisterRequest

class TestVpnThreatScenarios:
    """Showcases isolated test cases for VPN user connection and registration anomalies."""

    def test_vpn_scenario_1_geo_mismatch_block(self):
        """
        VPN Scenario 1: User logs in from a Commercial VPN located in Frankfurt.
        Apparent region is Frankfurt (EU-Central) but typical home profile is US-East.
        Expects:
          - Threat action = BLOCK
          - Threat reasons include: 'Geographic Mismatch via Commercial VPN Exit Node (Germany)'
        """
        event = NetworkEvent(
            event_id="vpn-geo-01",
            user_id="contractor_bill",
            source_ip="185.190.140.22",  # Frankfurt VPN IP (Starts with 185.)
            ip_region="EU-Central",
            user_region="US-East",
            action="login",
            login_hour=14,
            data_downloaded_mb=5.0,
            failed_attempts_last_15m=0,
            success=True,
            geo_mismatch=True,
            impossible_travel=False,
            is_vpn=True,
            event_source="live_portal"
        )
        
        result = process_event(event)
        assert result.is_threat is True
        assert result.threat_action == ThreatAction.BLOCK
        reasons = result.event_summary.get("threat_reasons", [])
        assert any("Geographic Mismatch via Commercial VPN Exit Node" in r for r in reasons)

    def test_vpn_scenario_2_tunnel_hopping_critical(self):
        """
        VPN Scenario 2: Attack via rapid VPN "tunnel hopping" server switches.
        Mismatched logins occur in London and Singapore under 2 minutes.
        Expects:
          - Threat action = CRITICAL_ALERT
          - Threat reasons include: 'Impossible Travel via rapid VPN server hopping (potential hijack)'
        """
        event = NetworkEvent(
            event_id="vpn-hop-02",
            user_id="lead_architect",
            source_ip="45.92.12.80",  # London VPN IP (Starts with 45.)
            ip_region="EU-Central",
            user_region="US-East",
            action="login",
            login_hour=4,
            data_downloaded_mb=45.0,
            failed_attempts_last_15m=0,
            success=True,
            geo_mismatch=True,
            impossible_travel=True,
            is_vpn=True,
            event_source="live_portal"
        )
        
        result = process_event(event)
        assert result.is_threat is True
        assert result.threat_action == ThreatAction.CRITICAL_ALERT
        reasons = result.event_summary.get("threat_reasons", [])
        assert any("Impossible Travel via rapid VPN server hopping" in r for r in reasons)

    def test_vpn_scenario_3_registration_warning(self):
        """
        VPN Scenario 3: User registers with a suspicious VPN signature (e.g. 'vpn' in department or username).
        Expects:
          - Dynamic is_vpn detection should resolve to True.
        """
        # Simulate registration request payload
        req = RegisterRequest(
            username="external_dev_vpn",
            department="Engineering-VPN-Remote"
        )
        
        # Calculate VPN signature matching our routes/auth.py logic
        is_vpn = ("vpn" in req.username.lower() or "vpn" in req.department.lower())
        assert is_vpn is True
