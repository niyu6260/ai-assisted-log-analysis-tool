from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from ccu_log_diag.error_catalog import load_error_catalog
from ccu_log_diag.model.events import Domain, Event, EventType, Finding
from ccu_log_diag.model.incidents import IncidentCase


def _detect_network_manager_conflict(case: IncidentCase, events: list[Event]) -> Finding:
    ordered = sorted(events, key=lambda event: event.ts_utc)

    def matches(event_type: EventType) -> list[Event]:
        return [event for event in ordered if event.type == event_type]

    starts = matches(EventType.NETWORK_MANAGER_START)
    lost = matches(EventType.CONNECTIVITY_LOST)
    releases = matches(EventType.NETWORK_MANAGER_RELEASE)
    router_modes = matches(EventType.NETWORK_MODE_CHANGE)
    cleanups = matches(EventType.PROCESS_CLEANUP)
    services = matches(EventType.SERVICE_START)
    resolved = matches(EventType.DNS_RECOVERED)
    sockets = matches(EventType.WEBSOCKET_CONNECTED)
    boots = matches(EventType.OCPP_BOOT_ACCEPTED)

    release_ts = releases[0].ts_utc if releases else ""
    router = next(
        (
            event
            for event in router_modes
            if event.attrs.get("mode") == "routerMode" and event.ts_utc >= release_ts
        ),
        None,
    )
    websocket = next((event for event in sockets if not router or event.ts_utc >= router.ts_utc), None)
    boot = next((event for event in boots if not websocket or event.ts_utc >= websocket.ts_utc), None)
    dns_recovery = next((event for event in resolved if not router or event.ts_utc >= router.ts_utc), None)
    sequence_complete = bool(starts and releases and router and len(cleanups) >= 2 and websocket and boot)

    evidence: list[Event] = []
    for candidate in (
        lost[0] if lost else None,
        starts[-1] if starts else None,
        releases[0] if releases else None,
        router,
        *cleanups[:3],
        services[-1] if services else None,
        dns_recovery,
        websocket,
        boot,
    ):
        if candidate and candidate not in evidence:
            evidence.append(candidate)

    gateway_before_release = [
        event
        for event in ordered
        if event.type == EventType.NETWORK_STATE
        and event.attrs.get("state") == "gateway_ok"
        and release_ts
        and event.ts_utc < release_ts
    ]
    connectivity_before_release = [
        event
        for event in ordered
        if event.type in {EventType.WEBSOCKET_CONNECTED, EventType.DNS_RECOVERED}
        and release_ts
        and event.ts_utc < release_ts
    ]

    if sequence_complete:
        return Finding(
            rule_id="eth1_network_manager_conflict_probable",
            severity="high",
            title="Probable eth1 network-manager ownership conflict",
            explanation=(
                f"{case.ground_truth.root_cause} The recovery sequence is complete, "
                "but the log records termination intent rather than confirmed process exits "
                "and does not prove simultaneous writes to eth1."
            ),
            evidence_event_ids=[event.id for event in evidence],
            counter_evidence_event_ids=[
                event.id for event in (gateway_before_release[-2:] + connectivity_before_release[-2:])
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="network_manager_ownership_conflict",
            affected_domain=Domain.NETWORK,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "Capture process ownership and ip-route/address changes during the next mode switch.",
                "Ensure only one manager controls eth1 and verify whether router_connect instances actually exit.",
            ],
        )

    return Finding(
        rule_id="inconclusive",
        severity="medium",
        title="Incomplete network ownership transition evidence",
        explanation="Only part of the expected DLM-to-router recovery sequence was observed.",
        evidence_event_ids=[event.id for event in evidence],
        confidence="low",
        status="inconclusive",
        affected_domain=Domain.NETWORK,
        missing_evidence=[
            name
            for present, name in (
                (bool(starts), "DLM manager start"),
                (bool(releases), "DLM manager release"),
                (router is not None, "routerMode takeover"),
                (len(cleanups) >= 2, "duplicate process cleanup"),
                (websocket is not None, "WebSocket recovery"),
                (boot is not None, "BootNotification accepted"),
            )
            if not present
        ],
    )


def _seconds_between(before: Event, after: Event) -> float:
    start = datetime.fromisoformat(before.ts_utc.replace("Z", "+00:00"))
    end = datetime.fromisoformat(after.ts_utc.replace("Z", "+00:00"))
    return (end - start).total_seconds()


def _detect_ev_estop_at_max_current(case: IncidentCase, events: list[Event]) -> list[Finding]:
    ordered = sorted(events, key=lambda event: event.ts_utc)
    error_codes = [event for event in ordered if event.type == EventType.ERROR_CODE and event.attrs.get("code") == "S3"]
    emergencies = [event for event in ordered if event.type == EventType.EMERGENCY_STOP]
    cp_drops = [event for event in ordered if event.type == EventType.CP_STATE_CHANGE]
    local_stops = [
        event
        for event in ordered
        if event.type == EventType.SESSION_STOP and event.attrs.get("reason") == "Local"
    ]
    accepted_stops = [event for event in ordered if event.type == EventType.OCPP_STOP_ACCEPTED]
    targets = [event for event in ordered if event.type == EventType.CURRENT_DEMAND]
    limits = [event for event in ordered if event.type == EventType.EV_CURRENT_LIMIT]

    catalog_path = Path(__file__).resolve().parents[2] / "knowledge" / "error_codes" / "sungrow.yaml"
    code = load_error_catalog(catalog_path).get("S3")
    confirmed_evidence = [
        *emergencies[:3],
        *cp_drops[:1],
        *error_codes[:3],
        *local_stops[:1],
        *accepted_stops[:1],
    ]
    findings: list[Finding] = []
    if error_codes and emergencies:
        findings.append(
            Finding(
                rule_id="s3_vehicle_emergency_stop",
                severity="high",
                title="S3 confirms vehicle-side emergency stop",
                explanation=(
                    f"Sungrow S3 maps to {code.meaning if code else 'EV_E_Stop'}. "
                    "The controller and OCPP sequence confirm the vehicle-side stop category; "
                    "OCPP reason=Local and errorCode=NoError do not override vendorErrorCode S3. "
                    "The underlying EV trigger remains unknown."
                ),
                evidence_event_ids=[event.id for event in confirmed_evidence],
                confidence=code.confidence if code else "high",
                status="confirmed",
                root_cause_category="vehicle_emergency_stop",
                affected_domain=Domain.CP,
                recommended_actions=["Use ISO 15118 and EV context to investigate why the EV asserted emergency stop."],
            )
        )

    emergency = emergencies[0] if emergencies else None
    prior_targets = [event for event in targets if emergency and event.ts_utc <= emergency.ts_utc]
    prior_limits = [event for event in limits if emergency and event.ts_utc <= emergency.ts_utc]
    target = prior_targets[-1] if prior_targets else None
    limit = prior_limits[-1] if prior_limits else None
    at_limit = bool(
        target
        and limit
        and emergency
        and abs(float(target.attrs.get("current_A", -1)) - float(limit.attrs.get("current_A", -2))) <= 0.1
        and 0 <= _seconds_between(target, emergency) <= 10
    )
    if at_limit:
        findings.append(
            Finding(
                rule_id="ev_estop_at_max_current_possible_fluctuation",
                severity="medium",
                title="EV emergency stop shortly after requesting its maximum current",
                explanation=(
                    f"The EV requested {target.attrs['current_A']:.1f} A, equal to its "
                    f"{limit.attrs['current_A']:.1f} A maximum, shortly before EV_E_Stop. "
                    "A current fluctuation is a plausible trigger, but no current waveform or "
                    "EV-internal fault evidence in this case proves that hypothesis."
                ),
                evidence_event_ids=[target.id, limit.id, emergency.id],
                confidence="low",
                status="probable",
                root_cause_category="possible_ev_current_limit_sensitivity",
                affected_domain=Domain.ISO15118,
                missing_evidence=[
                    "EV make/model and firmware version.",
                    "High-resolution requested-versus-output current around the stop.",
                    "EV-side diagnostic reason for asserting emergency stop.",
                ],
                recommended_actions=[
                    "Obtain the EV model and firmware version.",
                    "If supported by the vehicle manufacturer, update EV firmware and retest.",
                    "Compare PCU output-current feedback with EVTargetCurrent during the final seconds.",
                ],
            )
        )
    return findings or [
        Finding(
            rule_id="inconclusive",
            severity="medium",
            title="Incomplete S3/EV emergency-stop evidence",
            explanation="The selected time window does not contain the required S3 and EV emergency-stop sequence.",
            confidence="low",
            status="inconclusive",
            affected_domain=Domain.UNKNOWN,
        )
    ]


def _detect_s20_state_lifecycle(case: IncidentCase, events: list[Event]) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    s20_events = [
        event
        for event in ordered
        if event.type == EventType.ERROR_CODE
        and event.attrs.get("code") == "S20"
        and event.connector_id == 1
    ]
    clears = [
        event
        for event in ordered
        if event.type == EventType.ERROR_CODE_CLEARED
        and event.connector_id == 1
    ]
    finishing = [
        event
        for event in ordered
        if event.type == EventType.CONNECTOR_STATUS
        and "Finishing" in str(event.attrs.get("to_state", ""))
    ]
    normal_statuses = [
        event
        for event in ordered
        if event.type == EventType.CONNECTOR_STATUS
        and event.connector_id == 1
        and event.attrs.get("status") in {"Available", "Preparing", "Charging"}
        and event.attrs.get("ocpp_error") == "NoError"
        and not event.attrs.get("vendor_error")
    ]
    inconsistent_reports = [
        event
        for event in s20_events
        if event.attrs.get("ocpp_error") == "NoError"
        and event.attrs.get("status") in {"Available", "Unavailable"}
    ]

    if not s20_events:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="No S20 evidence in the selected window",
                explanation="Connector 1 did not report S20 in the selected incident window.",
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.ISO15118,
            )
        ]

    catalog_path = Path(__file__).resolve().parents[2] / "knowledge" / "error_codes" / "sungrow.yaml"
    code = load_error_catalog(catalog_path).get("S20")
    first_s20 = s20_events[0]
    preceding_finish = next(
        (
            event
            for event in reversed(finishing)
            if event.ts_utc <= first_s20.ts_utc
        ),
        None,
    )
    symptom_evidence = [
        event
        for event in (preceding_finish, *s20_events[:3])
        if event is not None
    ]
    findings = [
        Finding(
            rule_id="s20_frame_communication_timeout_observed",
            severity="high",
            title="Connector 1 reported S20 frame communication timeout",
            explanation=(
                f"Sungrow S20 maps to {code.meaning if code else 'Frame_Communication_Timeout'}: "
                "the next expected EV communication frame was not received in time. "
                "This confirms the stop category, but it does not establish whether the EV, "
                "physical unplug, or charger state handling caused the timeout."
            ),
            evidence_event_ids=[event.id for event in symptom_evidence],
            confidence="high",
            status="confirmed",
            root_cause_category="iso15118_frame_timeout_stop",
            affected_domain=Domain.ISO15118,
            missing_evidence=[
                "The exact missing ISO 15118 request and timeout timer state.",
                "A direct CP/unplug transition timestamp from the CCU.",
            ],
        )
    ]

    if inconsistent_reports:
        recovered_status = next(
            (
                event
                for event in normal_statuses
                if clears and event.ts_utc >= clears[0].ts_utc
            ),
            None,
        )
        counter_evidence = [
            event
            for event in (clears[0] if clears else None, recovered_status)
            if event is not None
        ]
        findings.append(
            Finding(
                rule_id="s20_state_lifecycle_inconsistency_probable",
                severity="high",
                title="Probable S20 state-lifecycle/reporting regression",
                explanation=(
                    "The state machine entered a Finishing state before the first S20 callback, "
                    "and later OCPP reports combined S20 with errorCode=NoError while connector 1 "
                    "was Available or Unavailable. This is internally inconsistent and supports a "
                    "stale-code/state-synchronization defect. However, the log also records an S20 "
                    "clear and a subsequent successful charging state, so a permanently stuck S20 "
                    "after the April 14 event is not proven."
                ),
                evidence_event_ids=[
                    event.id
                    for event in (
                        preceding_finish,
                        first_s20,
                        *inconsistent_reports[:3],
                    )
                    if event is not None
                ],
                counter_evidence_event_ids=[
                    event.id for event in counter_evidence
                ],
                confidence=case.ground_truth.confidence,
                status=case.ground_truth.confirmation_status,
                root_cause_category="stop_code_state_synchronization_defect",
                affected_domain=Domain.SYSTEM,
                missing_evidence=list(case.ground_truth.missing_proof),
                recommended_actions=[
                    "Trace the S20 latch and clear path across CCU, MainProcess, OCPP, and LED state.",
                    "Clear S20 atomically when connector 1 returns to unplugged/idle state.",
                    "Add a regression test for timeout-before-unplug and clear-after-unplug ordering.",
                    "Capture the LED controller input/state to verify why the strip remained red.",
                ],
            )
        )
    return findings


def _detect_maintenance_backend_disconnect(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    downs = [
        event
        for event in ordered
        if event.type == EventType.CONNECTIVITY_LOST
        and event.attrs.get("endpoint") == "maintenance"
        and event.attrs.get("state") == "down"
    ]
    recoveries = [
        event
        for event in ordered
        if event.type == EventType.WEBSOCKET_CONNECTED
        and event.attrs.get("endpoint") == "maintenance"
    ]
    attempts = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "maintenance"
        and event.attrs.get("action") == "connect_attempt"
    ]
    remote_closes = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "maintenance"
        and event.attrs.get("remote") == "true"
    ]
    customer_heartbeats = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "customer_ocpp"
        and event.attrs.get("state") == "reachable"
    ]
    signal = [
        event
        for event in ordered
        if event.attrs.get("state") == "signal_sampled"
    ]
    gateway_ok = [
        event for event in ordered if event.attrs.get("state") == "gateway_ok"
    ]
    gateway_readded = [
        event
        for event in ordered
        if event.attrs.get("state") == "gateway_readded"
    ]
    leases = [
        event
        for event in ordered
        if event.attrs.get("state") == "lease_obtained"
    ]

    down = downs[0] if downs else None
    recovery = next(
        (
            event
            for event in recoveries
            if not down or event.ts_utc > down.ts_utc
        ),
        None,
    )
    if not down or not recovery:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="Maintenance-backend outage boundary is incomplete",
                explanation="The selected logs do not contain both maintenance-backend Down and recovery evidence.",
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.NETWORK,
            )
        ]

    outage_seconds = _seconds_between(down, recovery)
    attempt_count = sum(int(event.attrs.get("count", 0)) for event in attempts)
    close_count = sum(int(event.attrs.get("count", 0)) for event in remote_closes)
    heartbeat_count = sum(
        int(event.attrs.get("count", 1)) for event in customer_heartbeats
    )
    hours = outage_seconds / 3600

    findings = [
        Finding(
            rule_id="maintenance_backend_prolonged_disconnection_confirmed",
            severity="high",
            title="Maintenance backend was unavailable while customer OCPP remained active",
            explanation=(
                f"The maintenance backend was marked Down for approximately {hours:.1f} hours. "
                f"Its client made {attempt_count} reconnect attempts and recorded {close_count} "
                f"closures, while the customer OCPP client recorded {heartbeat_count} heartbeat "
                "responses in the same log period. This confirms a maintenance-backend-specific "
                "reachability problem rather than a complete charger WAN outage."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    down,
                    *attempts,
                    *remote_closes,
                    *customer_heartbeats[:1],
                    *customer_heartbeats[-1:],
                    recovery,
                )
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="maintenance_backend_specific_disconnect",
            affected_domain=Domain.NETWORK,
        )
    ]

    latest_lease = next(
        (
            event
            for event in reversed(leases)
            if event.ts_utc <= recovery.ts_utc
        ),
        None,
    )
    evidence = [
        event
        for event in (
            down,
            gateway_readded[0] if gateway_readded else None,
            latest_lease,
            recovery,
        )
        if event is not None
    ]
    counter_evidence = [
        event
        for event in (
            customer_heartbeats[0] if customer_heartbeats else None,
            signal[0] if signal else None,
            gateway_ok[0] if gateway_ok else None,
        )
        if event is not None
    ]
    findings.append(
        Finding(
            rule_id="maintenance_backend_network_path_unresolved",
            severity="medium",
            title="Destination-specific route, NAT, firewall, or backend cause remains unresolved",
            explanation=(
                "Recovery closely followed a cellular data-call reset and a new DHCP lease, so "
                "source-IP, route-policy, carrier NAT, firewall, or remote-backend behavior are "
                "plausible. The logs do not show a manual IP configuration change or identify "
                "which of those layers failed. Healthy LTE signal samples, successful gateway "
                "checks, and customer-backend heartbeats argue against a general SIM or signal failure."
            ),
            evidence_event_ids=[event.id for event in evidence],
            counter_evidence_event_ids=[
                event.id for event in counter_evidence
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="destination_specific_network_path_unknown",
            affected_domain=Domain.NETWORK,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "During recurrence, capture ip addr, ip route, ip rule, and all routing tables over SSH.",
                "Compare DNS, ping, traceroute, and TCP port 1888 reachability for ioteu.suncharger.cn against the customer backend.",
                "Capture packets and maintenance-backend server/firewall logs using the charger timestamp and source IP.",
                "If routing is normal, swap the orange TCU SIM as an A/B isolation test and continue monitoring.",
            ],
        )
    )
    return findings


def _detect_customer_sim_path_failure(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    router_sim_detected = [
        event
        for event in ordered
        if event.attrs.get("state") == "router_sim_detected"
    ]
    router_lte = [
        event
        for event in ordered
        if event.attrs.get("state") == "router_lte_registered"
    ]
    router_lan_dhcp = [
        event
        for event in ordered
        if event.attrs.get("state") == "router_lan_dhcp_ack"
    ]
    router_recorded_down = [
        event
        for event in ordered
        if event.source == "router_network"
        and event.attrs.get("state") == "monitor_recorded_down"
    ]
    invalid_gateway = [
        event
        for event in ordered
        if event.source == "router_network"
        and event.attrs.get("state") == "invalid_gateway"
    ]
    external_ping_ok = [
        event
        for event in ordered
        if event.attrs.get("state") == "external_ping_ok"
    ]
    customer_dns = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "customer_ocpp"
        and event.attrs.get("state") == "dns_resolved"
    ]
    backend_states = [
        event
        for event in ordered
        if event.attrs.get("category") == "operation_backend_state"
    ]
    backend_good = next(
        (event for event in backend_states if event.attrs.get("state") == "good"),
        None,
    )
    backend_down = next(
        (
            event
            for event in backend_states
            if event.attrs.get("state") == "down"
            and (backend_good is None or event.ts_utc > backend_good.ts_utc)
        ),
        None,
    )
    customer_requests = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "customer_ocpp"
        and event.attrs.get("state") == "request_sent"
    ]
    customer_responses = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "customer_ocpp"
        and event.attrs.get("state") == "response_received"
    ]
    maintenance_responses = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "maintenance"
        and event.attrs.get("state") == "response_received"
    ]

    response_ids = {
        str(event.attrs.get("message_id"))
        for event in customer_responses
        if event.attrs.get("message_id")
    }
    answered_requests = [
        event
        for event in customer_requests
        if str(event.attrs.get("message_id")) in response_ids
    ]
    unanswered_requests = [
        event
        for event in customer_requests
        if str(event.attrs.get("message_id")) not in response_ids
        and (backend_good is None or event.ts_utc >= backend_good.ts_utc)
    ]
    maintenance_after_loss = next(
        (
            event
            for event in maintenance_responses
            if backend_down is not None and event.ts_utc >= backend_down.ts_utc
        ),
        None,
    )

    if backend_good is None or backend_down is None:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="Customer operation-backend state transition is incomplete",
                explanation=(
                    "The selected logs do not contain both operation-backend Good "
                    "and subsequent Down states."
                ),
                evidence_event_ids=[
                    event.id
                    for event in (
                        backend_good,
                        backend_down,
                        *customer_requests[-1:],
                    )
                    if event is not None
                ],
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.NETWORK,
                missing_evidence=list(case.ground_truth.missing_proof),
            )
        ]

    elapsed = _seconds_between(backend_good, backend_down)
    last_answered = answered_requests[-1] if answered_requests else None
    first_unanswered = next(
        (
            event
            for event in unanswered_requests
            if last_answered is None or event.ts_utc > last_answered.ts_utc
        ),
        unanswered_requests[0] if unanswered_requests else None,
    )
    findings = [
        Finding(
            rule_id="customer_router_backend_disconnect_confirmed",
            severity="high",
            title="Customer operation backend became unavailable on the router path",
            explanation=(
                "Vrouter_network initialized its customer-backend monitor with the "
                "connection recorded Down. Independently, the operation-backend state "
                f"changed from Good to Down in approximately {elapsed:.0f} seconds: "
                "earlier OCPP requests received matching responses, while later requests "
                "did not. The maintenance backend continued responding over Sungrow's "
                "separate maintenance-SIM path. Vnetwork evidence is intentionally excluded "
                "from customer-SIM attribution."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    router_recorded_down[-1] if router_recorded_down else None,
                    backend_good,
                    last_answered,
                    first_unanswered,
                    backend_down,
                    maintenance_after_loss,
                )
                if event is not None
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="customer_router_operation_backend_disconnect",
            affected_domain=Domain.NETWORK,
        )
    ]

    path_evidence = [
        event
        for event in (
            router_sim_detected[-1] if router_sim_detected else None,
            router_lte[0] if router_lte else None,
            router_lte[-1] if router_lte else None,
            router_lan_dhcp[-1] if router_lan_dhcp else None,
            router_recorded_down[-1] if router_recorded_down else None,
            invalid_gateway[-1] if invalid_gateway else None,
            external_ping_ok[-1] if external_ping_ok else None,
            customer_dns[-1] if customer_dns else None,
            backend_good,
            backend_down,
        )
        if event is not None
    ]
    rsrp_values = [
        int(event.attrs["rsrp"])
        for event in router_lte
        if str(event.attrs.get("rsrp", "")).lstrip("-").isdigit()
    ]
    radio_summary = (
        f"The router syslog contains {len(router_lte)} LTE registration samples"
        + (
            f" with RSRP from {min(rsrp_values)} to {max(rsrp_values)} dBm"
            if rsrp_values
            else ""
        )
        + f", plus {len(router_lan_dhcp)} LAN DHCP acknowledgements. "
        if router_lte or router_lan_dhcp
        else ""
    )
    findings.append(
        Finding(
            rule_id="customer_router_path_root_cause_unresolved",
            severity="medium",
            title="Router path is implicated, but the customer SIM card itself is not proven faulty",
            explanation=(
                f"{case.ground_truth.root_cause} {radio_summary}"
                "Vrouter_network passed external ping and repeatedly resolved the customer "
                "backend hostname, while also recording an invalid-gateway route-add attempt. "
                "The router syslog continued recognizing and registering the customer SIM. "
                "This excludes Vnetwork and the Sungrow maintenance SIM from the diagnosis, "
                "but does not distinguish a transient route setup problem, customer SIM "
                "subscription/APN or carrier policy, firewall/allowlist, or customer backend "
                "TCP/WebSocket behavior. DNS resolution alone does not prove that the OCPP "
                "WebSocket port is reachable."
            ),
            evidence_event_ids=[event.id for event in path_evidence],
            counter_evidence_event_ids=[
                event.id
                for event in (
                    router_sim_detected[-1] if router_sim_detected else None,
                    router_lte[-1] if router_lte else None,
                    external_ping_ok[-1] if external_ping_ok else None,
                    customer_dns[-1] if customer_dns else None,
                    maintenance_after_loss,
                )
                if event is not None
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="customer_router_path_unknown",
            affected_domain=Domain.NETWORK,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "During the failed state, test TCP/WebSocket reachability to every resolved customer-backend IP and port; DNS or ping alone is insufficient.",
                "Capture ip addr, ip route, ip rule, APN, ICCID, carrier registration, and a packet trace before rebooting.",
                "Move the same customer SIM to a known-good router/charger and place a known-good SIM in this charger for a controlled A/B test.",
                "Ask the carrier and customer backend teams to verify APN service, NAT, firewall/allowlist, and server logs for the charger source IP.",
            ],
        )
    )
    return findings


def _detect_fognode_operation_path_failure(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))

    def first_where(**attrs: str) -> Event | None:
        return next(
            (
                event
                for event in ordered
                if all(event.attrs.get(key) == value for key, value in attrs.items())
            ),
            None,
        )

    started = next(
        (
            event
            for event in ordered
            if event.source == "powercabinetfognode"
            and event.attrs.get("category") == "process_start"
        ),
        None,
    )
    operation_open = next(
        (
            event
            for event in ordered
            if event.type == EventType.WEBSOCKET_CONNECTED
            and event.attrs.get("endpoint") == "customer_ocpp"
        ),
        None,
    )
    operation_requests = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "customer_ocpp"
        and event.attrs.get("state") == "request_sent"
    ]
    operation_responses = [
        event
        for event in ordered
        if event.attrs.get("endpoint") == "customer_ocpp"
        and event.attrs.get("state") == "response_received"
    ]
    response_by_id = {
        str(event.attrs.get("message_id")): event
        for event in operation_responses
        if event.attrs.get("message_id")
    }
    boot_request = next(
        (
            event
            for event in operation_requests
            if str(event.attrs.get("action", "")).casefold()
            == "bootnotification"
        ),
        None,
    )
    boot_response = (
        response_by_id.get(str(boot_request.attrs.get("message_id")))
        if boot_request
        else None
    )
    heartbeat_request = next(
        (
            event
            for event in operation_requests
            if str(event.attrs.get("action", "")).casefold() == "heartbeat"
            and str(event.attrs.get("message_id")) in response_by_id
        ),
        None,
    )
    heartbeat_response = (
        response_by_id.get(str(heartbeat_request.attrs.get("message_id")))
        if heartbeat_request
        else None
    )
    heartbeat_timeout = first_where(
        endpoint="customer_ocpp", state="heartbeat_timeout"
    )
    maintenance_response = next(
        (
            event
            for event in ordered
            if event.attrs.get("endpoint") == "maintenance"
            and event.attrs.get("state") == "response_received"
            and (
                heartbeat_timeout is None
                or event.ts_utc >= heartbeat_timeout.ts_utc
            )
        ),
        None,
    )
    pong_timeout = first_where(endpoint="customer_ocpp", state="pong_timeout")
    reconnect_failure = first_where(
        endpoint="customer_ocpp", state="reconnect_failed"
    )
    reconnect_timeout = first_where(
        endpoint="customer_ocpp", state="reconnect_timeout"
    )
    disconnected_status = next(
        (
            event
            for event in ordered
            if event.attrs.get("category") == "fognode_backend_status"
            and str(event.attrs.get("operation_status", "")).casefold()
            == "disconnected"
            and str(event.attrs.get("maintenance_status", "")).casefold()
            == "connected"
            and str(event.attrs.get("public_net_status", "")).casefold()
            == "connected"
            and (
                heartbeat_timeout is None
                or event.ts_utc >= heartbeat_timeout.ts_utc
            )
        ),
        None,
    )
    ping_interval = next(
        (
            event
            for event in ordered
            if event.attrs.get("category") == "websocket_ping_interval"
            and event.attrs.get("endpoint") == "customer_ocpp"
        ),
        None,
    )
    router_sim = first_where(state="router_sim_detected")
    router_lte = [
        event
        for event in ordered
        if event.attrs.get("state") == "router_lte_registered"
    ]

    if not all(
        (
            started,
            operation_open,
            boot_request,
            boot_response,
            heartbeat_response,
            heartbeat_timeout,
            maintenance_response,
            pong_timeout,
            reconnect_timeout,
            disconnected_status,
        )
    ):
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="FogNode operation-path sequence is incomplete",
                explanation=(
                    "The selected FogNode/router logs do not contain the complete "
                    "startup, successful operation connection, heartbeat loss, Pong "
                    "timeout, reconnect timeout, and healthy maintenance-path sequence."
                ),
                evidence_event_ids=[
                    event.id
                    for event in (
                        started,
                        operation_open,
                        boot_response,
                        heartbeat_timeout,
                        maintenance_response,
                        pong_timeout,
                        reconnect_timeout,
                    )
                    if event is not None
                ],
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.NETWORK,
                missing_evidence=list(case.ground_truth.missing_proof),
            )
        ]

    findings = [
        Finding(
            rule_id="fognode_and_operation_initial_connection_confirmed",
            severity="info",
            title="FogNode and the configured Operation WebSocket initially worked",
            explanation=(
                "PowerCabinetFogNode completed startup, opened the Operation WebSocket "
                "with HTTP 101, received an Accepted BootNotification response, and "
                "received an Operation Heartbeat response. This rules out a stopped "
                "FogNode process and a persistently invalid Operation URL."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    started,
                    operation_open,
                    boot_request,
                    boot_response,
                    heartbeat_request,
                    heartbeat_response,
                )
                if event is not None
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="fognode_and_operation_configuration_healthy",
            affected_domain=Domain.OCPP,
        ),
        Finding(
            rule_id="operation_pong_timeout_and_reconnect_failure_confirmed",
            severity="high",
            title="Operation WebSocket lost Pong responses and could not reconnect",
            explanation=(
                "The Operation Heartbeat timed out while the Maintenance Heartbeat "
                "still received a reply. The Operation WebSocket then closed with code "
                "1006 because the peer did not answer Pong in time. Reconnection to "
                "connect.longship.io subsequently raised ConnectException and timed out, "
                "while status remained Operation=Disconnected, Maintenance=Connected, "
                "PublicNet=Connected. The 180-second Ping interval only delayed failure "
                "detection; it did not cause the network interruption."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    heartbeat_timeout,
                    maintenance_response,
                    disconnected_status,
                    pong_timeout,
                    reconnect_failure,
                    reconnect_timeout,
                    ping_interval,
                )
                if event is not None
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="operation_websocket_path_timeout",
            affected_domain=Domain.NETWORK,
        ),
    ]

    rsrp_values = [
        int(event.attrs["rsrp"])
        for event in router_lte
        if str(event.attrs.get("rsrp", "")).lstrip("-").isdigit()
    ]
    radio_detail = (
        f" Router syslog retained {len(router_lte)} LTE samples"
        + (
            f" with RSRP {min(rsrp_values)} to {max(rsrp_values)} dBm."
            if rsrp_values
            else "."
        )
        if router_lte
        else ""
    )
    findings.append(
        Finding(
            rule_id="customer_sim_to_operation_port_path_probable",
            severity="medium",
            title="Customer SIM/APN to Operation platform port is the probable fault domain",
            explanation=(
                f"{case.ground_truth.root_cause}{radio_detail} The SIM retained Internet "
                "and radio connectivity, while only the Operation destination stopped "
                "replying and timed out on reconnect. This is most consistent with "
                "destination/port-specific filtering in the customer APN or carrier, "
                "source-IP allowlisting/firewall policy, or the Longship endpoint. It "
                "does not support physical SIM-card failure."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    router_sim,
                    router_lte[0] if router_lte else None,
                    router_lte[-1] if router_lte else None,
                    heartbeat_timeout,
                    maintenance_response,
                    pong_timeout,
                    reconnect_timeout,
                    disconnected_status,
                )
                if event is not None
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="customer_apn_carrier_acl_or_operation_endpoint",
            affected_domain=Domain.NETWORK,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "While the customer SIM is active, run `nslookup connect.longship.io`.",
                "Run `nc -vz -w 10 connect.longship.io 80` to test the actual Operation TCP port.",
                "Run `ip route get $(getent hosts connect.longship.io | awk '{print $1; exit}')` to verify the selected egress path.",
                "Repeat the port test with a known-good SIM; immediate recovery isolates the customer SIM/APN or carrier policy.",
                "If every SIM times out, inspect Longship service, firewall, and source-IP allowlist logs.",
            ],
        )
    )
    return findings


def _detect_ev_invalid_target_voltage(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    invalid_targets = [
        event
        for event in ordered
        if event.type == EventType.PROTOCOL_ERROR
        and event.attrs.get("reason") == "invalid_target_voltage_below_minimum"
    ]
    requests = [
        event
        for event in ordered
        if event.type == EventType.ISO15118_STATE
        and event.attrs.get("message") == "P_CharReq"
    ]
    precharge_faults = [
        event
        for event in ordered
        if event.type == EventType.PROTOCOL_ERROR
        and event.attrs.get("stage") == "precharge"
    ]
    safety_stops = [
        event
        for event in ordered
        if event.type == EventType.EMERGENCY_STOP
        and event.attrs.get("origin") == "evse_protection"
    ]
    if not invalid_targets:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="No invalid EV target-voltage rejection found",
                explanation="The selected window does not contain the expected precharge target-voltage validation failure.",
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.ISO15118,
            )
        ]

    connectors = sorted(
        {
            event.connector_id
            for event in invalid_targets
            if event.connector_id is not None
        }
    )
    sources = sorted({event.source_location.path for event in invalid_targets if event.source_location})
    evidence = [
        *requests[:2],
        *invalid_targets[:4],
        *precharge_faults[:2],
        *safety_stops[:2],
    ]
    findings = [
        Finding(
            rule_id="ev_invalid_target_voltage_precharge_stop_confirmed",
            severity="high",
            title="EV requests were rejected for target voltage below the valid minimum",
            explanation=(
                f"The CCU recorded {len(invalid_targets)} invalid-target-voltage events "
                f"across connector(s) {connectors or 'unknown'} and {len(sources)} CCU log source(s). "
                "Each sequence occurs during the EV charge request/precharge path and is followed "
                "by the EVSE safety response to drop voltage. This confirms the immediate protocol "
                "reason charging did not proceed."
            ),
            evidence_event_ids=[event.id for event in evidence],
            confidence="high",
            status="confirmed",
            root_cause_category="ev_target_voltage_below_evse_minimum",
            affected_domain=Domain.ISO15118,
            recommended_actions=[
                "Compare the EV target-voltage field against EVSE minimum limits in an ISO 15118 packet capture.",
                "Retain the failed session trace as an interoperability regression test.",
            ],
        )
    ]
    findings.append(
        Finding(
            rule_id="mercedes_vehicle_software_root_cause_confirmed",
            severity="high",
            title="Mercedes Truck software behavior identified as the root cause",
            explanation=(
                "The failed logs repeatedly show the EV-side charge request being rejected for a "
                "target voltage below the charger's valid minimum. The same vehicle charged normally "
                "on the same IDC480E after its internal software update. That before/after result "
                "confirms vehicle software behavior as the root cause. Charging on another vendor "
                "before the update does not disprove this because protocol-limit handling can differ."
            ),
            evidence_event_ids=[
                event.id for event in (*requests[:1], *invalid_targets[:3])
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="vehicle_software_iso15118_interoperability",
            affected_domain=Domain.ISO15118,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "Record the Mercedes Truck software version before and after the successful update.",
                "Capture one successful post-update ISO 15118 session for field-level comparison.",
                "Do not loosen charger voltage safety limits without protocol and safety review.",
            ],
        )
    )
    return findings


def _detect_bmw_i3_module_switch_dip(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    targets = [
        event
        for event in ordered
        if event.type == EventType.CURRENT_DEMAND
        and event.attrs.get("measurement") == "EVTargetCurrent"
        and event.attrs.get("current_A") is not None
    ]
    feedback = [
        event for event in ordered if event.type == EventType.POWER_FEEDBACK
    ]
    cp_stops = [
        event
        for event in ordered
        if event.type == EventType.CP_STATE_CHANGE
        and event.attrs.get("transition") == "C_to_B"
    ]
    if not targets or not cp_stops:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="BMW i3 current-ramp/stop sequence is incomplete",
                explanation="The selected logs do not contain both stepwise EV target-current requests and C-to-B stops.",
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    def line_number(event: Event) -> int:
        return event.source_location.line if event.source_location and event.source_location.line else 0

    dip: tuple[Event, Event, Event] | None = None
    for stop in cp_stops:
        candidates = [
            event
            for event in feedback
            if event.source_location
            and stop.source_location
            and event.source_location.path == stop.source_location.path
            and line_number(event) < line_number(stop)
            and 0 <= _seconds_between(event, stop) <= 12
        ]
        if len(candidates) < 2:
            continue
        peak = max(candidates, key=lambda event: float(event.attrs.get("current_A", 0)))
        latest = max(candidates, key=line_number)
        peak_current = float(peak.attrs.get("current_A", 0))
        latest_current = float(latest.attrs.get("current_A", 0))
        if peak_current > 0 and latest_current <= peak_current * 0.85:
            dip = peak, latest, stop
            break

    unique_targets = sorted(
        {float(event.attrs.get("current_A", 0)) for event in targets}
    )
    ramp_evidence = [
        targets[0],
        targets[len(targets) // 2],
        targets[-1],
        *cp_stops[:2],
    ]
    findings = [
        Finding(
            rule_id="bmw_i3_stepwise_target_current_ramp_confirmed",
            severity="medium",
            title="BMW i3 requested current in a rising staircase",
            explanation=(
                f"The EV target-current requests span {unique_targets[0]:.1f} A to "
                f"{unique_targets[-1]:.1f} A across {len(targets)} request samples, "
                f"followed by {len(cp_stops)} C-to-B charging stops. This confirms the "
                "vehicle-specific gradual current ramp described for both attempts."
            ),
            evidence_event_ids=[event.id for event in ramp_evidence],
            confidence="high",
            status="confirmed",
            root_cause_category="ev_stepwise_current_ramp",
            affected_domain=Domain.ISO15118,
        )
    ]
    if dip:
        peak, reduced, stop = dip
        peak_current = float(peak.attrs["current_A"])
        reduced_current = float(reduced.attrs["current_A"])
        peak_power = float(peak.attrs["power_kW"])
        reduced_power = float(reduced.attrs["power_kW"])
        drop_percent = (peak_current - reduced_current) / peak_current * 100
        prior_targets = [
            event
            for event in targets
            if event.source_location
            and stop.source_location
            and event.source_location.path == stop.source_location.path
            and line_number(event) < line_number(stop)
        ]
        target = max(prior_targets, key=line_number) if prior_targets else None
        findings.append(
            Finding(
                rule_id="bmw_i3_module_switch_current_dip_root_cause",
                severity="high",
                title="Power-module transition caused a current dip before the vehicle stopped",
                explanation=(
                    f"While the BMW target rose to "
                    f"{float(target.attrs['current_A']):.1f} A, actual output fell from "
                    f"{peak_current:.1f} A ({peak_power:.1f} kW) to {reduced_current:.1f} A "
                    f"({reduced_power:.1f} kW), a {drop_percent:.1f}% dip, before the C-to-B stop. "
                    "The power crossed from above to below the 30 kW module rating. This matches "
                    "the confirmed PCU behavior: enabling another 30 kW module redistributed "
                    "current and created a transient drop that the BMW interpreted as a reason to stop. "
                    "The CCU labels the observed transition as C-to-B/normal-stop; it does not "
                    "independently prove an S3 EV_E_Stop code."
                ),
                evidence_event_ids=[
                    event.id
                    for event in (target, peak, reduced, stop)
                    if event is not None
                ],
                confidence=case.ground_truth.confidence,
                status=case.ground_truth.confirmation_status,
                root_cause_category="pcu_module_switch_output_current_dip",
                affected_domain=Domain.POWER,
                missing_evidence=list(case.ground_truth.missing_proof),
                recommended_actions=[
                    "For BMW i3 sessions, pre-enable two 30 kW modules before the current ramp crosses one-module capacity.",
                    "Keep module count stable during the sensitive rising-current phase.",
                    "Regression-test both 07:29 and 07:31:40 UTC attempts with high-rate module and output-current telemetry.",
                ],
            )
        )
    return findings


def _detect_lem2_internal_ethernet_fault(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    link_downs = [
        event
        for event in ordered
        if event.type == EventType.NETWORK_STATE
        and event.attrs.get("interface") == "eth1"
        and event.attrs.get("state") == "link_down"
    ]
    link_ups = [
        event
        for event in ordered
        if event.type == EventType.NETWORK_STATE
        and event.attrs.get("interface") == "eth1"
        and event.attrs.get("state") == "link_up"
    ]
    meter_offline = [
        event
        for event in ordered
        if event.type == EventType.CONNECTIVITY_LOST
        and event.attrs.get("endpoint") == "dc_meter"
        and event.connector_id == 2
    ]
    lem_vectors = [
        event
        for event in ordered
        if event.type == EventType.ERROR_CODE
        and event.attrs.get("category") == "lem_fault_vector"
        and event.connector_id == 2
    ]
    fault_entries = [
        event
        for event in ordered
        if event.connector_id == 2
        and (
            (
                event.type == EventType.CONNECTOR_STATUS
                and event.attrs.get("status") == "Faulted"
            )
            or event.attrs.get("category") == "connector_fault_state"
        )
    ]
    connector1_reachable = [
        event
        for event in ordered
        if event.attrs.get("device") == "dc_meter"
        and event.attrs.get("state") == "reachable"
        and event.connector_id == 1
    ]
    connector2_reachable = [
        event
        for event in ordered
        if event.attrs.get("device") == "dc_meter"
        and event.attrs.get("state") == "reachable"
        and event.connector_id == 2
    ]

    if not meter_offline or not lem_vectors:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="Connector 2 LEM communication-fault sequence is incomplete",
                explanation=(
                    "The selected logs do not contain both Meter 2 offline samples "
                    "and the Connector 2 LEM fault vector."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    offline = meter_offline[0]
    preceding_downs = [
        event for event in link_downs if event.ts_utc <= offline.ts_utc
    ]
    first_down = preceding_downs[0] if preceding_downs else None
    latest_down = preceding_downs[-1] if preceding_downs else None
    offline_count = sum(int(event.attrs.get("count", 1)) for event in meter_offline)
    codes = sorted(
        {
            code
            for event in lem_vectors
            for code in event.attrs.get("codes", [])
        },
        key=lambda value: int(str(value).lstrip("L") or 0),
    )

    findings = [
        Finding(
            rule_id="connector2_lem_communication_loss_confirmed",
            severity="high",
            title="Connector 2 lost communication with its LEM meter and entered Fault",
            explanation=(
                f"The charger recorded {offline_count} Connector 2 meter-offline samples. "
                f"The resulting LEM vector contained {', '.join(codes) or 'multiple LEM codes'}, "
                "including L20 (TCU-to-meter communication lost for more than 60 seconds), "
                "and Connector 2 then entered Fault. The simultaneous, unrelated LEM status "
                "bits are best treated as a communication-loss cascade rather than independent "
                "fatal, tamper, temperature, reverse-voltage, ADC, and RNG failures."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    offline,
                    *lem_vectors[:2],
                    *fault_entries[:3],
                )
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="connector2_lem_tcu_communication_loss",
            affected_domain=Domain.POWER,
        )
    ]

    if first_down:
        first_gap = _seconds_between(first_down, offline)
        latest_gap = _seconds_between(latest_down, offline) if latest_down else first_gap
        findings.append(
            Finding(
                rule_id="connector2_internal_ethernet_path_fault_probable",
                severity="high",
                title="Probable intermittent Ethernet path between TCU and Connector 2 LEM",
                explanation=(
                    f"eth1 first dropped {first_gap:.0f} seconds before the first Meter 2 "
                    f"offline record and dropped again {latest_gap:.0f} seconds before it. "
                    "Link flaps recur across the package, while the Connector 1 meter at "
                    "192.168.1.2 still responded and no successful response from Connector 2 "
                    "meter 192.168.10.2 appears in the incident window. This localizes the "
                    "problem to the Connector 2 internal Ethernet path or endpoint. A loose or "
                    "damaged RJ45 cable is plausible, but logs alone cannot distinguish cable, "
                    "connector, router/switch port, TCU eth1, or LEM hardware."
                ),
                evidence_event_ids=[
                    event.id
                    for event in (
                        first_down,
                        latest_down,
                        offline,
                        *lem_vectors[:1],
                    )
                    if event is not None
                ],
                counter_evidence_event_ids=[
                    event.id
                    for event in (
                        connector1_reachable[0] if connector1_reachable else None,
                        connector2_reachable[0] if connector2_reachable else None,
                        link_ups[0] if link_ups else None,
                    )
                    if event is not None
                ],
                confidence=case.ground_truth.confidence,
                status=case.ground_truth.confirmation_status,
                root_cause_category="connector2_internal_ethernet_path_intermittent",
                affected_domain=Domain.NETWORK,
                missing_evidence=list(case.ground_truth.missing_proof),
                recommended_actions=[
                    "SSH to the TCU eth1 network and capture `ping 192.168.10.2`.",
                    "Capture `curl -v http://192.168.10.2/v1/status` and `/v2/status`.",
                    "Check the TCU-to-LEM2 RJ45 path with a cable tester and monitor for instability.",
                    "Replace the cable, repeat ping/curl and the cable test, and retain before/after screenshots.",
                    "If replacement does not help, A/B test the router/switch port, TCU eth1, and LEM2 endpoint.",
                ],
            )
        )
    return findings


def _detect_lem2_http_service_hang(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    meter_offline = [
        event
        for event in ordered
        if event.type == EventType.CONNECTIVITY_LOST
        and event.attrs.get("endpoint") == "dc_meter"
        and event.connector_id == 2
    ]
    http_timeouts = [
        event
        for event in ordered
        if event.type == EventType.CONNECTIVITY_LOST
        and event.attrs.get("endpoint") == "dc_meter_http"
        and event.attrs.get("state") == "timeout"
    ]
    meter1_reachable = [
        event
        for event in ordered
        if event.attrs.get("device") == "dc_meter"
        and event.attrs.get("state") == "reachable"
        and event.connector_id == 1
    ]
    meter2_reachable = [
        event
        for event in ordered
        if event.attrs.get("device") == "dc_meter"
        and event.attrs.get("state") == "reachable"
        and event.connector_id == 2
    ]
    gateway_ok = [
        event
        for event in ordered
        if event.attrs.get("state") == "gateway_ok"
    ]
    link_downs = [
        event
        for event in ordered
        if event.attrs.get("interface") == "eth1"
        and event.attrs.get("state") == "link_down"
    ]

    if not meter_offline or not http_timeouts:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="LEM2 HTTP-service failure evidence is incomplete",
                explanation=(
                    "The selected logs do not contain both persistent Meter 2 "
                    "offline records and DC-meter HTTP TimeoutError responses."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    first_offline = meter_offline[0]
    last_offline_ts = max(
        str(event.attrs.get("last_ts") or event.ts_utc)
        for event in meter_offline
    )
    first_dt = datetime.fromisoformat(first_offline.ts_utc.replace("Z", "+00:00"))
    last_dt = datetime.fromisoformat(last_offline_ts.replace("Z", "+00:00"))
    duration_days = (last_dt - first_dt).total_seconds() / 86400
    offline_count = sum(int(event.attrs.get("count", 1)) for event in meter_offline)
    field_tests = case.metadata.get("field_tests", {})
    ping_passed = bool(field_tests.get("fault_ping_passed"))
    http_failed = bool(field_tests.get("fault_http_failed"))
    cable_passed = bool(field_tests.get("cable_continuity_passed"))
    power_cycle_recovered = bool(field_tests.get("power_cycle_recovered_http"))

    findings = [
        Finding(
            rule_id="connector2_meter_http_timeout_persistent_confirmed",
            severity="high",
            title="Connector 2 meter application requests timed out persistently",
            explanation=(
                f"The package contains {offline_count} Meter 2 offline samples over "
                f"at least {duration_days:.1f} days and {len(http_timeouts)} periodic "
                "DC-meter HTTP TimeoutError records. Connector 1 at 192.168.1.2 "
                f"completed {len(meter1_reachable)} time synchronizations, while "
                "Connector 2 at 192.168.10.2 completed none in the selected logs. "
                "This confirms a Connector 2-specific meter communication failure, "
                "not a charger-wide meter or external WAN outage."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    first_offline,
                    http_timeouts[0],
                    http_timeouts[-1],
                )
            ],
            counter_evidence_event_ids=[
                event.id
                for event in (
                    meter1_reachable[0] if meter1_reachable else None,
                    meter1_reachable[-1] if meter1_reachable else None,
                    gateway_ok[0] if gateway_ok else None,
                )
                if event is not None
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="connector2_dc_meter_http_timeout",
            affected_domain=Domain.POWER,
        )
    ]

    if ping_passed and http_failed and cable_passed and power_cycle_recovered:
        findings.append(
            Finding(
                rule_id="connector2_lem_http_service_hang_probable",
                severity="high",
                title="Probable recoverable hang in Connector 2 LEM HTTP service",
                explanation=(
                    "During the fault, 192.168.10.2 answered ICMP ping but its v1/v2 "
                    "HTTP status requests did not complete; cable continuity passed. "
                    "After a full power cycle, ping and both HTTP endpoints returned "
                    "healthy status JSON and Connector 2 recovered. Together with the "
                    "log timeouts and continued Connector 1 operation, this strongly "
                    "supports a hung LEM communication/status service rather than a "
                    "broken cable or fully dead meter. The exact firmware defect or "
                    "internal deadlock is not proven. The supplied SN-prefixed logs end "
                    "on July 1, so the July 3 post-restart recovery is supported by field "
                    "screenshots rather than an in-package post-restart log event."
                ),
                evidence_event_ids=[
                    event.id
                    for event in (
                        http_timeouts[0],
                        http_timeouts[-1],
                        first_offline,
                    )
                ],
                counter_evidence_event_ids=[
                    event.id
                    for event in (
                        meter1_reachable[-1] if meter1_reachable else None,
                        meter2_reachable[-1] if meter2_reachable else None,
                        link_downs[-1] if link_downs else None,
                    )
                    if event is not None
                ],
                confidence=case.ground_truth.confidence,
                status=case.ground_truth.confirmation_status,
                root_cause_category="lem_meter_http_service_hang",
                affected_domain=Domain.SYSTEM,
                missing_evidence=list(case.ground_truth.missing_proof),
                recommended_actions=[
                    "Collect LEM application/HTTP task logs and watchdog/reset reason before power cycling.",
                    "Record the LEM firmware version and compare it with known fixed versions.",
                    "Add continuous ping plus periodic v1/v2 HTTP probes to distinguish network loss from service hangs.",
                    "Capture a packet trace during recurrence to confirm TCP connect versus HTTP response timeout.",
                    "If supported, update LEM firmware and monitor whether the multi-day recurrence stops.",
                ],
            )
        )
    return findings


def _detect_dual_terminal_l20_recovery(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    serials = (
        case.source_selection.serial_number,
        *case.source_selection.related_serial_numbers,
    )

    def source_serial(event: Event) -> str:
        path = event.source_location.path if event.source_location else ""
        return next((serial for serial in serials if path.startswith(serial)), "")

    sequences: list[tuple[str, Event, Event, Event]] = []
    for serial in serials:
        offline_events = [
            event
            for event in ordered
            if source_serial(event) == serial
            and event.type == EventType.CONNECTIVITY_LOST
            and event.attrs.get("endpoint") == "dc_meter"
            and event.connector_id == 2
        ]
        triggers = [
            event
            for event in ordered
            if source_serial(event) == serial
            and event.type == EventType.ERROR_CODE
            and event.connector_id == 2
            and "L20" in event.attrs.get("codes", [])
        ]
        recoveries = [
            event
            for event in ordered
            if source_serial(event) == serial
            and event.type == EventType.ERROR_CODE_CLEARED
            and event.connector_id == 2
            and event.attrs.get("code") == "L20"
            and event.attrs.get("state") == "recovered"
        ]
        if not offline_events or not triggers or not recoveries:
            continue
        offline = offline_events[0]
        trigger = next(
            (
                event
                for event in triggers
                if 0 <= _seconds_between(offline, event) <= 15
            ),
            None,
        )
        recovery = next(
            (
                event
                for event in recoveries
                if trigger and 0 <= _seconds_between(trigger, event) <= 120
            ),
            None,
        )
        if trigger and recovery:
            sequences.append((serial, offline, trigger, recovery))

    if len(sequences) < len(serials):
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="Not all terminal L20 trigger/clear sequences were found",
                explanation=(
                    f"Complete offline, L20, and recovery sequences were found for "
                    f"{len(sequences)} of {len(serials)} selected terminal serials."
                ),
                evidence_event_ids=[
                    event.id
                    for _, offline, trigger, recovery in sequences
                    for event in (offline, trigger, recovery)
                ],
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    terminal_map = case.metadata.get("terminal_serial_map", {})
    sequence_text = []
    for serial, offline, trigger, recovery in sequences:
        terminal = terminal_map.get(serial, serial)
        sequence_text.append(
            f"{terminal}: L20 followed offline by "
            f"{_seconds_between(offline, trigger):.0f}s and cleared "
            f"{_seconds_between(trigger, recovery):.0f}s later"
        )

    connector1_offline = [
        event
        for event in ordered
        if event.type == EventType.CONNECTIVITY_LOST
        and event.attrs.get("endpoint") == "dc_meter"
        and event.connector_id == 1
    ]
    link_downs = [
        event
        for event in ordered
        if event.attrs.get("state") == "link_down"
    ]
    findings = [
        Finding(
            rule_id="dual_terminal_l20_trigger_clear_mechanism_confirmed",
            severity="medium",
            title="Both terminal L20 faults followed the designed trigger-and-clear mechanism",
            explanation=(
                "; ".join(sequence_text)
                + ". L20 is raised after the meter online counter is exhausted by "
                "failed REST polls. Once meter communication succeeds, the fatal "
                "meter state recovers, the L20 list is cleared, and the connector "
                "returns toward Available. No stuck L20 lifecycle is present here."
            ),
            evidence_event_ids=[
                event.id
                for _, offline, trigger, recovery in sequences
                for event in (offline, trigger, recovery)
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="lem_l20_expected_fault_lifecycle",
            affected_domain=Domain.POWER,
            recommended_actions=[
                "Keep the existing L20 threshold and automatic clear behavior.",
                "Trend failed REST polls and recovery duration per terminal and meter.",
            ],
        )
    ]
    findings.append(
        Finding(
            rule_id="dual_terminal_meter_communication_interruption_probable",
            severity="medium",
            title="Transient meter communication interruption is the probable trigger",
            explanation=(
                "The two terminal-local Connector 2 meters crossed the offline "
                "threshold at separate times and recovered automatically within about "
                "half a minute. Brief local Connector 1 meter faults also occurred near "
                "the same episodes. This supports transient REST/network communication "
                "loss rather than persistent meter hardware failure. The selected "
                f"window contains {len(link_downs)} explicit link-down events, so the "
                "logs do not identify whether the interruption came from Ethernet, "
                "HTTP service latency, TCU scheduling, or the meter itself."
            ),
            evidence_event_ids=[
                event.id
                for _, offline, trigger, _ in sequences
                for event in (offline, trigger)
            ],
            counter_evidence_event_ids=[
                event.id
                for _, _, _, recovery in sequences
                for event in (recovery,)
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="transient_meter_rest_communication_loss",
            affected_domain=Domain.NETWORK,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "Continue monitoring and correlate recurrences by terminal, meter IP, and time.",
                "Capture REST latency/error type and packet loss before the online counter reaches zero.",
                "Check whether both local meters or both terminals fail in the same short window.",
                "Escalate only if recovery stops, duration increases, or a repeatable timing pattern appears.",
            ],
        )
    )
    return findings


def _detect_plug_and_play_idtag_rejected(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    starts = [
        event
        for event in ordered
        if event.type == EventType.SESSION_START
        and event.attrs.get("endpoint") == "customer_ocpp"
    ]
    rejections = [
        event
        for event in ordered
        if event.type == EventType.AUTHORIZATION
        and event.attrs.get("endpoint") == "customer_ocpp"
        and event.attrs.get("action") == "StartTransaction"
        and event.attrs.get("auth_status") == "Invalid"
    ]
    deauthorized_stops = [
        event
        for event in ordered
        if event.type == EventType.SESSION_STOP
        and event.attrs.get("reason") == "DeAuthorized"
    ]
    maintenance_accepts = [
        event
        for event in ordered
        if event.type == EventType.AUTHORIZATION
        and event.attrs.get("endpoint") == "maintenance"
        and event.attrs.get("auth_status") == "Accepted"
    ]

    sequence: tuple[Event, Event, Event] | None = None
    for start in starts:
        rejection = next(
            (
                event
                for event in rejections
                if event.connector_id == start.connector_id
                and 0 <= _seconds_between(start, event) <= 5
            ),
            None,
        )
        stop = next(
            (
                event
                for event in deauthorized_stops
                if rejection
                and event.connector_id == start.connector_id
                and 0 <= _seconds_between(rejection, event) <= 30
            ),
            None,
        )
        if rejection and stop:
            sequence = start, rejection, stop
            break

    if not sequence:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="Plug & Play backend-rejection sequence is incomplete",
                explanation=(
                    "The selected OCPP log does not contain a correlated "
                    "StartTransaction, Invalid response, and DeAuthorized stop."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.OCPP,
            )
        ]

    start, rejection, stop = sequence
    id_tag = str(start.attrs.get("id_tag", ""))
    expected_id_tag = str(
        case.metadata.get("plug_and_play_id_tag")
        or case.source_selection.serial_number
    )
    duration = _seconds_between(start, stop)
    meter_start = int(start.attrs.get("meter_start", -1))
    meter_stop = int(stop.attrs.get("meter_stop", -2))
    no_energy = meter_start == meter_stop

    return [
        Finding(
            rule_id="plug_and_play_charger_idtag_rejected_confirmed",
            severity="high",
            title="Customer backend rejected the Plug & Play charger ID tag",
            explanation=(
                f"Connector {start.connector_id} sent StartTransaction with idTag "
                f"'{id_tag}', {'matching' if id_tag == expected_id_tag else 'not matching'} "
                f"the configured charger ID '{expected_id_tag}'. The customer backend "
                f"returned idTagInfo.status=Invalid and transactionId=0, then the charger "
                f"stopped with reason=DeAuthorized after {duration:.0f} seconds. "
                + (
                    "meterStart and meterStop were identical, confirming that no energy "
                    "was delivered. "
                    if no_energy
                    else ""
                )
                + "The charger initiated Plug & Play correctly; the failure is backend "
                "authorization/ID-tag registration, not a charging-control or firmware failure."
            ),
            evidence_event_ids=[
                start.id,
                rejection.id,
                stop.id,
            ],
            counter_evidence_event_ids=[
                event.id for event in maintenance_accepts[:1]
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="customer_backend_charger_idtag_not_registered",
            affected_domain=Domain.OCPP,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                f"Register '{expected_id_tag}' as a valid ID tag in the customer backend.",
                "Verify exact case and whitespace; OCPP 1.6 idTag matching should be treated as exact.",
                "Repeat Plug & Play and confirm StartTransactionResponse is Accepted with a non-zero transactionId.",
                "Confirm energy increases before closing the incident.",
            ],
        )
    ]


def _detect_precharge_residual_voltage(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    cablecheck_done = [
        event for event in ordered if event.type == EventType.CABLECHECK_FINISHED
    ]
    drop_commands = [
        event
        for event in ordered
        if event.type == EventType.POWER_REQUEST
        and event.attrs.get("action") == "drop_voltage"
    ]
    requests = [
        event
        for event in ordered
        if (
            (
                event.type == EventType.ISO15118_STATE
                and event.attrs.get("message") == "P_CharReq"
            )
            or (
                event.type == EventType.POWER_REQUEST
                and event.attrs.get("measurement") == "EVTargetVoltage"
            )
        )
        and isinstance(event.attrs.get("target_voltage_V"), (int, float))
    ]
    overvoltage = [
        event
        for event in ordered
        if event.type == EventType.ALARM
        and event.attrs.get("protection") == "output_over_ev_request_voltage"
    ]
    emergency_stops = [
        event
        for event in ordered
        if event.type == EventType.EMERGENCY_STOP
        and event.attrs.get("origin") == "evse_protection"
    ]
    stop_reports = [
        event
        for event in ordered
        if event.type == EventType.SESSION_STOP
        and event.attrs.get("reason") == "Precharge_Fault"
    ]

    def same_source(left: Event, right: Event) -> bool:
        return bool(
            left.source_location
            and right.source_location
            and left.source_location.path == right.source_location.path
        )

    def inner_delta(before: Event, after: Event) -> float | None:
        before_value = before.attrs.get("inner_time")
        after_value = after.attrs.get("inner_time")
        if not before_value or not after_value:
            return None
        start = datetime.strptime(str(before_value), "%H:%M:%S.%f")
        end = datetime.strptime(str(after_value), "%H:%M:%S.%f")
        return (end - start).total_seconds()

    sequences: list[tuple[Event, Event, Event, Event, Event | None]] = []
    for alarm in overvoltage:
        prior_requests = [
            event
            for event in requests
            if same_source(event, alarm)
            and event.ts_utc <= alarm.ts_utc
            and 0 <= _seconds_between(event, alarm) <= 2
        ]
        if not prior_requests:
            continue
        request = prior_requests[-1]
        prior_cablechecks = [
            event
            for event in cablecheck_done
            if same_source(event, request)
            and event.ts_utc <= request.ts_utc
            and 0 <= _seconds_between(event, request) <= 2
        ]
        prior_drops = [
            event
            for event in drop_commands
            if same_source(event, request)
            and event.ts_utc <= request.ts_utc
            and 0 <= _seconds_between(event, request) <= 2
        ]
        following_stop = next(
            (
                event
                for event in emergency_stops
                if same_source(event, alarm)
                and 0 <= _seconds_between(alarm, event) <= 2
            ),
            None,
        )
        if prior_cablechecks and prior_drops:
            sequences.append(
                (
                    prior_cablechecks[-1],
                    prior_drops[-1],
                    request,
                    alarm,
                    following_stop,
                )
            )

    if not sequences:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="PreCharge overvoltage sequence is incomplete",
                explanation=(
                    "No complete CableCheck, voltage-drop command, low-voltage "
                    "PreCharge request, and output-over-request alarm was found."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    targets = [float(item[2].attrs["target_voltage_V"]) for item in sequences]
    differences = [float(item[3].attrs["difference_V"]) for item in sequences]
    delays = [
        value
        for value in (inner_delta(item[2], item[3]) for item in sequences)
        if value is not None
    ]
    inferred_bus = [
        target + difference
        for target, difference in zip(targets, differences)
    ]
    connector_counts: dict[int, int] = {}
    for _, _, request, _, _ in sequences:
        if request.connector_id is not None:
            connector_counts[request.connector_id] = (
                connector_counts.get(request.connector_id, 0) + 1
            )
    threshold = float(case.metadata.get("voltage_difference_threshold_V", 12))

    findings = [
        Finding(
            rule_id="precharge_output_over_ev_voltage_protection_confirmed",
            severity="high",
            title="Low-voltage Tesla PreCharge triggered output-over-request protection",
            explanation=(
                f"The detailed CCU logs contain {len(sequences)} complete failure "
                f"sequences across connectors {connector_counts}. CableCheck completed, "
                "the charger commanded voltage to drop, and the Tesla requested "
                f"{min(targets):.0f}-{max(targets):.0f} V. The measured output-to-request "
                f"difference was {min(differences):.1f}-{max(differences):.1f} V, "
                f"exceeding the {threshold:.0f} V protection threshold, followed by "
                "EVSE emergency stop/PreCharge fault. Repeated Fault_State stop-reason "
                f"records ({len(stop_reports)}) are reports of these sequences, not "
                "necessarily separate charging attempts."
            ),
            evidence_event_ids=[
                event.id
                for cable, drop, request, alarm, stop in sequences[:3]
                for event in (cable, drop, request, alarm, stop)
                if event is not None
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="precharge_output_voltage_above_ev_request_limit",
            affected_domain=Domain.POWER,
        )
    ]

    delay_text = (
        f"{min(delays) * 1000:.0f}-{max(delays) * 1000:.0f} ms"
        if delays
        else "about 500 ms"
    )
    findings.append(
        Finding(
            rule_id="post_cablecheck_residual_voltage_timing_probable",
            severity="high",
            title="Probable residual bus voltage during the CableCheck-to-PreCharge transition",
            explanation=(
                f"The protection fired {delay_text} after each low-voltage EV request. "
                f"Combining requested voltage with the reported difference implies "
                f"approximately {min(inferred_bus):.1f}-{max(inferred_bus):.1f} V remained "
                "at the measured output point. This supports insufficient discharge or "
                "relay/contactor transition time after the higher-voltage CableCheck phase. "
                "The logs prove the residual-voltage condition but do not directly prove "
                "which relay, discharge path, or control delay caused it."
            ),
            evidence_event_ids=[
                event.id
                for cable, drop, request, alarm, _ in sequences[:4]
                for event in (cable, drop, request, alarm)
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="cablecheck_to_precharge_voltage_discharge_timing",
            affected_domain=Domain.POWER,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "Keep the output-versus-EV-request overvoltage protection enabled.",
                "Gate PreCharge on measured output voltage entering the EV target plus the allowed safety margin.",
                "Review discharge resistance, relay/contactor timing, weld detection, and voltage-sensor location.",
                "Add high-rate bus, EV-side voltage, relay command/feedback, and discharge-current telemetry.",
                "Regression-test low-voltage Tesla requests on both connectors after the timing fix.",
            ],
        )
    )
    return findings


def _detect_current_demand_overvoltage_unresolved(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    alarms = [
        event
        for event in ordered
        if event.type == EventType.ALARM
        and event.attrs.get("protection") == "output_over_ev_request_voltage"
    ]
    current_demand_faults = [
        event
        for event in ordered
        if event.type == EventType.PROTOCOL_ERROR
        and event.attrs.get("reason") == "Current_Demand_Fault"
    ]
    stop_reports = [
        event
        for event in ordered
        if event.type == EventType.SESSION_STOP
        and event.attrs.get("reason") == "Current_Demand_Fault"
    ]
    battery_overvoltage = [
        event
        for event in ordered
        if event.type == EventType.ERROR_CODE
        and "Battery_Overvoltage" in str(event.attrs.get("fault", ""))
    ]
    targets = [
        event
        for event in ordered
        if event.type == EventType.POWER_REQUEST
        and event.attrs.get("measurement") == "EVTargetVoltage"
    ]
    limits = [
        event
        for event in ordered
        if event.type == EventType.POWER_REQUEST
        and event.attrs.get("measurement") == "EVMaximumVoltageLimit"
    ]
    feedback = [
        event for event in ordered if event.type == EventType.POWER_FEEDBACK
    ]
    starts = [
        event
        for event in ordered
        if event.type == EventType.SESSION_START
        and event.attrs.get("endpoint") == "customer_ocpp"
    ]
    ocpp_stops = [
        event
        for event in ordered
        if event.type == EventType.SESSION_STOP
        and event.attrs.get("endpoint") == "customer_ocpp"
    ]
    statuses = [
        event
        for event in ordered
        if event.type == EventType.CONNECTOR_STATUS
    ]

    if not alarms or not current_demand_faults:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="CurrentDemand overvoltage sequence is incomplete",
                explanation=(
                    "The selected logs do not contain both the voltage-difference "
                    "alarm and CurrentDemand fault trigger."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    alarm = alarms[0]
    prior_targets = [event for event in targets if event.ts_utc <= alarm.ts_utc]
    prior_limits = [event for event in limits if event.ts_utc <= alarm.ts_utc]
    prior_feedback = [event for event in feedback if event.ts_utc <= alarm.ts_utc]
    target = prior_targets[-1] if prior_targets else None
    limit = prior_limits[-1] if prior_limits else None
    last_feedback = prior_feedback[-1] if prior_feedback else None
    difference = float(alarm.attrs.get("difference_V", 0))
    target_voltage = float(target.attrs.get("voltage_V", 0)) if target else 0
    inferred_voltage = target_voltage + difference if target_voltage else 0

    findings = [
        Finding(
            rule_id="current_demand_output_overvoltage_protection_confirmed",
            severity="high",
            title="CurrentDemand stopped on the CCU output-over-request protection",
            explanation=(
                f"Connector 2 triggered an output-to-EV-request difference of "
                f"{difference:.2f} V, followed by Current_Demand_Fault, EVSE emergency "
                "stop, and the battery-overvoltage fault state. The last recorded EV "
                f"target and maximum were both {target_voltage:.0f} V. If the protection "
                f"input was valid, it implies approximately {inferred_voltage:.1f} V "
                "at the sampled output point. This confirms why the CCU stopped, but "
                "does not prove the physical voltage was actually that high."
            ),
            evidence_event_ids=[
                event.id
                for event in (
                    target,
                    limit,
                    alarm,
                    current_demand_faults[0],
                    battery_overvoltage[0] if battery_overvoltage else None,
                    stop_reports[0] if stop_reports else None,
                )
                if event is not None
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="current_demand_output_over_request_protection",
            affected_domain=Domain.POWER,
        )
    ]

    feedback_age = (
        _seconds_between(last_feedback, alarm) if last_feedback else None
    )
    feedback_voltage = (
        float(last_feedback.attrs.get("voltage_V", 0))
        if last_feedback
        else 0
    )
    findings.append(
        Finding(
            rule_id="current_demand_true_overvoltage_vs_sample_unresolved",
            severity="high",
            title="Actual PCU overvoltage versus bad CCU sample remains unresolved",
            explanation=(
                f"The last Connector_Power value was {feedback_voltage:.0f} V, but it "
                f"was {feedback_age:.0f} seconds old when the alarm fired and therefore "
                "cannot refute a millisecond-scale transient. Conversely, the package "
                "does not contain the referenced PCU segment "
                "`pcu_20260728050417.log` or synchronized PM voltage samples proving "
                f"the inferred {inferred_voltage:.1f} V. Module switching, a real PCU "
                "overshoot, CCU sensor/ADC error, stale data, or a single bad sampled "
                "point remain plausible. No root cause should be declared yet."
            ),
            evidence_event_ids=[
                event.id
                for event in (last_feedback, alarm)
                if event is not None
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="overvoltage_or_voltage_sample_unknown",
            affected_domain=Domain.POWER,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "Obtain the exact PCU/PM log segment covering 05:04:14-05:04:16 UTC.",
                "Align CCU ADC voltage, PCU bus voltage, PM output voltage, and module-count changes at millisecond resolution.",
                "Verify voltage-sensor scaling, filtering, freshness, and outlier rejection.",
                "Do not weaken the overvoltage protection until the physical-versus-sampled value is resolved.",
            ],
        )
    )

    external_connector = int(case.metadata.get("external_connector_id", 4))
    retry_start = next(
        (
            event
            for event in starts
            if event.connector_id == external_connector
            and event.ts_utc > alarm.ts_utc
        ),
        None,
    )
    first_stop = next(
        (
            event
            for event in ocpp_stops
            if event.connector_id == external_connector
            and 0 <= _seconds_between(alarm, event) <= 5
            and event.attrs.get("reason") == "Other"
        ),
        None,
    )
    retry_stop = next(
        (
            event
            for event in ocpp_stops
            if retry_start
            and event.connector_id == external_connector
            and event.ts_utc > retry_start.ts_utc
        ),
        None,
    )
    retry_charging = next(
        (
            event
            for event in reversed(statuses)
            if retry_start
            and event.connector_id == external_connector
            and event.attrs.get("status") == "Charging"
            and event.ts_utc <= retry_start.ts_utc
        ),
        None,
    )
    if retry_start and retry_stop:
        first_txn = first_stop.attrs.get("transaction_id") if first_stop else None
        retry_txn = retry_stop.attrs.get("transaction_id")
        delivered = int(retry_stop.attrs.get("meter_stop", 0)) - int(
            retry_start.attrs.get("meter_start", 0)
        )
        findings.append(
            Finding(
                rule_id="replug_started_new_successful_transaction_confirmed",
                severity="info",
                title="Replugging started a separate transaction that delivered energy",
                explanation=(
                    f"The failed transaction ID was {first_txn}; after the replug, a "
                    f"new StartTransaction led to transaction ID {retry_txn}. The meter "
                    f"increased by {delivered} raw units before a later Local stop. "
                    "This was a separate session, not continuation of the original "
                    "transaction. Its success argues against a persistent battery or "
                    "charger fault, but does not by itself exclude a transient EV-side "
                    "event or prove that the first voltage sample was false."
                ),
                evidence_event_ids=[
                    event.id
                    for event in (
                        first_stop,
                        retry_charging,
                        retry_start,
                        retry_stop,
                    )
                    if event is not None
                ],
                confidence="high",
                status="confirmed",
                root_cause_category="successful_new_transaction_after_replug",
                affected_domain=Domain.OCPP,
            )
        )
    return findings


def _detect_ems_low_power_taper(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    soc_events = [
        event
        for event in ordered
        if event.type == EventType.ISO15118_STATE
        and event.attrs.get("message") == "C_DemandReq"
        and event.attrs.get("soc")
    ]
    targets = [
        event
        for event in ordered
        if event.type == EventType.CURRENT_DEMAND
        and event.attrs.get("measurement") == "EVTargetCurrent"
    ]
    ems_limits = [
        event
        for event in ordered
        if event.type == EventType.POWER_REQUEST
        and event.attrs.get("controller") == "EMS300CP"
        and str(event.attrs.get("gun")) == "2"
        and event.attrs.get("power_kW") is not None
    ]
    feedback = [
        event
        for event in ordered
        if event.type == EventType.POWER_FEEDBACK
        and event.connector_id == 2
        and event.attrs.get("current_A") is not None
        and event.attrs.get("voltage_V") is not None
    ]

    if not soc_events or not targets or not ems_limits or not feedback:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="EV/EMS low-power correlation is incomplete",
                explanation=(
                    "The selected logs do not contain all of EV SoC, EV target "
                    "current, EMS gun power allocation, and connector feedback."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    def parsed_ts(event: Event) -> datetime:
        return datetime.fromisoformat(event.ts_utc.replace("Z", "+00:00"))

    high_soc = [event for event in soc_events if int(event.attrs["soc"]) >= 78]
    if not high_soc:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="No high-SoC taper period found",
                explanation="No CurrentDemand SoC sample at or above 78% was parsed.",
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.ISO15118,
            )
        ]

    taper_start = parsed_ts(high_soc[0])
    taper_end = parsed_ts(high_soc[-1]) + timedelta(seconds=60)
    taper_targets = [
        event
        for event in targets
        if taper_start <= parsed_ts(event) <= taper_end
    ]
    if not taper_targets:
        taper_targets = [
            event for event in targets if parsed_ts(event) >= taper_start
        ]
    first_target = taper_targets[0]
    final_target = taper_targets[-1]
    min_target = min(
        taper_targets, key=lambda event: float(event.attrs.get("current_A", 0))
    )
    final_time = parsed_ts(final_target)
    prior_feedback = [
        event for event in feedback if parsed_ts(event) <= final_time
    ]
    prior_ems = [
        event for event in ems_limits if parsed_ts(event) <= final_time
    ]
    if not prior_feedback or not prior_ems:
        return [
            Finding(
                rule_id="inconclusive",
                severity="medium",
                title="No aligned EV, EMS, and connector endpoint sample",
                explanation=(
                    "The selected window has the required signal types, but no "
                    "complete connector feedback and EMS sample at or before the "
                    "final EV CurrentDemand point."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]
    final_feedback = prior_feedback[-1]
    final_ems = prior_ems[-1]
    final_voltage = float(final_feedback.attrs.get("voltage_V", 0))
    final_ev_current = float(final_target.attrs.get("current_A", 0))
    final_ev_power = final_voltage * final_ev_current / 1000
    final_ems_power = float(final_ems.attrs.get("power_kW", 0))
    first_ems = next(
        (
            event
            for event in ems_limits
            if parsed_ts(event) >= taper_start
        ),
        ems_limits[0],
    )
    first_ems_power = float(first_ems.attrs.get("power_kW", 0))
    min_ems_power = min(
        float(event.attrs.get("power_kW", 0)) for event in ems_limits
    )
    soc_min = min(int(event.attrs["soc"]) for event in high_soc)
    soc_max = max(int(event.attrs["soc"]) for event in high_soc)

    findings = [
        Finding(
            rule_id="ev_high_soc_current_taper_confirmed",
            severity="medium",
            title="The EV itself tapered CurrentDemand to approximately 1 A",
            explanation=(
                f"Between {soc_min}% and {soc_max}% SoC, EVTargetCurrent fell from "
                f"{float(first_target.attrs['current_A']):.1f} A to "
                f"{final_ev_current:.1f} A, with a minimum request of "
                f"{float(min_target.attrs['current_A']):.1f} A. Connector feedback "
                f"reached {float(final_feedback.attrs['current_A']):.1f} A at "
                f"approximately {final_voltage:.0f} V. This directly confirms that "
                "the low delivered current was requested by the EV/BMS during the "
                "high-SoC taper period."
            ),
            evidence_event_ids=[
                high_soc[0].id,
                first_target.id,
                high_soc[-1].id,
                min_target.id,
                final_feedback.id,
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="ev_bms_high_soc_current_taper",
            affected_domain=Domain.ISO15118,
        )
    ]
    findings.append(
        Finding(
            rule_id="ems_low_allocation_not_primary_limiter_probable",
            severity="medium",
            title="EMS allocation also fell, but was above the final EV demand",
            explanation=(
                f"EMS300CP gun 2 allocation decreased from about "
                f"{first_ems_power:.1f} kW to a {min_ems_power:.1f} kW floor. "
                f"Near the final EV request, EMS still allowed {final_ems_power:.1f} kW "
                f"while the EV requested only about {final_ev_power:.1f} kW "
                f"({final_ev_current:.1f} A at {final_voltage:.0f} V). Therefore the "
                "EMS limit was not the binding constraint at the low-current endpoint. "
                "Its falling allocation may be a response to observed demand or part "
                "of the site strategy; the log does not expose the EMS input policy, "
                "so its causal contribution earlier in the taper remains unresolved."
            ),
            evidence_event_ids=[
                first_ems.id,
                final_ems.id,
                final_target.id,
                final_feedback.id,
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="ems_allocation_tracks_ev_taper",
            affected_domain=Domain.POWER,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "Ask the customer for the EMS300CP site-limit strategy and all inputs used during 06:49-06:53 UTC.",
                "Confirm the EV model, BMS charging curve, configured charge limit, and expected taper near 78-82% SoC.",
                "Log requested EV power, EMS available power, site load, and applied connector limit as separate values.",
                "Do not attribute the low power to an internal charger limit unless a lower charger-side constraint is recorded.",
            ],
        )
    )
    return findings


def _detect_s25_dynamic_ramp_tracking(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    clear_request = next(
        (
            event
            for event in ordered
            if event.attrs.get("action") == "ClearChargingProfile"
            and event.type == EventType.POWER_REQUEST
        ),
        None,
    )
    clear_accepted = next(
        (
            event
            for event in ordered
            if event.attrs.get("action") == "ClearChargingProfile"
            and event.attrs.get("status") == "Accepted"
        ),
        None,
    )
    smart_limit = next(
        (
            event
            for event in ordered
            if event.attrs.get("controller") == "smart_charging"
            and float(event.attrs.get("power_kW", 0)) == 15
        ),
        None,
    )
    evse_limit = next(
        (
            event
            for event in ordered
            if event.type == EventType.EV_CURRENT_LIMIT
            and abs(float(event.attrs.get("current_A", 0)) - 18.9) < 0.01
        ),
        None,
    )
    alarm = next(
        (
            event
            for event in ordered
            if event.attrs.get("protection") == "output_current_over_ev_request"
        ),
        None,
    )
    s25 = next(
        (
            event
            for event in ordered
            if event.type == EventType.ERROR_CODE
            and event.attrs.get("code") == "S25"
        ),
        None,
    )
    stop = next(
        (
            event
            for event in ordered
            if event.type == EventType.SESSION_STOP
            and event.attrs.get("reason") == "Current_Demand_Fault"
        ),
        None,
    )
    required = [
        clear_request,
        clear_accepted,
        smart_limit,
        evse_limit,
        alarm,
        s25,
    ]
    if any(event is None for event in required):
        return [
            Finding(
                rule_id="inconclusive",
                severity="high",
                title="S25 dynamic ramp-down chain is incomplete",
                explanation=(
                    "The selected logs do not contain the complete profile-clear, "
                    "15 kW limit, EVSE 18.9 A limit, tracking alarm, and S25 chain."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    assert clear_request and clear_accepted and smart_limit and evse_limit
    assert alarm and s25
    cabinet_current = [
        event
        for event in ordered
        if event.type == EventType.POWER_FEEDBACK
        and event.attrs.get("device") == "power_cabinet"
        and event.attrs.get("measurement") == "output_current"
        and _seconds_between(event, clear_request) >= 0
    ]
    cabinet_voltage = [
        event
        for event in ordered
        if event.type == EventType.POWER_FEEDBACK
        and event.attrs.get("device") == "power_cabinet"
        and event.attrs.get("measurement") == "output_voltage"
        and _seconds_between(event, clear_request) >= 0
    ]
    pre_current = cabinet_current[-1] if cabinet_current else None
    pre_voltage = cabinet_voltage[-1] if cabinet_voltage else None
    pre_power_kw = 0.0
    if pre_current and pre_voltage:
        pre_power_kw = (
            float(pre_current.attrs["current_A"])
            * float(pre_voltage.attrs["voltage_V"])
            / 1000
        )

    targets = [
        event
        for event in ordered
        if event.type == EventType.CURRENT_DEMAND
        and event.connector_id == 1
        and 0 <= _seconds_between(evse_limit, event) <= 13
    ]
    feedback = [
        event
        for event in ordered
        if event.type == EventType.POWER_FEEDBACK
        and event.connector_id == 1
        and event.attrs.get("device") != "power_cabinet"
        and 0 <= _seconds_between(evse_limit, event) <= 13
    ]
    alarm_line = alarm.source_location.line if alarm.source_location else 10**12
    pre_alarm_targets = [
        event
        for event in targets
        if _seconds_between(event, alarm) >= 0
        and (
            event.ts_utc != alarm.ts_utc
            or not event.source_location
            or event.source_location.line < alarm_line
        )
    ]
    pre_alarm_feedback = [
        event
        for event in feedback
        if _seconds_between(event, alarm) >= 0
        and (
            event.ts_utc != alarm.ts_utc
            or not event.source_location
            or event.source_location.line < alarm_line
        )
    ]
    first_target = targets[0] if targets else None
    last_target = pre_alarm_targets[-1] if pre_alarm_targets else None
    last_feedback = pre_alarm_feedback[-1] if pre_alarm_feedback else None
    if not first_target or not last_target or not last_feedback:
        return [
            Finding(
                rule_id="inconclusive",
                severity="high",
                title="S25 current traces are incomplete",
                explanation=(
                    "The profile and S25 events exist, but EV target-current and "
                    "charger output-current samples could not be correlated."
                ),
                evidence_event_ids=[event.id for event in required if event],
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    initial_target = float(first_target.attrs["current_A"])
    final_target = float(last_target.attrs["current_A"])
    final_output = float(last_feedback.attrs["current_A"])
    final_gap = final_output - final_target
    limit_to_alarm_s = _seconds_between(evse_limit, alarm)
    clear_to_alarm_s = _seconds_between(clear_request, alarm)

    findings = [
        Finding(
            rule_id="smart_profile_abrupt_step_down_confirmed",
            severity="high",
            title="Clearing the 250 kW profile exposed an immediate 15 kW limit",
            explanation=(
                f"The platform cleared profile {clear_request.attrs.get('profile_id')} "
                f"and the dispenser accepted the request. The remaining smart-charging "
                f"profile applied 15.0 kW, which the CCU advertised as an 18.9 A "
                f"maximum. Before the change, cabinet output was approximately "
                f"{pre_power_kw:.1f} kW. This was an abrupt operating-point step, "
                "not an over-rated-current event."
            ),
            evidence_event_ids=[
                clear_request.id,
                clear_accepted.id,
                smart_limit.id,
                evse_limit.id,
                *(
                    [pre_current.id, pre_voltage.id]
                    if pre_current and pre_voltage
                    else []
                ),
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="abrupt_smart_charging_profile_step",
            affected_domain=Domain.OCPP,
        ),
        Finding(
            rule_id="s25_dynamic_current_tracking_lag_confirmed",
            severity="high",
            title="Charger down-ramp lag triggered the S25 tracking protection",
            explanation=(
                f"After the 18.9 A limit was advertised, EVTargetCurrent ramped from "
                f"{initial_target:.0f} A to {final_target:.0f} A rather than stepping "
                f"immediately to the cap. Charger output also ramped down but was still "
                f"{final_output:.0f} A near the alarm, about {final_gap:.0f} A above "
                f"the EV request. The mismatch persisted until the output-current-over-"
                f"EV-request alarm at {limit_to_alarm_s:.0f} s and was reported as "
                f"S25/OverCurrentFailure about {clear_to_alarm_s:.0f} s after the "
                "profile-clear command. This confirms insufficient current tracking "
                "during the forced dynamic reduction."
            ),
            evidence_event_ids=[
                evse_limit.id,
                first_target.id,
                last_target.id,
                last_feedback.id,
                alarm.id,
                s25.id,
                *([stop.id] if stop else []),
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="charger_current_down_ramp_tracking_lag",
            affected_domain=Domain.POWER,
            recommended_actions=[
                "Coordinate CCU and PCU down-ramp control so output does not remain above a falling EV target for the S25 timer duration.",
                "Apply a controlled transition when charging profiles change abruptly instead of a 250 kW to 15 kW step.",
                "Remove the transient fallback to 480 kW while profiles are reinitialized.",
                "Keep S25 protection enabled; validate any timer or threshold change against safety and protocol requirements.",
            ],
        ),
        Finding(
            rule_id="ev_slow_compliance_with_new_limit_contributed",
            severity="medium",
            title="The truck also remained above the newly advertised EVSE limit",
            explanation=(
                f"The CCU advertised 18.9 A, but the truck still requested "
                f"{final_target:.0f} A near the stop. The truck's gradual ramp-down "
                "increased the transition duration, while the direct S25 trigger was "
                "the charger output remaining above the truck's changing request."
            ),
            evidence_event_ids=[
                evse_limit.id,
                first_target.id,
                last_target.id,
                alarm.id,
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="ev_slow_response_to_evse_limit",
            affected_domain=Domain.ISO15118,
            missing_evidence=list(case.ground_truth.missing_proof),
        ),
    ]
    return findings


def _detect_initial_precharge_zero_voltage(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    zero_requests = [
        event
        for event in ordered
        if event.type == EventType.POWER_REQUEST
        and event.attrs.get("category") == "initial_precharge_zero_voltage"
    ]
    zero_waits = [
        event
        for event in ordered
        if event.attrs.get("state") == "precharge_wait_for_higher_voltage"
        and float(event.attrs.get("target_voltage_V", -1)) == 0
    ]
    real_targets = [
        event
        for event in ordered
        if event.type == EventType.POWER_REQUEST
        and event.attrs.get("measurement") == "EVTargetVoltage"
        and float(event.attrs.get("voltage_V", 0)) > 300
    ]
    feedback = [
        event
        for event in ordered
        if event.type == EventType.POWER_FEEDBACK
        and float(event.attrs.get("voltage_V", 0)) > 0
    ]
    vehicle_stops = [
        event
        for event in ordered
        if event.type == EventType.NORMAL_STOP
        and event.attrs.get("initiator") == "vehicle"
    ]
    if not zero_requests or not zero_waits or not real_targets or not feedback:
        return [
            Finding(
                rule_id="inconclusive",
                severity="high",
                title="Initial PreCharge zero-voltage sequence is incomplete",
                explanation=(
                    "The selected logs do not contain the complete initial zero "
                    "target, later valid target, output-voltage, and vehicle-stop chain."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.ISO15118,
            )
        ]

    representative_text = str(
        case.metadata.get("representative_attempt_utc", "")
    )
    representative_ts = (
        datetime.fromisoformat(representative_text.replace("Z", "+00:00"))
        if representative_text
        else datetime.fromisoformat(
            zero_requests[0].ts_utc.replace("Z", "+00:00")
        )
    )
    representative = min(
        zero_requests,
        key=lambda event: abs(
            (
                datetime.fromisoformat(event.ts_utc.replace("Z", "+00:00"))
                - representative_ts
            ).total_seconds()
        ),
    )
    later_target = next(
        (
            event
            for event in real_targets
            if event.connector_id == representative.connector_id
            and 0 <= _seconds_between(representative, event) <= 2
        ),
        None,
    )
    vehicle_stop = next(
        (
            event
            for event in vehicle_stops
            if event.connector_id == representative.connector_id
            and 0 <= _seconds_between(representative, event) <= 10
        ),
        None,
    )
    before_feedback = [
        event
        for event in feedback
        if event.connector_id == representative.connector_id
        and 0 <= _seconds_between(event, representative) <= 3
    ]
    after_feedback = [
        event
        for event in feedback
        if event.connector_id == representative.connector_id
        and _seconds_between(representative, event) >= 0
        and (
            vehicle_stop is None
            or _seconds_between(event, vehicle_stop) >= 0
        )
    ]
    if (
        later_target is None
        or vehicle_stop is None
        or not before_feedback
        or not after_feedback
    ):
        return [
            Finding(
                rule_id="inconclusive",
                severity="high",
                title="Representative PreCharge attempt cannot be correlated",
                explanation=(
                    "Repeated zero-target requests exist, but a single attempt lacks "
                    "all voltage-collapse and EV-stop evidence."
                ),
                evidence_event_ids=[event.id for event in zero_requests[:10]],
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.ISO15118,
            )
        ]

    before = before_feedback[-1]
    minimum = min(
        after_feedback, key=lambda event: float(event.attrs["voltage_V"])
    )
    final_before_stop = after_feedback[-1]
    initial_voltage = float(before.attrs["voltage_V"])
    minimum_voltage = float(minimum.attrs["voltage_V"])
    requested_voltage = float(later_target.attrs["voltage_V"])
    final_voltage = float(final_before_stop.attrs["voltage_V"])
    stop_delay = _seconds_between(representative, vehicle_stop)
    faults_during_attempt = [
        event
        for event in ordered
        if event.type in {EventType.ALARM, EventType.ERROR_CODE}
        and event.connector_id == representative.connector_id
        and 0 <= _seconds_between(representative, event) <= stop_delay
    ]

    return [
        Finding(
            rule_id="repeated_initial_precharge_zero_voltage_confirmed",
            severity="high",
            title="The ORA repeatedly started PreCharge without a valid target voltage",
            explanation=(
                f"The retained CCU logs contain {len(zero_waits)} attempts where "
                "the first PreCharge request had no valid EV_Target_V and the CCU "
                "internally used target voltage 0 V. The customer reported 15 attempts; "
                f"{len(zero_waits)} are directly confirmed by this archive."
            ),
            evidence_event_ids=[
                *[event.id for event in zero_requests[:5]],
                *[event.id for event in zero_waits[:5]],
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="ev_initial_precharge_target_voltage_missing",
            affected_domain=Domain.ISO15118,
        ),
        Finding(
            rule_id="zero_target_output_collapse_confirmed",
            severity="high",
            title="Treating the initial target as 0 V collapsed charger output",
            explanation=(
                f"In the representative attempt, output was about "
                f"{initial_voltage:.0f} V when the 0 V target was processed. The EV "
                f"then requested approximately {requested_voltage:.1f} V within "
                f"{_seconds_between(representative, later_target):.1f} s, but output "
                f"fell to {minimum_voltage:.0f} V. It recovered only to about "
                f"{final_voltage:.0f} V before the EV stopped, so the charger could "
                "not reach the new target in the available PreCharge window."
            ),
            evidence_event_ids=[
                before.id,
                representative.id,
                later_target.id,
                minimum.id,
                final_before_stop.id,
                vehicle_stop.id,
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="charger_zero_target_precharge_handling",
            affected_domain=Domain.POWER,
        ),
        Finding(
            rule_id="ora_precharge_compatibility_software_change_required",
            severity="high",
            title="CCU PreCharge handling requires a zero/missing-target compatibility fix",
            explanation=(
                f"The EV requested a normal stop after {stop_delay:.1f} s, with "
                f"{len(faults_during_attempt)} charger alarm/error-code events in the "
                "attempt. The failure is a deterministic timing interaction: an "
                "initial missing/zero target causes output collapse, then the valid "
                "approximately 374 V target arrives too late for the restarted power "
                "path to settle. This is a software compatibility defect rather than "
                "a hardware fault."
            ),
            evidence_event_ids=[
                representative.id,
                later_target.id,
                minimum.id,
                vehicle_stop.id,
            ],
            confidence=case.ground_truth.confidence,
            status=case.ground_truth.confirmation_status,
            root_cause_category="precharge_zero_target_software_compatibility",
            affected_domain=Domain.ISO15118,
            missing_evidence=list(case.ground_truth.missing_proof),
            recommended_actions=[
                "Change CCU PreCharge logic to debounce or hold the safe present-voltage state when the first EV target voltage is missing or zero.",
                "Accept and ramp to the first valid EV_Target_V without power-module stop/restart latency, subject to insulation and voltage safety checks.",
                "Add a bounded timeout for receiving a valid target; do not wait indefinitely or disable voltage protections.",
                "Regression-test both connectors with the Great Wall ORA and with EVs that send a valid target in the first PreCharge request.",
            ],
        ),
    ]


def _detect_c36_cp_state_e_lifecycle(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    state_e = [
        event
        for event in ordered
        if event.type == EventType.CP_STATE_CHANGE
        and event.attrs.get("transition") == "A_to_E"
    ]
    alarm80 = [
        event
        for event in ordered
        if event.type == EventType.ALARM
        and event.attrs.get("internal_alarm_id") == "80"
    ]
    non_forced = [
        event
        for event in ordered
        if event.attrs.get("cp_state") == "E"
        and event.attrs.get("forced") == "false"
    ]
    recoveries = [
        event
        for event in ordered
        if event.type == EventType.ERROR_CODE_CLEARED
        and event.attrs.get("code") == "C36"
    ]
    code_lists = [
        event
        for event in ordered
        if event.attrs.get("category") == "connector_alarm_vector"
    ]
    c36_reports = [
        event for event in code_lists if "C36" in event.attrs.get("codes", [])
    ]
    c2_reports = [
        event for event in code_lists if "C2" in event.attrs.get("codes", [])
    ]
    ac_samples = [
        event
        for event in ordered
        if event.attrs.get("measurement") == "r37_ac_input"
    ]
    if not state_e or not alarm80 or not non_forced or not c36_reports:
        return [
            Finding(
                rule_id="inconclusive",
                severity="high",
                title="C36/CP State E evidence is incomplete",
                explanation=(
                    "The selected logs do not contain the complete A-to-E, alarm "
                    "80, non-forced State E, and C36 reporting chain."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.CP,
            )
        ]

    trigger_c36 = c36_reports[0]
    nearby_state_e = [
        event
        for event in state_e
        if abs(_seconds_between(event, trigger_c36)) <= 5
    ]
    trigger = nearby_state_e[-1] if nearby_state_e else state_e[0]
    trigger_alarm = next(
        (
            event
            for event in alarm80
            if 0 <= _seconds_between(trigger, event) <= 2
        ),
        alarm80[0],
    )
    trigger_non_forced = next(
        (
            event
            for event in non_forced
            if 0 <= _seconds_between(trigger, event) <= 2
        ),
        non_forced[0],
    )
    findings = [
        Finding(
            rule_id="c36_cp_state_e_mapping_confirmed",
            severity="high",
            title="C36 maps to connector 1 non-forced CP State E",
            explanation=(
                "The CCU recorded A→E, internal alarm ID 80, a non-forced "
                "State E latch, and connector 1 C36 reporting in the same sequence. "
                "C36 is therefore the CP State E alarm and not the emergency-stop "
                "button code."
            ),
            evidence_event_ids=[
                trigger.id,
                trigger_alarm.id,
                trigger_non_forced.id,
                trigger_c36.id,
            ],
            confidence="high",
            status="confirmed",
            root_cause_category="connector1_cp_state_e",
            affected_domain=Domain.CP,
        )
    ]

    mode = str(case.metadata.get("analysis_mode", "estop_independence"))
    if mode == "estop_independence":
        first_c2 = next(
            (event for event in c2_reports if event.ts_utc > trigger_c36.ts_utc),
            None,
        )
        c36_after_release = (
            next(
                (
                    event
                    for event in c36_reports
                    if first_c2
                    and event.ts_utc > first_c2.ts_utc
                    and "C2" not in event.attrs.get("codes", [])
                ),
                None,
            )
            if first_c2
            else None
        )
        nearest_ac = (
            min(
                ac_samples,
                key=lambda event: abs(_seconds_between(event, trigger)),
            )
            if ac_samples
            else None
        )
        if first_c2 and c36_after_release:
            c36_lead = _seconds_between(trigger_c36, first_c2)
            phases = (
                nearest_ac.attrs.get("phase_voltages_V", [])
                if nearest_ac
                else []
            )
            ac_text = (
                f" R37 phase voltages were approximately "
                f"{min(phases):.1f}-{max(phases):.1f} V, so AC supply was normal."
                if phases
                else ""
            )
            findings.extend(
                [
                    Finding(
                        rule_id="c36_preceded_estop_independent_confirmed",
                        severity="high",
                        title="C36 existed before the emergency-stop event",
                        explanation=(
                            f"C36 was reported {c36_lead:.0f} s before C2 first "
                            f"appeared. The emergency button therefore did not create "
                            f"the original C36 condition.{ac_text}"
                        ),
                        evidence_event_ids=[
                            trigger.id,
                            trigger_c36.id,
                            first_c2.id,
                            *([nearest_ac.id] if nearest_ac else []),
                        ],
                        confidence="high",
                        status="confirmed",
                        root_cause_category="cp_state_e_independent_of_estop",
                        affected_domain=Domain.CP,
                    ),
                    Finding(
                        rule_id="c36_persisted_after_estop_release_confirmed",
                        severity="high",
                        title="Emergency release cleared C2/C37 while C36 remained",
                        explanation=(
                            "The maintenance-code sequence added C2 and C37 during "
                            "the emergency event, then returned to C36 alone. This "
                            "shows independent lifecycles: C2/C37 follow the emergency "
                            "input, while C36 remains latched as long as CP stays in E."
                        ),
                        evidence_event_ids=[
                            first_c2.id,
                            c36_after_release.id,
                            trigger_non_forced.id,
                        ],
                        confidence="high",
                        status="confirmed",
                        root_cause_category="independent_alarm_lifecycles",
                        affected_domain=Domain.CP,
                    ),
                ]
            )
    else:
        cycles: list[tuple[Event, Event, float]] = []
        for reappear in state_e:
            prior = [
                event
                for event in recoveries
                if event.ts_utc < reappear.ts_utc
            ]
            if not prior:
                continue
            gap = _seconds_between(prior[-1], reappear)
            if gap >= 3600:
                cycles.append((prior[-1], reappear, gap))
        if cycles:
            evidence = [
                event.id
                for recovered, reappeared, _ in cycles
                for event in (recovered, reappeared)
            ]
            gaps = ", ".join(f"{gap / 3600:.1f} h" for _, _, gap in cycles)
            findings.append(
                Finding(
                    rule_id="c36_spontaneous_cp_state_lifecycle_confirmed",
                    severity="high",
                    title="C36 cleared and reappeared without emergency-button activity",
                    explanation=(
                        f"The logs contain {len(cycles)} long clear→reappear cycles "
                        f"({gaps}). Each reappearance begins with A→E/alarm 80; no C2 "
                        "event occurs around those transitions. C36 clears only when "
                        "the sampled CP state leaves E and has no independent timeout."
                    ),
                    evidence_event_ids=evidence,
                    confidence="high",
                    status="confirmed",
                    root_cause_category="intermittent_cp_state_e",
                    affected_domain=Domain.CP,
                )
            )
            findings.append(
                Finding(
                    rule_id="connector1_cp_signal_path_fault_probable",
                    severity="high",
                    title="Connector 1 CP-to-PE or sensing path is intermittently entering State E",
                    explanation=(
                        "The repeatable non-forced A→E and recovery behavior localizes "
                        "the issue to the physical CP/PE path or the CCU sampling path. "
                        "The logs cannot distinguish a true CP pull-down, moisture/"
                        "contamination, harness contact, noise, or a false sampled value."
                    ),
                    evidence_event_ids=[
                        trigger.id,
                        trigger_alarm.id,
                        trigger_non_forced.id,
                        *[
                            event.id
                            for recovered, reappeared, _ in cycles
                            for event in (recovered, reappeared)
                        ],
                    ],
                    confidence=case.ground_truth.confidence,
                    status=case.ground_truth.confirmation_status,
                    root_cause_category="cp_pe_or_sensing_path_intermittent",
                    affected_domain=Domain.CP,
                    missing_evidence=list(case.ground_truth.missing_proof),
                    recommended_actions=[
                        "Measure connector 1 CP-to-PE voltage while C36 is active and inactive.",
                        "Use an oscilloscope to capture brief CP dips that a multimeter can miss.",
                        "Inspect the connector, CP/PE harness, terminals, water ingress, dirt, and leakage paths.",
                        "If physical CP remains near 12 V while C36 is active, investigate the CCU sensing and sampling path.",
                    ],
                )
            )
    return findings


def _detect_single_pm_fan_fault(
    case: IncidentCase, events: list[Event]
) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.ts_utc, event.id))
    firmware_transition = next(
        (
            event
            for event in ordered
            if event.attrs.get("category") == "firmware_update"
            and event.attrs.get("old_version")
            and event.attrs.get("new_version")
        ),
        None,
    )
    firmware_success = next(
        (
            event
            for event in ordered
            if event.attrs.get("category") == "firmware_update"
            and event.attrs.get("status") == "success"
            and (
                firmware_transition is None
                or event.ts_utc >= firmware_transition.ts_utc
            )
        ),
        None,
    )
    pm_fault_state = next(
        (
            event
            for event in ordered
            if event.type == EventType.MODULE_STATE
            and event.attrs.get("category") == "power_module_fault"
            and event.attrs.get("state") == "fault"
        ),
        None,
    )
    allocation_zero = next(
        (
            event
            for event in ordered
            if event.attrs.get("measurement") == "cabinet_output_allocation"
            and float(event.attrs.get("to_power_kW", -1)) == 0
            and float(event.attrs.get("from_power_kW", 0)) == 25
        ),
        None,
    )
    no_modules = next(
        (
            event
            for event in ordered
            if event.attrs.get("category") == "power_module_availability"
            and str(event.attrs.get("valid_module_count")) == "0"
        ),
        None,
    )
    evse_limits = [
        event
        for event in ordered
        if event.type == EventType.EV_CURRENT_LIMIT
        and isinstance(event.attrs.get("power_kW"), (int, float))
    ]
    limit_25 = next(
        (
            event
            for event in evse_limits
            if abs(float(event.attrs["power_kW"]) - 25) < 0.1
        ),
        None,
    )
    limit_zero = next(
        (
            event
            for event in evse_limits
            if float(event.attrs["power_kW"]) == 0
            and (pm_fault_state is None or event.ts_utc >= pm_fault_state.ts_utc)
        ),
        None,
    )
    pm_errors = [
        event
        for event in ordered
        if event.type == EventType.ERROR_CODE
        and event.attrs.get("category") == "power_module_fault"
    ]
    required_faults = {
        "Err_PFC1_Fan6Speedabnormal",
        "Err_LLC1_EVT_HARD_PFC_FAULT",
        "Err_LLC1_EVT_PFC_FAULT_FLAG",
    }
    observed_faults = {str(event.attrs.get("fault")) for event in pm_errors}
    normal_stop = next(
        (
            event
            for event in ordered
            if event.type == EventType.NORMAL_STOP
            and pm_fault_state
            and 0 <= _seconds_between(pm_fault_state, event) <= 60
        ),
        None,
    )
    if (
        pm_fault_state is None
        or allocation_zero is None
        or no_modules is None
        or limit_zero is None
        or normal_stop is None
        or not required_faults.issubset(observed_faults)
    ):
        return [
            Finding(
                rule_id="inconclusive",
                severity="high",
                title="PM1 fault-to-stop sequence is incomplete",
                explanation=(
                    "The selected logs do not contain the complete PM1 fault, "
                    "25-to-0 kW allocation, zero valid modules, zero EVSE limit, "
                    "three PM fault names, and session-stop chain."
                ),
                confidence="low",
                status="inconclusive",
                affected_domain=Domain.POWER,
            )
        ]

    feedback = [
        event
        for event in ordered
        if event.type == EventType.POWER_FEEDBACK
        and float(event.attrs.get("power_kW", 0)) > 0
        and 0 <= _seconds_between(event, pm_fault_state) <= 90
    ]
    peak = max(
        feedback, key=lambda event: float(event.attrs["power_kW"])
    ) if feedback else None
    ev_max_samples = [
        event
        for event in ordered
        if event.type == EventType.CURRENT_DEMAND
        and isinstance(event.attrs.get("ev_max_power_kW"), (int, float))
        and 0 <= _seconds_between(event, pm_fault_state) <= 90
    ]
    ev_max_values = sorted(
        {
            round(float(event.attrs["ev_max_power_kW"]))
            for event in ev_max_samples
        }
    )
    stop_delay = _seconds_between(pm_fault_state, normal_stop)

    findings: list[Finding] = []
    if firmware_transition and firmware_success:
        findings.append(
            Finding(
                rule_id="sdsp_update_success_pm_fault_persisted_confirmed",
                severity="medium",
                title="SDSP update succeeded but did not remove the PM1 hardware fault",
                explanation=(
                    f"SDSP was updated from "
                    f"{firmware_transition.attrs['old_version']} to "
                    f"{firmware_transition.attrs['new_version']} and the updater "
                    "reported success. PM1 subsequently entered fault during the "
                    "test session, so backend availability after update did not prove "
                    "the power module was healthy."
                ),
                evidence_event_ids=[
                    firmware_transition.id,
                    firmware_success.id,
                    pm_fault_state.id,
                ],
                confidence="high",
                status="confirmed",
                root_cause_category="firmware_update_not_pm_fault_resolution",
                affected_domain=Domain.SYSTEM,
            )
        )

    if limit_25 and peak:
        ev_values_text = ", ".join(f"{value} kW" for value in ev_max_values)
        findings.append(
            Finding(
                rule_id="charger_25kw_limit_operated_correctly_confirmed",
                severity="medium",
                title="The configured 25 kW charger limit operated correctly",
                explanation=(
                    f"The CCU advertised a 25.0 kW EVSE limit and measured output "
                    f"reached approximately {float(peak.attrs['power_kW']):.1f} kW. "
                    f"The Tesla EV_Max_P_Limit startup sequence contained "
                    f"{ev_values_text}; therefore the temporary 8 kW value came from "
                    "the vehicle's startup ramp, not a charger limit change."
                ),
                evidence_event_ids=[
                    limit_25.id,
                    peak.id,
                    *[event.id for event in ev_max_samples[:6]],
                ],
                confidence="high",
                status="confirmed",
                root_cause_category="configured_power_limit_normal",
                affected_domain=Domain.POWER,
            )
        )

    findings.extend(
        [
            Finding(
                rule_id="pm1_fault_removed_only_power_module_confirmed",
                severity="high",
                title="PM1 fault removed the charger's only available power module",
                explanation=(
                    f"PM1 entered Fault and cabinet allocation switched directly "
                    f"from {float(allocation_zero.attrs['from_power_kW']):.0f} kW "
                    "to 0 kW. ValidMdNum then became 0 and the CCU advertised zero "
                    f"current/power. With one 30 kW module in this 30R, no healthy "
                    f"module remained; charging ended about {stop_delay:.0f} s later "
                    "as EV_Normal_Stop."
                ),
                evidence_event_ids=[
                    pm_fault_state.id,
                    allocation_zero.id,
                    no_modules.id,
                    limit_zero.id,
                    normal_stop.id,
                    *[event.id for event in pm_errors],
                ],
                confidence="high",
                status="confirmed",
                root_cause_category="single_power_module_fault",
                affected_domain=Domain.POWER,
            ),
            Finding(
                rule_id="pm1_fan6_or_feedback_path_fault_probable",
                severity="high",
                title="PM1 Fan 6 or its speed-feedback path is the primary hardware suspect",
                explanation=(
                    "PM1 reported Fan6Speedabnormal together with HARD_PFC_FAULT and "
                    "PFC_FAULT_FLAG. This fault set persisted after the SDSP update "
                    "and directly preceded module loss. The remaining uncertainty is "
                    "whether Fan 6 itself, its supply, speed-feedback wiring, or the "
                    "PM1 sensing/control circuit is defective."
                ),
                evidence_event_ids=[event.id for event in pm_errors],
                confidence=case.ground_truth.confidence,
                status=case.ground_truth.confirmation_status,
                root_cause_category="pm1_fan6_speed_feedback_fault",
                affected_domain=Domain.POWER,
                missing_evidence=list(case.ground_truth.missing_proof),
                recommended_actions=[
                    "Inspect PM1 Fan 6 for obstruction and verify fan supply voltage.",
                    "Check Fan 6 speed-feedback wiring, connector seating, and tachometer signal.",
                    "A/B test with a known-good fan where permitted.",
                    "Replace Fan 6 or PM1 according to the isolation result, then run a sustained 25 kW load test.",
                ],
            ),
        ]
    )
    return findings


INCIDENT_DETECTORS = {
    "network_manager_ownership_conflict": _detect_network_manager_conflict,
    "ev_estop_at_max_current": _detect_ev_estop_at_max_current,
    "s20_state_lifecycle": _detect_s20_state_lifecycle,
    "maintenance_backend_disconnect": _detect_maintenance_backend_disconnect,
    "customer_sim_path_failure": _detect_customer_sim_path_failure,
    "fognode_operation_path_failure": _detect_fognode_operation_path_failure,
    "ev_invalid_target_voltage": _detect_ev_invalid_target_voltage,
    "bmw_i3_module_switch_dip": _detect_bmw_i3_module_switch_dip,
    "lem2_internal_ethernet_fault": _detect_lem2_internal_ethernet_fault,
    "lem2_http_service_hang": _detect_lem2_http_service_hang,
    "dual_terminal_l20_recovery": _detect_dual_terminal_l20_recovery,
    "plug_and_play_idtag_rejected": _detect_plug_and_play_idtag_rejected,
    "precharge_residual_voltage": _detect_precharge_residual_voltage,
    "current_demand_overvoltage_unresolved": _detect_current_demand_overvoltage_unresolved,
    "ems_low_power_taper": _detect_ems_low_power_taper,
    "s25_dynamic_ramp_tracking": _detect_s25_dynamic_ramp_tracking,
    "initial_precharge_zero_voltage": _detect_initial_precharge_zero_voltage,
    "c36_cp_state_e_lifecycle": _detect_c36_cp_state_e_lifecycle,
    "single_pm_fan_fault": _detect_single_pm_fan_fault,
}


def detect_incident(case: IncidentCase, events: list[Event]) -> list[Finding]:
    detector = INCIDENT_DETECTORS.get(case.detector)
    if detector:
        result = detector(case, events)
        return result if isinstance(result, list) else [result]
    return [
        Finding(
            rule_id="inconclusive",
            severity="info",
            title="No incident detector registered",
            explanation=f"No detector is registered for '{case.detector}'.",
            confidence="low",
            status="inconclusive",
            affected_domain=Domain.UNKNOWN,
            missing_evidence=["case-specific detector"],
        )
    ]
