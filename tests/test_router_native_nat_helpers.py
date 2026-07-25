from router_native_features_patch import _nat_result_with_request, _nat_terminal


def test_rfc5780_behavior_pair_is_terminal_without_legacy_nat_type():
    payload = {
        "status": "running",
        "mappingBehavior": "Endpoint Independent",
        "filteringBehavior": "Addr & Port Dependent",
        "mappedAddress": "36.157.252.33:23884",
    }
    normalized = _nat_result_with_request(
        payload,
        {"host": "stun.hot-chilli.net", "port": 3478, "interface": "wan", "mode": "5780"},
    )
    assert normalized["status"] == "completed"
    assert normalized["mapping_behavior"] == "Endpoint Independent"
    assert normalized["filtering_behavior"] == "Addr & Port Dependent"
    assert normalized["external_address"] == "36.157.252.33:23884"
    assert normalized["requested_mode"] == "5780"
    assert _nat_terminal(normalized)


def test_rfc3489_nat_type_remains_terminal():
    payload = {"status": "running", "nat_type": "Port Restricted Cone NAT"}
    assert _nat_terminal(payload)


def test_partial_rfc5780_result_keeps_running():
    payload = {"status": "running", "mapping_behavior": "Endpoint Independent"}
    assert not _nat_terminal(payload)
