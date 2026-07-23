use std::env;
use std::fs;
use std::path::PathBuf;

fn replace_once(source: &mut String, old: &str, new: &str, label: &str) {
    if source.contains(new) {
        return;
    }
    if !source.contains(old) {
        panic!("LabRelay low-traffic patch pattern missing: {label}");
    }
    *source = source.replacen(old, new, 1);
}

fn main() {
    // Existing installations are built from the long-lived agent.rs source. Keep
    // this narrowly scoped transformation automatic and idempotent so every
    // local/CI/cross build gets the same direct-Hub traffic policy.
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let agent_path = manifest.join("src/agent.rs");
    let mut source = fs::read_to_string(&agent_path).expect("read src/agent.rs");

    if !source.contains("pub hub_direct_mode: bool") {
        replace_once(
            &mut source,
            "    pub router_name: String,\n    pub interval_seconds: u64,",
            "    pub router_name: String,\n    /// Hub owns WSS/dashboard/devices; Relay only supplements IPv6 and 6to6.\n    pub hub_direct_mode: bool,\n    pub interval_seconds: u64,",
            "AgentConfig hub_direct_mode",
        );
        replace_once(
            &mut source,
            "            router_name: \"router\".into(),\n            interval_seconds: 15,",
            "            router_name: \"router\".into(),\n            hub_direct_mode: true,\n            interval_seconds: 15,",
            "AgentConfig default direct mode",
        );
        replace_once(
            &mut source,
            "    last_credentials_refresh_nonce: u64,\n}",
            "    last_credentials_refresh_nonce: u64,\n    last_status_report_at: u64,\n    last_snapshot_signature: String,\n    last_snapshot_push_at: u64,\n    last_portmap_status_push_at: u64,\n}",
            "AgentState low-traffic fields",
        );

        replace_once(
            &mut source,
            "fn now_epoch() -> u64 {\n    SystemTime::now()\n        .duration_since(UNIX_EPOCH)\n        .unwrap_or_default()\n        .as_secs()\n}\n",
            "fn now_epoch() -> u64 {\n    SystemTime::now()\n        .duration_since(UNIX_EPOCH)\n        .unwrap_or_default()\n        .as_secs()\n}\n\nfn snapshot_signature(value: &Value) -> String {\n    let mut stable = value.clone();\n    if let Value::Object(root) = &mut stable {\n        root.remove(\"ts\");\n        if let Some(Value::Array(neighbors)) = root.get_mut(\"ipv6_neighbors\") {\n            for neighbor in neighbors {\n                if let Value::Object(row) = neighbor {\n                    // REACHABLE/STALE changes constantly and is not an address change.\n                    row.remove(\"state\");\n                }\n            }\n        }\n    }\n    serde_json::to_string(&stable).unwrap_or_default()\n}\n",
            "stable IPv6 snapshot signature",
        );

        replace_once(
            &mut source,
            "async fn get_json(client: &Client, config: &AgentConfig, path: &str) -> Result<Value> {\n    let url = format!(\"{}{}\", config.hub_url.trim_end_matches('/'), path);\n    let response = client\n        .get(url)\n        .header(\"X-LabProbe-Token\", &config.hook_token)\n        .send()",
            "async fn get_json(client: &Client, config: &AgentConfig, path: &str) -> Result<Value> {\n    let url = format!(\"{}{}\", config.hub_url.trim_end_matches('/'), path);\n    let request_timeout = if path.contains(\"/api/router/agent/commands\") && path.contains(\"wait=55\") {\n        Duration::from_secs(70)\n    } else {\n        Duration::from_secs(12)\n    };\n    let response = client\n        .get(url)\n        .header(\"X-LabProbe-Token\", &config.hook_token)\n        .timeout(request_timeout)\n        .send()",
            "long-poll request timeout",
        );

        replace_once(
            &mut source,
            "async fn sync_agent_update(client: &Client, config: &AgentConfig, state: &mut AgentState) -> Result<bool> {\n    let router = url_encode(&config.router_name);\n    let root = get_json(\n        client,\n        config,\n        &format!(\"/api/router/agent/commands?router={}\", router),\n    )\n    .await?;\n    let commands = root",
            "async fn sync_agent_update(client: &Client, config: &AgentConfig, state: &mut AgentState) -> Result<bool> {\n    let router = url_encode(&config.router_name);\n    let root = get_json(\n        client,\n        config,\n        &format!(\n            \"/api/router/agent/commands?router={}&credentialsSince={}&wait=55\",\n            router,\n            state.last_credentials_refresh_nonce\n        ),\n    )\n    .await?;\n    let credentials_requested = root\n        .get(\"credentialsRefreshNonce\")\n        .and_then(Value::as_u64)\n        .unwrap_or(0);\n    let credentials_completed = root\n        .get(\"credentialsCompletedNonce\")\n        .and_then(Value::as_u64)\n        .unwrap_or(0);\n    if credentials_completed >= credentials_requested\n        && credentials_completed > state.last_credentials_refresh_nonce\n    {\n        state.last_credentials_refresh_nonce = credentials_completed;\n    } else if credentials_requested > state.last_credentials_refresh_nonce {\n        sync_router_credentials(client, config, state, credentials_requested).await?;\n    }\n    let commands = root",
            "credential-aware long poll",
        );

        replace_once(
            &mut source,
            "    let wan_scope = network.get(\"wan\").unwrap_or(&network);\n    let lan_scope = network.get(\"lan\").unwrap_or(&network);",
            "    // Firmware variants place PPPoE fields under wan arrays, profiles or\n    // nested service objects. The recursive helper must inspect the full tree.\n    let wan_scope = &network;\n    let lan_scope = &network;",
            "router-local credential tree scope",
        );
        replace_once(
            &mut source,
            "&[\"username\", \"userName\", \"user_name\", \"account\", \"pppoeUser\", \"pppoe_username\", \"pppoe_account\", \"broadbandAccount\", \"user\"],",
            "&[\"username\", \"userName\", \"user_name\", \"account\", \"accountName\", \"pppoeUser\", \"pppoe_username\", \"pppoe_account\", \"broadbandAccount\", \"broadbandUser\", \"user\"],",
            "router-local username keys",
        );
        replace_once(
            &mut source,
            "&[\"password\", \"passwd\", \"pwd\", \"pppoePassword\", \"pppoe_password\", \"pppoe_passwd\", \"broadbandPassword\"],",
            "&[\"password\", \"passwd\", \"pwd\", \"passWord\", \"pppoePassword\", \"pppoe_password\", \"pppoe_passwd\", \"broadbandPassword\", \"broadbandPasswd\"],",
            "router-local password keys",
        );

        replace_once(
            &mut source,
            "    let commands = root\n        .get(\"commands\")\n        .and_then(Value::as_array)\n        .cloned()\n        .unwrap_or_default();\n    if !commands.is_empty() {\n        let mut acks = Vec::new();",
            "    let commands = root\n        .get(\"commands\")\n        .and_then(Value::as_array)\n        .cloned()\n        .unwrap_or_default();\n    let had_commands = !commands.is_empty();\n    if had_commands {\n        let mut acks = Vec::new();",
            "portmap command marker",
        );
        replace_once(
            &mut source,
            "    if Path::new(&config.relay_socket).exists() {\n        let relay = ctl_request(Path::new(&config.relay_socket), &json!({\"action\":\"status\"}))?;\n        post_json(\n            client,\n            config,\n            &format!(\"/api/router/portmaps/status?router={}\", router),\n            &relay,\n        )\n        .await?;\n    }",
            "    let status_due = had_commands\n        || state.last_portmap_status_push_at == 0\n        || now_epoch().saturating_sub(state.last_portmap_status_push_at) >= 300;\n    if Path::new(&config.relay_socket).exists() && status_due {\n        let relay = ctl_request(Path::new(&config.relay_socket), &json!({\"action\":\"status\"}))?;\n        post_json(\n            client,\n            config,\n            &format!(\"/api/router/portmaps/status?router={}\", router),\n            &relay,\n        )\n        .await?;\n        state.last_portmap_status_push_at = now_epoch();\n    }",
            "low-frequency portmap status",
        );

        replace_once(
            &mut source,
            "async fn agent_cycle(client: &Client, config: &AgentConfig, state: &mut AgentState) -> Result<()> {\n    if let Err(error) = report_agent_status(client, config, state).await {\n        log_limited(config, state, \"WARN\", \"agent-status\", &format!(\"agent status report skipped: {:#}\", error));\n    }\n    match sync_agent_update(client, config, state).await {\n        Ok(true) => return Ok(()),\n        Ok(false) => {}\n        Err(error) => log_limited(config, state, \"WARN\", \"agent-update-check\", &format!(\"agent update check skipped: {:#}\", error)),\n    }\n    let user_list = collect_user_list()?;\n    let mut current = BTreeMap::new();\n    find_devices(&user_list, &mut current);\n    queue_device_events(state, &current);\n    post_json(client, config, \"/hook/ruijie/devices\", &user_list).await?;\n    flush_device_events(client, config, state).await;\n    post_json(client, config, \"/api/router/push\", &router_snapshot(config)).await?;\n    sync_portmaps(client, config, state).await?;\n    state.last_success_at = now_epoch();\n    state.update_state = \"idle\".into();\n    state.update_message.clear();\n    Ok(())\n}",
            "async fn agent_cycle(client: &Client, config: &AgentConfig, state: &mut AgentState) -> Result<()> {\n    let now = now_epoch();\n    if state.last_status_report_at == 0 || now.saturating_sub(state.last_status_report_at) >= 300 {\n        if let Err(error) = report_agent_status(client, config, state).await {\n            log_limited(config, state, \"WARN\", \"agent-status\", &format!(\"agent status report skipped: {:#}\", error));\n        } else {\n            state.last_status_report_at = now;\n        }\n    }\n    match sync_agent_update(client, config, state).await {\n        Ok(true) => return Ok(()),\n        Ok(false) => {}\n        Err(error) => log_limited(config, state, \"WARN\", \"agent-update-check\", &format!(\"agent update check skipped: {:#}\", error)),\n    }\n\n    if !config.hub_direct_mode {\n        let user_list = collect_user_list()?;\n        let mut current = BTreeMap::new();\n        find_devices(&user_list, &mut current);\n        queue_device_events(state, &current);\n        post_json(client, config, \"/hook/ruijie/devices\", &user_list).await?;\n        flush_device_events(client, config, state).await;\n    }\n\n    let snapshot = router_snapshot(config);\n    let signature = snapshot_signature(&snapshot);\n    let snapshot_due = !config.hub_direct_mode\n        || signature != state.last_snapshot_signature\n        || state.last_snapshot_push_at == 0\n        || now.saturating_sub(state.last_snapshot_push_at) >= 900;\n    if snapshot_due {\n        post_json(client, config, \"/api/router/push\", &snapshot).await?;\n        state.last_snapshot_signature = signature;\n        state.last_snapshot_push_at = now;\n    }\n\n    sync_portmaps(client, config, state).await?;\n    state.last_success_at = now_epoch();\n    state.update_state = \"idle\".into();\n    state.update_message.clear();\n    Ok(())\n}",
            "direct-Hub agent cycle",
        );

        replace_once(
            &mut source,
            "        let mut errors = Vec::new();\n        if once || last_agent_cycle_at == 0 || now.saturating_sub(last_agent_cycle_at) >= config.interval_seconds.clamp(5, 300) {",
            "        let mut errors = Vec::new();\n        let cycle_interval = if config.hub_direct_mode {\n            config.interval_seconds.clamp(60, 300)\n        } else {\n            config.interval_seconds.clamp(5, 300)\n        };\n        if once || last_agent_cycle_at == 0 || now.saturating_sub(last_agent_cycle_at) >= cycle_interval {",
            "direct-Hub cycle interval",
        );
        replace_once(
            &mut source,
            "        if dashboard_due {\n            if let Err(error) = sync_router_dashboard(&client, &config, &mut state, once).await {",
            "        if !config.hub_direct_mode && dashboard_due {\n            if let Err(error) = sync_router_dashboard(&client, &config, &mut state, once).await {",
            "disable Relay dashboard in direct mode",
        );

        fs::write(&agent_path, source).expect("write patched src/agent.rs");
    }

    // Avoid a second hard-coded runtime version that can drift from Cargo.toml.
    let main_path = manifest.join("src/main.rs");
    let mut main_source = fs::read_to_string(&main_path).expect("read src/main.rs");
    replace_once(
        &mut main_source,
        "const VERSION: &str = \"0.2.4\";",
        "const VERSION: &str = env!(\"CARGO_PKG_VERSION\");",
        "runtime package version",
    );
    fs::write(&main_path, main_source).expect("write patched src/main.rs");
}
