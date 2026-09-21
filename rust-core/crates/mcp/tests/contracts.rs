use serde_json::{json, Value};
use unissh_mcp::contract::{parse, tools, InvalidRequest, RunCommand, ToolRequest};

fn request(args: Value) -> Result<ToolRequest, InvalidRequest> {
    parse("run_command", args.as_object().unwrap().clone())
}

#[test]
fn run_modes_are_explicit_and_disjoint() {
    assert!(matches!(
        request(json!({"session_id":"s", "command":"pwd", "request_key":"k"})),
        Ok(ToolRequest::RunCommand(RunCommand::Existing(_)))
    ));
    assert!(matches!(
        request(json!({"session_id":null, "target_id":"t", "command":"pwd", "request_key":"k"})),
        Ok(ToolRequest::RunCommand(RunCommand::OneShot(_)))
    ));
    for args in [
        json!({"target_id":"t", "command":"pwd", "request_key":"k"}),
        json!({"session_id":null, "command":"pwd", "request_key":"k"}),
        json!({"session_id":"s", "target_id":"t", "command":"pwd", "request_key":"k"}),
        json!({"session_id":12, "command":"pwd", "request_key":"k"}),
        json!({"session_id":"", "command":"pwd", "request_key":"k"}),
        json!({"session_id":"s", "command":"pwd"}),
    ] {
        assert!(
            matches!(request(args.clone()), Err(InvalidRequest::InvalidArguments)),
            "accepted {args}"
        );
    }
}

#[test]
fn runtime_rejects_credentials_identity_overrides_and_invalid_limits() {
    for field in [
        "password",
        "private_key",
        "hostname",
        "username",
        "integration_id",
        "grant_id",
        "env",
        "cwd",
    ] {
        let mut args = json!({"session_id":"s", "command":"pwd", "request_key":"k"});
        args[field] = json!("should-never-be-accepted");
        assert!(request(args).is_err(), "accepted {field}");
    }
    assert!(
        request(json!({"session_id":"s","command":"x".repeat(32769),"request_key":"k"})).is_err()
    );
    assert!(
        request(json!({"session_id":"s","command":"true","request_key":"x".repeat(129)})).is_err()
    );
    assert!(request(json!({"session_id":"s","command":"true\0false","request_key":"k"})).is_err());
    for timeout in [json!(0), json!(600001), json!(-1), json!(1.5), json!("1")] {
        assert!(request(
            json!({"session_id":"s", "command":"pwd", "request_key":"k", "timeout_ms":timeout})
        )
        .is_err());
    }
    assert!(parse(
        "get_command",
        json!({"run_id":"r", "wait_ms":30001})
            .as_object()
            .unwrap()
            .clone()
    )
    .is_err());
    assert!(matches!(
        parse("reveal_password", Default::default()),
        Err(InvalidRequest::UnknownTool)
    ));
}

#[test]
fn discovery_describes_only_the_supported_tools() {
    let tools = tools();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(
        names,
        [
            "list_targets",
            "open_ssh_session",
            "list_ssh_sessions",
            "close_ssh_session",
            "run_command",
            "get_command",
            "cancel_command"
        ]
    );
    let schema = serde_json::to_value(&tools[4].input_schema).unwrap();
    assert_eq!(schema["type"], "object");
    for variant in ["ExistingSessionCommand", "OneShotCommand"] {
        let definition = &schema["$defs"][variant];
        assert_eq!(definition["additionalProperties"], false);
        assert!(definition["required"]
            .as_array()
            .unwrap()
            .contains(&json!("session_id")));
    }
    assert_eq!(
        schema["$defs"]["OneShotCommand"]["properties"]["session_id"]["type"],
        "null"
    );
}
