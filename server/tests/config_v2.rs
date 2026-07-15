use unissh_server::Config;

#[test]
fn v2_config_defaults() {
    let c = Config::load(None).unwrap();
    assert_eq!(c.setup.code, "");
    assert!(!c.oidc.enabled);
    assert_eq!(c.oidc.issuer, "");
    assert_eq!(c.server.public_url, "");
}
