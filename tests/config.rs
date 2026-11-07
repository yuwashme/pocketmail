//! Env-only configuration (src/config.rs). Uses `Config::from_vars`, never the process env.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use synology_mail_server::config::{Config, ConfigError};

fn cfg(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
    Config::from_vars(vars.iter().map(|(k, v)| (k.to_string(), v.to_string())))
}

fn base(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut v = vec![("SSM_DATA_DIR", "/volume1/ssm")];
    v.extend_from_slice(extra);
    v
}

fn assert_missing(r: Result<Config, ConfigError>, var: &str) {
    match r {
        Err(ConfigError::Missing(v)) => assert_eq!(v, var),
        Err(other) => panic!("expected Missing({var}), got {other:?}"),
        Ok(_) => panic!("expected Missing({var}), got Ok"),
    }
}

fn assert_invalid(r: Result<Config, ConfigError>, var: &str) {
    match r {
        Err(ConfigError::Invalid { var: v, .. }) => assert_eq!(v, var),
        Err(other) => panic!("expected Invalid({var}), got {other:?}"),
        Ok(_) => panic!("expected Invalid({var}), got Ok"),
    }
}

#[test]
fn data_dir_is_required() {
    assert_missing(cfg(&[]), "SSM_DATA_DIR");
    assert_missing(
        cfg(&[("PATH", "/usr/bin"), ("HOME", "/root")]),
        "SSM_DATA_DIR",
    );
}

#[test]
fn empty_data_dir_counts_as_missing() {
    assert_missing(cfg(&[("SSM_DATA_DIR", "")]), "SSM_DATA_DIR");
}

#[test]
fn defaults_with_only_the_data_dir() {
    let c = cfg(&base(&[])).unwrap();
    assert_eq!(c.data_dir, PathBuf::from("/volume1/ssm"));
    assert_eq!(c.pull_url, None);
    assert_eq!(c.pull_token_file, None);
    assert_eq!(c.pull_interval, Duration::from_secs(120));
    assert_eq!(c.imap_listen, "0.0.0.0:9993".parse::<SocketAddr>().unwrap());
    assert_eq!(c.imap_max_conn, 100);
    assert_eq!(c.tls_cert, None);
    assert_eq!(c.tls_key, None);
}

#[test]
fn unrelated_variables_are_ignored() {
    let c = cfg(&base(&[
        ("PATH", "/bin"),
        ("SSM_UNRELATED_X", "1"),
        ("LANG", "sl_SI.UTF-8"),
    ]))
    .unwrap();
    assert_eq!(c.data_dir, PathBuf::from("/volume1/ssm"));
}

#[test]
fn pull_interval_minimum_is_120_seconds() {
    // KV free tier: 1,000 lists/day; 120 s = 720 lists/day.
    assert_eq!(
        cfg(&base(&[("SSM_PULL_INTERVAL_SECS", "120")]))
            .unwrap()
            .pull_interval,
        Duration::from_secs(120)
    );
    assert_eq!(
        cfg(&base(&[("SSM_PULL_INTERVAL_SECS", "600")]))
            .unwrap()
            .pull_interval,
        Duration::from_secs(600)
    );
    assert_invalid(
        cfg(&base(&[("SSM_PULL_INTERVAL_SECS", "119")])),
        "SSM_PULL_INTERVAL_SECS",
    );
    assert_invalid(
        cfg(&base(&[("SSM_PULL_INTERVAL_SECS", "30")])),
        "SSM_PULL_INTERVAL_SECS",
    );
    assert_invalid(
        cfg(&base(&[("SSM_PULL_INTERVAL_SECS", "0")])),
        "SSM_PULL_INTERVAL_SECS",
    );
}

#[test]
fn pull_interval_must_be_a_number() {
    for bad in ["abc", "-5", "120s", "1.5e3"] {
        assert_invalid(
            cfg(&base(&[("SSM_PULL_INTERVAL_SECS", bad)])),
            "SSM_PULL_INTERVAL_SECS",
        );
    }
}

#[test]
fn empty_optional_values_mean_default() {
    let c = cfg(&base(&[
        ("SSM_PULL_INTERVAL_SECS", ""),
        ("SSM_PULL_URL", ""),
        ("SSM_IMAP_LISTEN", ""),
    ]))
    .unwrap();
    assert_eq!(c.pull_interval, Duration::from_secs(120));
    assert_eq!(c.pull_url, None);
    assert_eq!(c.imap_listen, "0.0.0.0:9993".parse::<SocketAddr>().unwrap());
}

#[test]
fn pull_url_and_token_file_are_read() {
    let c = cfg(&base(&[
        ("SSM_PULL_URL", "https://ssm-inbound.example.workers.dev"),
        ("SSM_PULL_TOKEN_FILE", "/var/packages/ssm/var/pull_token"),
    ]))
    .unwrap();
    assert_eq!(
        c.pull_url.as_deref(),
        Some("https://ssm-inbound.example.workers.dev")
    );
    assert_eq!(
        c.pull_token_file,
        Some(PathBuf::from("/var/packages/ssm/var/pull_token"))
    );
}

#[test]
fn pull_url_needs_a_token_file() {
    assert_missing(
        cfg(&base(&[(
            "SSM_PULL_URL",
            "https://ssm-inbound.example.workers.dev",
        )])),
        "SSM_PULL_TOKEN_FILE",
    );
}

#[test]
fn pull_url_must_be_https_so_the_token_never_goes_out_in_clear() {
    for bad in [
        "http://ssm-inbound.example.workers.dev",
        "ssm-inbound.example.workers.dev",
        "ftp://x",
    ] {
        assert_invalid(
            cfg(&base(&[
                ("SSM_PULL_URL", bad),
                ("SSM_PULL_TOKEN_FILE", "/t"),
            ])),
            "SSM_PULL_URL",
        );
    }
}

#[test]
fn imap_listen_and_max_conn_are_parsed_and_validated() {
    let c = cfg(&base(&[
        ("SSM_IMAP_LISTEN", "127.0.0.1:1993"),
        ("SSM_IMAP_MAX_CONN", "250"),
    ]))
    .unwrap();
    assert_eq!(
        c.imap_listen,
        "127.0.0.1:1993".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(c.imap_max_conn, 250);
    assert_eq!(
        cfg(&base(&[("SSM_IMAP_LISTEN", "[::]:9993")]))
            .unwrap()
            .imap_listen,
        "[::]:9993".parse::<SocketAddr>().unwrap()
    );
    assert_invalid(
        cfg(&base(&[("SSM_IMAP_LISTEN", "nonsense")])),
        "SSM_IMAP_LISTEN",
    );
    assert_invalid(
        cfg(&base(&[("SSM_IMAP_LISTEN", "0.0.0.0")])),
        "SSM_IMAP_LISTEN",
    );
    assert_invalid(
        cfg(&base(&[("SSM_IMAP_MAX_CONN", "0")])),
        "SSM_IMAP_MAX_CONN",
    );
    assert_invalid(
        cfg(&base(&[("SSM_IMAP_MAX_CONN", "many")])),
        "SSM_IMAP_MAX_CONN",
    );
}

#[test]
fn tls_cert_and_key_come_together() {
    let c = cfg(&base(&[
        ("SSM_TLS_CERT", "/c.pem"),
        ("SSM_TLS_KEY", "/k.pem"),
    ]))
    .unwrap();
    assert_eq!(c.tls_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(c.tls_key, Some(PathBuf::from("/k.pem")));
    assert_invalid(cfg(&base(&[("SSM_TLS_CERT", "/c.pem")])), "SSM_TLS_KEY");
    assert_invalid(cfg(&base(&[("SSM_TLS_KEY", "/k.pem")])), "SSM_TLS_CERT");
}

#[test]
fn web_listen_default_and_off() {
    let default = Some("0.0.0.0:8443".parse::<SocketAddr>().unwrap());
    assert_eq!(cfg(&base(&[])).unwrap().web_listen, default);
    assert_eq!(
        cfg(&base(&[("SSM_WEB_LISTEN", "")])).unwrap().web_listen,
        default
    );
    assert_eq!(
        cfg(&base(&[("SSM_WEB_LISTEN", "127.0.0.1:18443")]))
            .unwrap()
            .web_listen,
        Some("127.0.0.1:18443".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(
        cfg(&base(&[("SSM_WEB_LISTEN", "[::]:8443")]))
            .unwrap()
            .web_listen,
        Some("[::]:8443".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(
        cfg(&base(&[("SSM_WEB_LISTEN", "off")])).unwrap().web_listen,
        None
    );
    for bad in ["nonsense", "8443", "0.0.0.0", "no"] {
        assert_invalid(cfg(&base(&[("SSM_WEB_LISTEN", bad)])), "SSM_WEB_LISTEN");
    }
}

#[test]
fn web_allow_public_yes_no_only() {
    assert!(
        !cfg(&base(&[])).unwrap().web_allow_public,
        "home network only by default"
    );
    assert!(
        !cfg(&base(&[("SSM_WEB_ALLOW_PUBLIC", "")]))
            .unwrap()
            .web_allow_public
    );
    assert!(
        cfg(&base(&[("SSM_WEB_ALLOW_PUBLIC", "yes")]))
            .unwrap()
            .web_allow_public
    );
    assert!(
        !cfg(&base(&[("SSM_WEB_ALLOW_PUBLIC", "no")]))
            .unwrap()
            .web_allow_public
    );
    for bad in ["true", "1", "on", "y", "yes please"] {
        assert_invalid(
            cfg(&base(&[("SSM_WEB_ALLOW_PUBLIC", bad)])),
            "SSM_WEB_ALLOW_PUBLIC",
        );
    }
}
