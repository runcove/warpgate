//! Which hostnames a web (HTTP) target may be bound to with `external_host`.
//!
//! A bound hostname serves exactly one target. It may not be Warpgate's own
//! control-plane host, at any port, and no two targets may share it, whatever
//! their ports: browsers scope cookies by hostname, not by port, so two
//! bindings on one hostname (or one on Warpgate's own) share cookies with each
//! other. Hostnames are compared ASCII case-insensitively.
//!
//! The admin API refuses such a binding when it is written, and the HTTP
//! proxy refuses to serve one that is already stored.

use poem::http::uri::Authority;

/// The hostname of an `external_host` binding (or a Host header), without
/// its port. An IPv6 literal keeps its brackets. A value that is not an
/// authority is taken whole.
pub fn binding_hostname(external_host: &str) -> &str {
    let value = external_host.trim();
    match value.parse::<Authority>() {
        // With a port, the last `:` starts it (an IPv6 literal is bracketed).
        Ok(authority) if authority.port().is_some() => {
            value.rsplit_once(':').map_or(value, |(host, _)| host)
        }
        _ => value,
    }
}

/// Whether two `external_host` values (or a binding and a host) name the same
/// hostname, ignoring ports, ASCII case and one trailing dot (the fully
/// qualified `warp.example.com.` is the same host as `warp.example.com`).
pub fn same_binding_hostname(a: &str, b: &str) -> bool {
    fn comparable(value: &str) -> &str {
        let hostname = binding_hostname(value);
        hostname.strip_suffix('.').unwrap_or(hostname)
    }
    comparable(a).eq_ignore_ascii_case(comparable(b))
}

/// Why a web target may not be bound to a hostname.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostBindingConflict {
    #[error("`{hostname}` is Warpgate's own host; a target cannot be bound to it, at any port")]
    ControlPlane { hostname: String },
    #[error(
        "the hostname `{hostname}` is already bound to target `{other}`; a hostname can be bound to one target only, whatever the port"
    )]
    Shared { hostname: String, other: String },
}

/// Whether binding a web target to `external_host` conflicts with Warpgate's
/// own host (`control_plane_host`, a bare hostname) or with another target's
/// binding. `others` are `(name, external_host)` of every OTHER web target
/// that has a binding; the caller leaves the target itself out.
pub fn host_binding_conflict<'a>(
    external_host: &str,
    control_plane_host: Option<&str>,
    others: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<HostBindingConflict> {
    let hostname = binding_hostname(external_host);
    if control_plane_host.is_some_and(|own| same_binding_hostname(own, hostname)) {
        return Some(HostBindingConflict::ControlPlane {
            hostname: hostname.to_owned(),
        });
    }
    others
        .into_iter()
        .find(|(_, other)| same_binding_hostname(other, hostname))
        .map(|(other, _)| HostBindingConflict::Shared {
            hostname: hostname.to_owned(),
            other: other.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_drops_only_the_port() {
        for (value, hostname) in [
            ("vm.example.com", "vm.example.com"),
            ("vm.example.com:8443", "vm.example.com"),
            ("VM.Example.com:80", "VM.Example.com"),
            ("[::1]:8080", "[::1]"),
            ("[::1]", "[::1]"),
            ("127.0.0.1:3000", "127.0.0.1"),
            (" vm.example.com ", "vm.example.com"),
            ("not a host", "not a host"),
        ] {
            assert_eq!(binding_hostname(value), hostname, "{value}");
        }
    }

    #[test]
    fn control_plane_host_is_refused_at_any_port_and_case() {
        for binding in [
            "warp.example.com",
            "warp.example.com:8443",
            "WARP.example.COM:443",
        ] {
            assert_eq!(
                host_binding_conflict(binding, Some("warp.example.com"), []),
                Some(HostBindingConflict::ControlPlane {
                    hostname: binding_hostname(binding).to_owned()
                }),
                "{binding}"
            );
        }
        assert_eq!(
            host_binding_conflict("vm.warp.example.com", Some("warp.example.com"), []),
            None
        );
        assert_eq!(host_binding_conflict("warp.example.com", None, []), None);
    }

    #[test]
    fn one_trailing_dot_names_the_same_hostname() {
        for (a, b) in [
            ("warp.example.com.", "warp.example.com"),
            ("warp.example.com", "WARP.example.com.:8443"),
            ("warp.example.com.:443", "warp.example.com:80"),
        ] {
            assert!(same_binding_hostname(a, b), "{a} {b}");
            assert!(same_binding_hostname(b, a), "{b} {a}");
        }
        // Only one dot is dropped.
        assert!(!same_binding_hostname(
            "warp.example.com..",
            "warp.example.com"
        ));
        assert_eq!(
            host_binding_conflict("warp.example.com.", Some("warp.example.com"), []),
            Some(HostBindingConflict::ControlPlane {
                hostname: "warp.example.com.".into()
            })
        );
        assert_eq!(
            host_binding_conflict("warp.example.com", Some("warp.example.com."), []),
            Some(HostBindingConflict::ControlPlane {
                hostname: "warp.example.com".into()
            })
        );
        assert_eq!(
            host_binding_conflict("vm.example.com.:3000", None, [("vm", "vm.example.com")]),
            Some(HostBindingConflict::Shared {
                hostname: "vm.example.com.".into(),
                other: "vm".into(),
            })
        );
    }

    #[test]
    fn a_hostname_serves_one_target_whatever_the_port() {
        let others = [
            ("vm-1", "vm-1.example.com:3000"),
            ("vm-2", "vm-2.example.com"),
        ];
        for binding in [
            "vm-1.example.com:3000",
            "vm-1.example.com:8080",
            "vm-1.example.com",
            "VM-1.EXAMPLE.COM:3000",
        ] {
            assert_eq!(
                host_binding_conflict(binding, None, others),
                Some(HostBindingConflict::Shared {
                    hostname: binding_hostname(binding).to_owned(),
                    other: "vm-1".into(),
                }),
                "{binding}"
            );
        }
        assert_eq!(
            host_binding_conflict("vm-3.example.com:3000", None, others),
            None
        );
        assert_eq!(
            host_binding_conflict("vm-1.example.org", None, others),
            None
        );
    }
}
