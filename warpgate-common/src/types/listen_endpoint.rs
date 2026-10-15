use std::fmt::Debug;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use futures::stream::{FuturesUnordered, iter};
use futures::{Stream, StreamExt, TryStreamExt};
use poem::listener::Listener;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::warn;

use crate::WarpgateError;

#[derive(Clone, PartialEq, Eq, JsonSchema)]
pub struct ListenEndpoint(SocketAddr);

impl ListenEndpoint {
    pub const fn address(&self) -> SocketAddr {
        self.0
    }

    pub fn addresses_to_listen_on(&self) -> Result<Vec<SocketAddr>, WarpgateError> {
        // For [::], explicitly return both addresses so that we are not affected
        // by the state of the ipv6only sysctl.
        if self.0.ip() == Ipv6Addr::UNSPECIFIED {
            let addr6 = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), self.0.port());
            let addr4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.0.port());
            let listener6 = std::net::TcpListener::bind(addr6)?;
            let listener4 = std::net::TcpListener::bind(addr4);
            let result = match listener4 {
                Ok(_) => vec![addr4, addr6],
                Err(e) if e.kind() == ErrorKind::AddrInUse => vec![addr6],
                Err(e) => return Err(WarpgateError::Io(e)),
            };
            drop(listener6);
            Ok(result)
        } else {
            Ok(vec![self.0])
        }
    }

    pub async fn tcp_listeners(&self) -> Result<Vec<TcpListener>, WarpgateError> {
        Ok(self
            .addresses_to_listen_on()?
            .into_iter()
            .map(TcpListener::bind)
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await?)
    }

    pub fn poem_listener(&self) -> Result<poem::listener::BoxListener, WarpgateError> {
        let addrs = self.addresses_to_listen_on()?;
        #[allow(clippy::unwrap_used)] // length known >=1
        let (first, rest) = addrs.split_first().unwrap();
        let mut listener: poem::listener::BoxListener =
            poem::listener::TcpListener::bind(first.to_string()).boxed();
        for addr in rest {
            listener = listener
                .combine(poem::listener::TcpListener::bind(addr.to_string()))
                .boxed();
        }

        Ok(listener)
    }

    pub async fn tcp_accept_stream(
        &self,
    ) -> Result<impl Stream<Item = TcpStream> + Unpin + Send + 'static, WarpgateError> {
        Ok(iter(
            self.tcp_listeners()
                .await?
                .into_iter()
                .map(TcpListenerStream::new),
        )
        .flatten_unordered(None)
        .filter_map(|result| async {
            match result {
                Ok(stream) => Some(stream),
                Err(error) => {
                    // #1962 - accept errors as transient (e.g. EMFILE)
                    // and don't kill the listener
                    warn!(%error, "Failed to accept connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    None
                }
            }
        })
        .boxed())
    }

    pub const fn port(&self) -> u16 {
        self.0.port()
    }

    /// Whether every address this endpoint listens on is a loopback one:
    /// 127.0.0.0/8, `::1`, or 127.0.0.0/8 in IPv4-mapped form
    /// (`::ffff:127.0.0.1`). A wildcard (`0.0.0.0`, `[::]`) is not: it also
    /// listens on every other interface.
    pub fn is_loopback(&self) -> bool {
        is_loopback_ip(self.0.ip())
    }
}

/// Whether an address is a loopback one: 127.0.0.0/8, `::1`, or 127.0.0.0/8
/// in IPv4-mapped form (`::ffff:127.0.0.1`).
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

impl From<SocketAddr> for ListenEndpoint {
    fn from(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl<'de> Deserialize<'de> for ListenEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: String = Deserialize::deserialize::<D>(deserializer)?;
        let v = v
            .to_socket_addrs()
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "failed to resolve {v} into a TCP endpoint: {e:?}"
                ))
            })?
            .next()
            .ok_or_else(|| {
                serde::de::Error::custom(format!("failed to resolve {v} into a TCP endpoint"))
            })?;
        Ok(Self(v))
    }
}

impl Serialize for ListenEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl Debug for ListenEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::ListenEndpoint;

    fn endpoint(address: &str) -> ListenEndpoint {
        ListenEndpoint::from(address.parse::<SocketAddr>().unwrap())
    }

    #[test]
    fn unit_loopback_addresses_are_loopback() {
        for address in [
            "127.0.0.1:8888",
            "127.1.2.3:8888",
            "[::1]:8888",
            "[::ffff:127.0.0.1]:8888",
        ] {
            assert!(endpoint(address).is_loopback(), "{address}");
        }
    }

    #[test]
    fn unit_wildcard_and_other_addresses_are_not_loopback() {
        for address in [
            "0.0.0.0:8888",
            "[::]:8888",
            "203.0.113.10:8888",
            "198.51.100.7:8888",
            "[2001:db8::1]:8888",
            "[::ffff:203.0.113.10]:8888",
            "[::ffff:0.0.0.0]:8888",
        ] {
            assert!(!endpoint(address).is_loopback(), "{address}");
        }
    }
}
