//! On a plain-HTTP loopback listener (`http.plain_http_on_loopback`), a
//! connection is served only when the connecting socket belongs to the OS
//! account Warpgate runs as. Other accounts on the same machine can reach the
//! loopback interface too; their connections are closed before any HTTP is
//! read.
//!
//! The owner comes from the kernel (on Linux, a `sock_diag` netlink lookup of
//! the one socket, or `/proc/net/tcp{,6}` where that is unavailable; on macOS
//! each process's open sockets, through libproc): the client socket is the
//! one whose local endpoint is the accepted connection's remote endpoint and
//! whose remote endpoint is the listener's. A lookup that fails, times out or
//! finds no such socket refuses the connection.
//!
//! Limits of the check:
//! - TCP carries no peer credentials: the owner is looked up by address and
//!   port after the connection is accepted. Each accept costs a lookup (one
//!   netlink request on Linux, a walk of the process table on macOS), at most
//!   [`MAX_CONCURRENT_LOOKUPS`] at a time and each bounded at 2 seconds
//!   including its wait for a turn; one that fails or runs over refuses, so
//!   another account can slow the listener down but not get through.
//! - On Linux a socket belongs to the account that created it, wherever its
//!   descriptor is passed. On macOS it belongs to the account when one of
//!   the account's processes other than Warpgate holds it, which includes a
//!   descriptor another account passed into such a process, and a
//!   descriptor the account handed to another account's process while one
//!   of its own still holds it. A socket held only by processes Warpgate
//!   cannot inspect (root's or another account's) is never found there.
//! - Every process of the account is trusted, relays included: an `ssh -R`
//!   forward, a proxy the account runs. Whoever reaches such a relay is
//!   served as the account. A target pointing back at this listener is
//!   served on Linux; on macOS its client socket is in Warpgate's own
//!   process, which is skipped, so it is refused.
//! - A reverse proxy in front of the listener running as another account is
//!   refused like any other account.
//! - Only the HTTP listener is checked; the SSH listener is not, even on a
//!   loopback address.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use poem::listener::Acceptor;
use tracing::warn;
use warpgate_common::helpers::concurrent_acceptor::{Accepted, ConcurrentAcceptor};

/// The socket tables are read whole; a larger one is refused rather than read.
#[cfg(target_os = "linux")]
const MAX_SOCKET_TABLE_BYTES: usize = 16 * 1024 * 1024;

/// How long one lookup may take, waiting for its turn included, before the
/// connection is refused.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// How many lookups run at once; the rest wait their turn, first come first
/// served, within [`LOOKUP_TIMEOUT`]. Each running lookup holds a blocking
/// thread, so this also bounds the threads a burst of connections can take.
/// A netlink lookup is a single request; the macOS walk reads every process's
/// sockets, so fewer of those run at once.
#[cfg(not(target_os = "macos"))]
const MAX_CONCURRENT_LOOKUPS: usize = 16;
#[cfg(target_os = "macos")]
const MAX_CONCURRENT_LOOKUPS: usize = 4;

static LOOKUP_TURNS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_LOOKUPS);

/// Finds the OS account owning a TCP socket.
pub(crate) trait SocketOwnerLookup: Send + Sync + 'static {
    /// The uid owning the TCP socket whose local endpoint is `local` and whose
    /// remote endpoint is `remote`, or `None` when the table lists no such
    /// socket. Blocking: called off the async executor.
    fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>>;
}

/// The kernel's own socket tables: on Linux a `sock_diag` lookup, or
/// `/proc/net/tcp{,6}` when `sock_diag` failed its self-test; the per-process
/// file tables of libproc on macOS.
pub(crate) struct KernelSocketTable {
    #[cfg(target_os = "linux")]
    sock_diag: bool,
}

impl KernelSocketTable {
    /// On Linux, checks once that `sock_diag` finds a connection this
    /// process has just opened, and falls back to reading `/proc/net/tcp`
    /// when it does not: the kernel answers a lookup it cannot serve (no
    /// `tcp_diag`, a filter on netlink) the way it answers one for a socket
    /// that does not exist, which would refuse every connection.
    pub(crate) fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            let sock_diag = match linux::sock_diag::self_test() {
                Ok(()) => true,
                Err(error) => {
                    warn!(
                        error = %format!("{error:#}"),
                        "The sock_diag socket lookup is unavailable; reading /proc/net/tcp for each loopback connection instead"
                    );
                    false
                }
            };
            Self { sock_diag }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {}
        }
    }
}

impl SocketOwnerLookup for KernelSocketTable {
    #[cfg(target_os = "linux")]
    fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>> {
        if self.sock_diag {
            linux::sock_diag::owner_uid(local, remote)
        } else {
            linux::owner_uid(local, remote)
        }
    }

    #[cfg(target_os = "macos")]
    fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>> {
        macos::owner_uid(local, remote)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn owner_uid(&self, _local: SocketAddr, _remote: SocketAddr) -> anyhow::Result<Option<u32>> {
        bail!("socket owner lookup is not supported on this platform")
    }
}

/// The effective uid of this process, on the platforms where connection
/// owners can be checked; an error elsewhere, so loopback mode refuses to
/// start.
pub(crate) fn effective_uid() -> anyhow::Result<u32> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::geteuid() };
        Ok(uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!(
            "`http.plain_http_on_loopback` is only supported on Linux and macOS, where Warpgate can check which OS account opened each connection"
        )
    }
}

/// The uid a plain-HTTP loopback listener serves, given this process's
/// effective uid: `uid`, unless it is root's: root owns system services' sockets as well,
/// and the kernel lists sockets with no process behind them under uid 0, so
/// serving root's connections would not tell them apart.
pub(crate) fn serving_uid(uid: u32) -> anyhow::Result<u32> {
    if uid == 0 {
        bail!(
            "`http.plain_http_on_loopback` is set, but Warpgate runs as root; run it as the OS account whose connections it should serve"
        );
    }
    Ok(uid)
}

/// What the owner check concluded about one connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OwnerCheck {
    /// The client socket belongs to this process's account.
    SameAccount,
    /// The client socket belongs to another account.
    OtherAccount(u32),
    /// The socket table lists no client socket for this connection.
    NotFound,
    /// The socket table could not be read in time.
    LookupFailed(String),
}

/// Looks up the owner of the client end of the connection `remote` ->
/// `local` (as seen by the listener), off the async executor, at most
/// [`MAX_CONCURRENT_LOOKUPS`] at a time, and within [`LOOKUP_TIMEOUT`].
pub(crate) async fn check_connection_owner(
    lookup: Arc<dyn SocketOwnerLookup>,
    our_uid: u32,
    local: SocketAddr,
    remote: SocketAddr,
) -> OwnerCheck {
    let looked_up = tokio::time::timeout(LOOKUP_TIMEOUT, async move {
        // The turn goes into the blocking task, so a lookup still running
        // after the timeout keeps its place until it ends.
        let turn = LOOKUP_TURNS.acquire().await?;
        // The client socket's endpoints are the accepted connection's, swapped.
        let task = tokio::task::spawn_blocking(move || {
            let _turn = turn;
            lookup.owner_uid(remote, local)
        });
        anyhow::Ok(task.await)
    })
    .await;
    match looked_up {
        Err(_) => OwnerCheck::LookupFailed("timed out".into()),
        Ok(Err(error)) => OwnerCheck::LookupFailed(error.to_string()),
        Ok(Ok(looked_up)) => owner_check(looked_up, our_uid),
    }
}

fn owner_check(
    looked_up: Result<anyhow::Result<Option<u32>>, tokio::task::JoinError>,
    our_uid: u32,
) -> OwnerCheck {
    match looked_up {
        Err(error) => OwnerCheck::LookupFailed(error.to_string()),
        Ok(Err(error)) => OwnerCheck::LookupFailed(format!("{error:#}")),
        Ok(Ok(None)) => OwnerCheck::NotFound,
        Ok(Ok(Some(uid))) if uid == our_uid => OwnerCheck::SameAccount,
        Ok(Ok(Some(uid))) => OwnerCheck::OtherAccount(uid),
    }
}

/// Wraps a loopback acceptor so that only connections from `our_uid`'s
/// sockets come out of it; the others are closed unread. Each check runs in
/// its own task, so a slow lookup does not hold up the accept loop.
pub(crate) fn same_account_acceptor<A: Acceptor + 'static>(
    inner: A,
    lookup: Arc<dyn SocketOwnerLookup>,
    our_uid: u32,
) -> ConcurrentAcceptor<A::Io> {
    ConcurrentAcceptor::new(inner, move |accepted: Accepted<A::Io>| {
        let lookup = lookup.clone();
        async move {
            let (Some(local), Some(remote)) = (
                accepted.1.as_socket_addr().copied(),
                accepted.2.as_socket_addr().copied(),
            ) else {
                warn!("Refused a loopback connection without a TCP address");
                bail!("connection has no TCP address");
            };
            let check = check_connection_owner(lookup, our_uid, local, remote).await;
            match &check {
                OwnerCheck::SameAccount => return Ok(accepted),
                OwnerCheck::OtherAccount(uid) => warn!(
                    peer_uid = uid,
                    "Refused a loopback connection opened by another OS account"
                ),
                OwnerCheck::NotFound => warn!(
                    peer_port = remote.port(),
                    "Refused a loopback connection whose client socket is not in the socket table"
                ),
                OwnerCheck::LookupFailed(error) => warn!(
                    %error,
                    "Refused a loopback connection: could not look up its owner"
                ),
            }
            bail!("connection refused by the owner check: {check:?}")
        }
    })
}

/// The one uid among the sockets that matched, or an error when matching
/// sockets disagree (which refuses the connection).
fn single_owner(uids: impl IntoIterator<Item = u32>) -> anyhow::Result<Option<u32>> {
    let mut found = None;
    for uid in uids {
        match found {
            None => found = Some(uid),
            Some(previous) if previous == uid => {}
            Some(_) => bail!("sockets with different owners match the same connection"),
        }
    }
    Ok(found)
}

fn same_endpoint(a: SocketAddr, b: SocketAddr) -> bool {
    a.ip().to_canonical() == b.ip().to_canonical() && a.port() == b.port()
}

/// `/proc/net/tcp` and `/proc/net/tcp6`.
#[cfg(any(test, target_os = "linux"))]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::same_endpoint;

    #[cfg(target_os = "linux")]
    pub(super) fn owner_uid(local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>> {
        let mut uids = Vec::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Some(table) = read_table(path)? {
                uids.extend(matching_uids(&table, local, remote));
            }
        }
        super::single_owner(uids)
    }

    /// The table at `path`, or `None` when the kernel has none (IPv6 off).
    #[cfg(target_os = "linux")]
    fn read_table(path: &str) -> anyhow::Result<Option<String>> {
        use std::io::Read;

        use anyhow::Context;

        use super::MAX_SOCKET_TABLE_BYTES;

        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("opening {path}")),
        };
        let mut table = String::new();
        file.take(MAX_SOCKET_TABLE_BYTES as u64 + 1)
            .read_to_string(&mut table)
            .with_context(|| format!("reading {path}"))?;
        if table.len() > MAX_SOCKET_TABLE_BYTES {
            anyhow::bail!("{path} is larger than {MAX_SOCKET_TABLE_BYTES} bytes");
        }
        Ok(Some(table))
    }

    /// The uids of the table's sockets with these endpoints. A row with
    /// inode 0 has no open socket behind it (TIME_WAIT, a socket its process
    /// has closed, a connection not yet accepted), is listed under uid 0 and
    /// belongs to no one: it is skipped. Lines that do not parse are skipped
    /// too: they can only leave a socket unfound.
    pub(super) fn matching_uids(
        table: &str,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> impl Iterator<Item = u32> + '_ {
        table.lines().skip(1).filter_map(move |line| {
            let mut fields = line.split_whitespace();
            let _slot = fields.next()?;
            let line_local = parse_endpoint(fields.next()?)?;
            let line_remote = parse_endpoint(fields.next()?)?;
            // State, tx/rx queue, timer, retransmits, then the uid.
            let uid = fields.nth(4)?.parse::<u32>().ok()?;
            // Timeout, then the inode.
            let inode = fields.nth(1)?.parse::<u64>().ok()?;
            (inode != 0 && same_endpoint(line_local, local) && same_endpoint(line_remote, remote))
                .then_some(uid)
        })
    }

    /// An `ADDRESS:PORT` field: the address as the kernel's in-memory words,
    /// each printed as a host-order hex number; the port in hex.
    pub(super) fn parse_endpoint(field: &str) -> Option<SocketAddr> {
        let (address, port) = field.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let ip = match address.len() {
            8 => IpAddr::V4(Ipv4Addr::from(
                u32::from_str_radix(address, 16).ok()?.to_ne_bytes(),
            )),
            32 => {
                let mut bytes = [0u8; 16];
                for (word, out) in address.as_bytes().chunks(8).zip(bytes.chunks_mut(4)) {
                    let word = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
                    out.copy_from_slice(&word.to_ne_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// The kernel's `sock_diag` netlink interface (`linux/inet_diag.h`),
    /// asked for the one TCP socket with the given endpoints: a lookup in the
    /// kernel's connection table rather than a read of all of it, so its cost
    /// does not grow with the number of sockets on the machine, and the
    /// answer is one socket at one moment rather than rows read over time.
    ///
    /// Structures are written and read as bytes at the header's offsets, in
    /// the kernel's byte order (host order, except ports and addresses, which
    /// are in network order). Values are Linux's, so the encoding is tested on
    /// every platform.
    pub(super) mod sock_diag {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        use anyhow::{Context, bail};

        use super::super::same_endpoint;

        /// `SOCK_DIAG_BY_FAMILY`, `NLMSG_ERROR` and `NLM_F_REQUEST`.
        const SOCK_DIAG_BY_FAMILY: u16 = 20;
        const NLMSG_ERROR: u16 = 2;
        const NLM_F_REQUEST: u16 = 1;
        /// `sizeof(struct nlmsghdr)`.
        pub(in super::super) const NLMSG_HDRLEN: usize = 16;
        /// `sizeof(struct inet_diag_req_v2)`.
        pub(in super::super) const REQ_LEN: usize = 56;
        /// `sizeof(struct inet_diag_msg)`.
        pub(in super::super) const MSG_LEN: usize = 72;
        pub(in super::super) const AF_INET: u8 = 2;
        pub(in super::super) const AF_INET6: u8 = 10;
        const IPPROTO_TCP: u8 = 6;
        /// `TCP_LISTEN` in `idiag_state`.
        pub(in super::super) const TCP_LISTEN: u8 = 10;
        const ENOENT: i32 = 2;

        /// The request for the TCP socket whose local endpoint is `local`
        /// and whose remote endpoint is `remote`, or `None` when one is IPv4
        /// and the other IPv6, which no socket is.
        pub(in super::super) fn request(
            local: SocketAddr,
            remote: SocketAddr,
            seq: u32,
        ) -> Option<Vec<u8>> {
            let (family, src, dst) = match (local.ip().to_canonical(), remote.ip().to_canonical()) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    // An IPv4 address is the first of the four words.
                    let mut src_words = [0u8; 16];
                    let mut dst_words = [0u8; 16];
                    src_words.get_mut(..4)?.copy_from_slice(&src.octets());
                    dst_words.get_mut(..4)?.copy_from_slice(&dst.octets());
                    (AF_INET, src_words, dst_words)
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => (AF_INET6, src.octets(), dst.octets()),
                _ => return None,
            };
            let mut out = Vec::with_capacity(NLMSG_HDRLEN + REQ_LEN);
            // struct nlmsghdr: length, type, flags, sequence, port id (0 is
            // the kernel).
            out.extend_from_slice(&u32::try_from(NLMSG_HDRLEN + REQ_LEN).ok()?.to_ne_bytes());
            out.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            out.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
            out.extend_from_slice(&seq.to_ne_bytes());
            out.extend_from_slice(&0u32.to_ne_bytes());
            // struct inet_diag_req_v2: family, protocol, no extensions,
            // padding, every state.
            out.extend_from_slice(&[family, IPPROTO_TCP, 0, 0]);
            out.extend_from_slice(&u32::MAX.to_ne_bytes());
            // struct inet_diag_sockid: ports, addresses, any interface,
            // INET_DIAG_NOCOOKIE.
            out.extend_from_slice(&local.port().to_be_bytes());
            out.extend_from_slice(&remote.port().to_be_bytes());
            out.extend_from_slice(&src);
            out.extend_from_slice(&dst);
            out.extend_from_slice(&0u32.to_ne_bytes());
            out.extend_from_slice(&[0xff; 8]);
            Some(out)
        }

        /// The owner of the socket in the kernel's reply to request `seq`.
        /// "No such socket" is `None`. So is a socket that is not the one
        /// asked for: the kernel's lookup falls back to a listening socket on
        /// the local endpoint, and lists one with no open descriptor behind it
        /// (TIME_WAIT, closed by its process) under uid 0 and inode 0; neither
        /// belongs to the client.
        pub(in super::super) fn parse_reply(
            reply: &[u8],
            seq: u32,
            local: SocketAddr,
            remote: SocketAddr,
        ) -> anyhow::Result<Option<u32>> {
            let length = ne_u32(reply, 0).context("short netlink reply")? as usize;
            let kind = ne_u16(reply, 4).context("short netlink reply")?;
            if ne_u32(reply, 8) != Some(seq) {
                bail!("netlink reply to another request");
            }
            let body = reply
                .get(NLMSG_HDRLEN..length)
                .context("netlink reply shorter than its header says")?;
            match kind {
                NLMSG_ERROR => {
                    let error = ne_i32(body, 0).context("short netlink error")?;
                    if error == -ENOENT {
                        return Ok(None);
                    }
                    bail!(
                        "the kernel refused the socket lookup: {}",
                        std::io::Error::from_raw_os_error(-error)
                    );
                }
                SOCK_DIAG_BY_FAMILY => {}
                other => bail!("unexpected netlink message type {other}"),
            }
            let message = body.get(..MSG_LEN).context("short inet_diag_msg")?;
            let family = *message.first().context("short inet_diag_msg")?;
            let state = *message.get(1).context("short inet_diag_msg")?;
            let (Some(found_local), Some(found_remote)) = (
                endpoint(message, family, 4, 8),
                endpoint(message, family, 6, 24),
            ) else {
                return Ok(None);
            };
            let uid = ne_u32(message, 64).context("short inet_diag_msg")?;
            let inode = ne_u32(message, 68).context("short inet_diag_msg")?;
            let is_the_client = state != TCP_LISTEN
                && inode != 0
                && same_endpoint(found_local, local)
                && same_endpoint(found_remote, remote);
            Ok(is_the_client.then_some(uid))
        }

        fn ne_u16(bytes: &[u8], at: usize) -> Option<u16> {
            Some(u16::from_ne_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
        }

        fn ne_i32(bytes: &[u8], at: usize) -> Option<i32> {
            Some(i32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
        }

        fn ne_u32(bytes: &[u8], at: usize) -> Option<u32> {
            Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
        }

        /// The endpoint with its port at `port_at` and its address at
        /// `address_at`, both in network order.
        fn endpoint(
            message: &[u8],
            family: u8,
            port_at: usize,
            address_at: usize,
        ) -> Option<SocketAddr> {
            let port = u16::from_be_bytes(message.get(port_at..port_at + 2)?.try_into().ok()?);
            let ip = match family {
                AF_INET => IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(message.get(address_at..address_at + 4)?).ok()?,
                )),
                AF_INET6 => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(message.get(address_at..address_at + 16)?).ok()?,
                )),
                _ => return None,
            };
            Some(SocketAddr::new(ip, port))
        }

        /// Opens a loopback connection and looks its client socket up: the
        /// lookup must find it under this process's uid.
        #[cfg(target_os = "linux")]
        pub(in super::super) fn self_test() -> anyhow::Result<()> {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").context("binding a test listener")?;
            let listen_address = listener.local_addr()?;
            let client =
                std::net::TcpStream::connect(listen_address).context("connecting to it")?;
            let (_server, _) = listener.accept().context("accepting the connection")?;
            let found = owner_uid(client.local_addr()?, listen_address)?;
            let ours = super::super::effective_uid()?;
            if found != Some(ours) {
                bail!("a connection of this process was looked up as {found:?}, not uid {ours}");
            }
            Ok(())
        }

        /// The uid owning the TCP socket with these endpoints, from one
        /// `sock_diag` request.
        #[cfg(target_os = "linux")]
        #[allow(unsafe_code)]
        pub(in super::super) fn owner_uid(
            local: SocketAddr,
            remote: SocketAddr,
        ) -> anyhow::Result<Option<u32>> {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            use std::sync::atomic::{AtomicU32, Ordering};

            static SEQUENCE: AtomicU32 = AtomicU32::new(1);

            let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let Some(request) = request(local, remote, seq) else {
                return Ok(None);
            };

            // SAFETY: socket(2) has no memory preconditions; the descriptor
            // is owned (and closed) by `socket` below.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    libc::NETLINK_SOCK_DIAG,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).context("opening a sock_diag socket");
            }
            // SAFETY: `fd` is a descriptor just opened that nothing else owns.
            let socket = unsafe { OwnedFd::from_raw_fd(fd) };

            // A reply that never comes ends the read here rather than holding
            // the thread for good.
            let timeout = libc::timeval {
                tv_sec: super::super::LOOKUP_TIMEOUT
                    .as_secs()
                    .try_into()
                    .unwrap_or(libc::time_t::MAX),
                tv_usec: 0,
            };
            // SAFETY: setsockopt reads `timeout` for the length given.
            let set = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&raw const timeout).cast(),
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if set != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("setting the sock_diag read timeout");
            }

            // SAFETY: an all-zero sockaddr_nl is valid; port id 0 is the
            // kernel.
            let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: sendto reads `request` and `kernel` for the lengths
            // given.
            let sent = unsafe {
                libc::sendto(
                    socket.as_raw_fd(),
                    request.as_ptr().cast(),
                    request.len(),
                    0,
                    (&raw const kernel).cast(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("sending the sock_diag request");
            }
            if sent as usize != request.len() {
                bail!("the sock_diag request was sent short");
            }

            let mut reply = [0u8; 8192];
            // SAFETY: as above, all zeroes is a valid sockaddr_nl.
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut sender_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: recvfrom writes at most `reply.len()` bytes into
            // `reply` and at most `sender_len` bytes into `sender`.
            let received = unsafe {
                libc::recvfrom(
                    socket.as_raw_fd(),
                    reply.as_mut_ptr().cast(),
                    reply.len(),
                    0,
                    (&raw mut sender).cast(),
                    &raw mut sender_len,
                )
            };
            if received < 0 {
                return Err(std::io::Error::last_os_error()).context("reading the sock_diag reply");
            }
            if sender.nl_pid != 0 {
                bail!("a sock_diag reply that did not come from the kernel");
            }
            let reply = reply
                .get(..received as usize)
                .context("sock_diag reply longer than its buffer")?;
            parse_reply(reply, seq, local, remote)
        }
    }
}

/// libproc's per-process file tables, which `lsof` reads too: every process
/// this account may inspect, each of its socket descriptors, and the TCP
/// endpoints of each. An ordinary user can inspect only its own account's
/// processes, so a socket held by another account's process (root's
/// included) is never found and its connection is refused.
///
/// The client socket is identified by its full 4-tuple (both addresses and
/// both ports), which no two live TCP sockets share; `soi_so` is a scrambled
/// kernel pointer and is not used. A socket can be open in several processes
/// (an inherited or passed descriptor): every holder found must have the same
/// uid. A socket counts only in ESTABLISHED, CLOSE_WAIT, FIN_WAIT_1 or
/// FIN_WAIT_2. This process's own sockets are skipped.
///
/// Layouts follow `sys/proc_info.h`; `libc` declares `proc_fdinfo` and
/// `proc_bsdinfo` but not `socket_fdinfo`, which is read as bytes at the
/// header's offsets, and every call's returned size is checked.
#[cfg(any(test, target_os = "macos"))]
mod macos {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{same_endpoint, single_owner};

    /// `sizeof(struct socket_fdinfo)`: a `struct proc_fileinfo` (24 bytes),
    /// then `struct socket_info`.
    pub(super) const SOCKET_FDINFO_LEN: usize = 792;
    /// `psi.soi_kind`.
    pub(super) const SOI_KIND: usize = 24 + 232;
    /// `psi.soi_proto`: for `SOCKINFO_TCP`, a `struct tcp_sockinfo`, which
    /// starts with a `struct in_sockinfo`.
    pub(super) const SOI_PROTO: usize = 24 + 240;
    // `struct in_sockinfo`. The ports are `int`s holding the network-order
    // `u_short`.
    pub(super) const INSI_FPORT: usize = SOI_PROTO;
    pub(super) const INSI_LPORT: usize = SOI_PROTO + 4;
    pub(super) const INSI_VFLAG: usize = SOI_PROTO + 24;
    pub(super) const INSI_FADDR: usize = SOI_PROTO + 32;
    pub(super) const INSI_LADDR: usize = SOI_PROTO + 48;
    /// `struct tcp_sockinfo`'s `tcpsi_state`, after its `in_sockinfo`.
    pub(super) const TCPSI_STATE: usize = SOI_PROTO + 80;
    /// Within an address union, where an IPv4 address sits (`ina_46`).
    pub(super) const IN_ADDR_4IN6_OFFSET: usize = 12;
    pub(super) const SOCKINFO_TCP: i32 = 2;
    pub(super) const INI_IPV4: u8 = 0x1;
    pub(super) const INI_IPV6: u8 = 0x2;
    // The `TSI_S_*` (`TCPS_*`) states in which a socket counts as holding a
    // connection. Every other state (CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED,
    // CLOSING, LAST_ACK, TIME_WAIT) does not, and its process is no holder.
    pub(super) const TSI_S_ESTABLISHED: i32 = 4;
    pub(super) const TSI_S_CLOSE_WAIT: i32 = 5;
    pub(super) const TSI_S_FIN_WAIT_1: i32 = 6;
    pub(super) const TSI_S_FIN_WAIT_2: i32 = 9;

    /// A TCP socket's endpoints and state, from its `struct socket_fdinfo`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct TcpSocket {
        pub local: SocketAddr,
        pub remote: SocketAddr,
        pub state: i32,
    }

    impl TcpSocket {
        /// Whether the socket holds a live connection; only then is its
        /// process a holder.
        fn is_connected(&self) -> bool {
            matches!(
                self.state,
                TSI_S_ESTABLISHED | TSI_S_CLOSE_WAIT | TSI_S_FIN_WAIT_1 | TSI_S_FIN_WAIT_2
            )
        }
    }

    /// A TCP socket open in a process.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct ProcessSocket {
        pub pid: i32,
        pub socket: TcpSocket,
    }

    /// The owner of the socket with these endpoints among `sockets`: the one
    /// uid of every process holding it connected, other than `own_pid`; a
    /// socket in any other state is not a holder. `uid_of` gives
    /// a holder's uid, or `None` when it has exited since (it is passed over).
    /// Holders with different uids are an error.
    pub(super) fn find_owner(
        sockets: &[ProcessSocket],
        own_pid: i32,
        local: SocketAddr,
        remote: SocketAddr,
        mut uid_of: impl FnMut(i32) -> anyhow::Result<Option<u32>>,
    ) -> anyhow::Result<Option<u32>> {
        let mut holders = sockets
            .iter()
            .filter(|socket| {
                socket.pid != own_pid
                    && socket.socket.is_connected()
                    && same_endpoint(socket.socket.local, local)
                    && same_endpoint(socket.socket.remote, remote)
            })
            .map(|socket| socket.pid)
            .collect::<Vec<_>>();
        holders.sort_unstable();
        holders.dedup();
        let mut uids = Vec::new();
        for pid in holders {
            if let Some(uid) = uid_of(pid)? {
                uids.push(uid);
            }
        }
        single_owner(uids)
    }

    /// Whether a failed per-process call, by its errno, only means the
    /// process or descriptor is out of reach: it has exited (`ESRCH`), closed
    /// the descriptor (`EBADF`), or belongs to an account this one may not
    /// inspect (`EPERM`). `0` is a call that returned nothing without an
    /// error. Anything else refuses the connection.
    #[cfg(unix)]
    pub(super) fn is_out_of_reach(errno: Option<i32>) -> bool {
        matches!(errno, Some(0 | libc::ESRCH | libc::EBADF | libc::EPERM))
    }

    fn read_i32(record: &[u8], offset: usize) -> Option<i32> {
        let bytes = record.get(offset..offset.checked_add(4)?)?;
        Some(i32::from_ne_bytes(bytes.try_into().ok()?))
    }

    /// A port: an `int` holding the network-order `u_short`.
    fn read_port(record: &[u8], offset: usize) -> Option<u16> {
        Some(u16::from_be(read_i32(record, offset)? as u16))
    }

    fn read_address(record: &[u8], union_offset: usize, vflag: u8) -> Option<IpAddr> {
        if vflag & INI_IPV4 != 0 {
            let start = union_offset.checked_add(IN_ADDR_4IN6_OFFSET)?;
            let bytes: [u8; 4] = record.get(start..start.checked_add(4)?)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        } else if vflag & INI_IPV6 != 0 {
            let bytes: [u8; 16] = record
                .get(union_offset..union_offset.checked_add(16)?)?
                .try_into()
                .ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        } else {
            None
        }
    }

    /// A `struct socket_fdinfo`'s endpoints and state when it is a TCP
    /// socket; `None` for any other socket. A record of any other size is an
    /// error: the layout is not the one this reads.
    pub(super) fn parse_socket_fdinfo(record: &[u8]) -> anyhow::Result<Option<TcpSocket>> {
        if record.len() != SOCKET_FDINFO_LEN {
            anyhow::bail!(
                "socket info is {} bytes, expected {SOCKET_FDINFO_LEN}",
                record.len()
            );
        }
        if read_i32(record, SOI_KIND) != Some(SOCKINFO_TCP) {
            return Ok(None);
        }
        Ok(tcp_socket(record))
    }

    /// A TCP socket's `struct in_sockinfo` endpoints and its state.
    fn tcp_socket(record: &[u8]) -> Option<TcpSocket> {
        let vflag = *record.get(INSI_VFLAG)?;
        let local = SocketAddr::new(
            read_address(record, INSI_LADDR, vflag)?,
            read_port(record, INSI_LPORT)?,
        );
        let remote = SocketAddr::new(
            read_address(record, INSI_FADDR, vflag)?,
            read_port(record, INSI_FPORT)?,
        );
        Some(TcpSocket {
            local,
            remote,
            state: read_i32(record, TCPSI_STATE)?,
        })
    }

    #[cfg(target_os = "macos")]
    pub(super) use walk::owner_uid;

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    mod walk {
        use std::net::SocketAddr;
        use std::time::Instant;

        use anyhow::{Context, bail};

        use super::{
            ProcessSocket, SOCKET_FDINFO_LEN, TcpSocket, find_owner, is_out_of_reach,
            parse_socket_fdinfo,
        };

        /// `PROC_ALL_PIDS` and `PROC_PIDFDSOCKETINFO` in `sys/proc_info.h`;
        /// not in `libc`.
        const PROC_ALL_PIDS: u32 = 1;
        const PROC_PIDFDSOCKETINFO: libc::c_int = 3;

        /// Bounds on the walk: past any of them, or past the deadline, the
        /// connection is refused.
        const MAX_PIDS: usize = 100_000;
        const MAX_FDS_PER_PROCESS: usize = 1 << 20;
        const MAX_SOCKETS: usize = 1 << 20;

        /// `struct socket_fdinfo`, as bytes with its alignment.
        #[repr(C, align(8))]
        struct SocketFdInfo([u8; SOCKET_FDINFO_LEN]);

        pub(in super::super) fn owner_uid(
            local: SocketAddr,
            remote: SocketAddr,
        ) -> anyhow::Result<Option<u32>> {
            let deadline = Instant::now() + super::super::LOOKUP_TIMEOUT;
            let own_pid = i32::try_from(std::process::id()).context("process id")?;
            let mut sockets = Vec::new();
            let mut inspected = 0usize;
            for pid in list_pids()? {
                if pid <= 0 || pid == own_pid {
                    continue;
                }
                let Some(fds) = list_fds(pid)? else {
                    continue;
                };
                for fd in fds {
                    if fd.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
                        continue;
                    }
                    inspected += 1;
                    if inspected > MAX_SOCKETS {
                        bail!("more than {MAX_SOCKETS} sockets to inspect");
                    }
                    if Instant::now() > deadline {
                        bail!("the socket lookup ran past its deadline");
                    }
                    if let Some(socket) = tcp_socket(pid, fd.proc_fd)? {
                        sockets.push(ProcessSocket { pid, socket });
                    }
                }
                if Instant::now() > deadline {
                    bail!("the socket lookup ran past its deadline");
                }
            }
            find_owner(&sockets, own_pid, local, remote, process_uid)
        }

        fn clear_errno() {
            // SAFETY: `__error` returns this thread's errno location.
            unsafe { *libc::__error() = 0 };
        }

        /// Every process id. A list that fills the buffer may have been cut
        /// short, and is refused.
        fn list_pids() -> anyhow::Result<Vec<i32>> {
            // SAFETY: a size query: no buffer.
            let needed = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
            if needed <= 0 {
                return Err(std::io::Error::last_os_error()).context("sizing the process list");
            }
            let count = needed as usize / size_of::<i32>() + 64;
            if count > MAX_PIDS {
                bail!("more than {MAX_PIDS} processes");
            }
            let mut pids = vec![0i32; count];
            let bytes = libc::c_int::try_from(count * size_of::<i32>())?;
            // SAFETY: `pids` is writable for `bytes` bytes.
            let filled =
                unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), bytes) };
            if filled <= 0 {
                return Err(std::io::Error::last_os_error()).context("listing processes");
            }
            if filled >= bytes {
                bail!("the process list grew while it was read");
            }
            pids.truncate(filled as usize / size_of::<i32>());
            Ok(pids)
        }

        /// The open descriptors of `pid`, or `None` when it is out of reach.
        fn list_fds(pid: i32) -> anyhow::Result<Option<Vec<libc::proc_fdinfo>>> {
            const ENTRY: usize = size_of::<libc::proc_fdinfo>();
            clear_errno();
            // SAFETY: a size query: no buffer.
            let needed = unsafe {
                libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
            };
            if needed <= 0 {
                return out_of_reach("sizing a process's descriptors").map(|()| None);
            }
            let count = needed as usize / ENTRY + 16;
            if count > MAX_FDS_PER_PROCESS {
                bail!("a process has more than {MAX_FDS_PER_PROCESS} descriptors");
            }
            let mut fds = vec![
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0,
                };
                count
            ];
            let bytes = libc::c_int::try_from(count * ENTRY)?;
            clear_errno();
            // SAFETY: `fds` is writable for `bytes` bytes.
            let filled = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    bytes,
                )
            };
            if filled <= 0 {
                return out_of_reach("listing a process's descriptors").map(|()| None);
            }
            if filled >= bytes || filled as usize % ENTRY != 0 {
                bail!("a process's descriptor list does not fit its layout or grew while read");
            }
            fds.truncate(filled as usize / ENTRY);
            Ok(Some(fds))
        }

        /// The TCP socket behind `pid`'s descriptor `fd`, or `None` when it
        /// is not a TCP socket or is out of reach.
        fn tcp_socket(pid: i32, fd: i32) -> anyhow::Result<Option<TcpSocket>> {
            let mut info = SocketFdInfo([0; SOCKET_FDINFO_LEN]);
            clear_errno();
            // SAFETY: `info` is writable for `SOCKET_FDINFO_LEN` bytes.
            let size = unsafe {
                libc::proc_pidfdinfo(
                    pid,
                    fd,
                    PROC_PIDFDSOCKETINFO,
                    info.0.as_mut_ptr().cast(),
                    SOCKET_FDINFO_LEN as libc::c_int,
                )
            };
            if size <= 0 {
                return out_of_reach("reading a socket").map(|()| None);
            }
            let record = info
                .0
                .get(..size as usize)
                .context("socket info larger than its buffer")?;
            parse_socket_fdinfo(record)
        }

        /// The effective uid of `pid`, or `None` when it has exited. Any
        /// other failure, or a reply of another size, refuses.
        fn process_uid(pid: i32) -> anyhow::Result<Option<u32>> {
            const EXPECTED: usize = size_of::<libc::proc_bsdinfo>();
            // SAFETY: `proc_bsdinfo` is plain integers and arrays of them.
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            clear_errno();
            // SAFETY: `info` is writable for `EXPECTED` bytes.
            let size = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    (&raw mut info).cast(),
                    EXPECTED as libc::c_int,
                )
            };
            if size <= 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(None);
                }
                return Err(error).context("reading a socket holder's uid");
            }
            if size as usize != EXPECTED {
                bail!("process info is {size} bytes, expected {EXPECTED}");
            }
            Ok(Some(info.pbi_uid))
        }

        /// `Ok` when the call that just failed only found its process or
        /// descriptor out of reach; otherwise its error.
        fn out_of_reach(what: &str) -> anyhow::Result<()> {
            let error = std::io::Error::last_os_error();
            if is_out_of_reach(error.raw_os_error()) {
                Ok(())
            } else {
                Err(error).context(what.to_owned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Mutex;

    use poem::listener::{Listener, TcpListener};
    use tokio::io::AsyncReadExt;

    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A lookup that answers from a fixed result and records what it was
    /// asked.
    struct FixedLookup {
        answer: Result<Option<u32>, String>,
        asked: Mutex<Vec<(SocketAddr, SocketAddr)>>,
    }

    impl FixedLookup {
        fn new(answer: Result<Option<u32>, String>) -> Arc<Self> {
            Arc::new(Self {
                answer,
                asked: Mutex::new(Vec::new()),
            })
        }
    }

    impl SocketOwnerLookup for FixedLookup {
        fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>> {
            self.asked.lock().unwrap().push((local, remote));
            self.answer.clone().map_err(anyhow::Error::msg)
        }
    }

    #[tokio::test]
    async fn owner_check_asks_for_the_client_end_of_the_connection() {
        let lookup = FixedLookup::new(Ok(Some(501)));
        let listener = addr("127.0.0.1:8888");
        let peer = addr("127.0.0.1:50123");
        let check = check_connection_owner(lookup.clone(), 501, listener, peer).await;
        assert_eq!(check, OwnerCheck::SameAccount);
        assert_eq!(*lookup.asked.lock().unwrap(), vec![(peer, listener)]);
    }

    #[tokio::test]
    async fn owner_check_allows_only_the_same_account() {
        let (local, remote) = (addr("127.0.0.1:8888"), addr("127.0.0.1:50123"));
        for (answer, expected) in [
            (Ok(Some(501)), OwnerCheck::SameAccount),
            (Ok(Some(502)), OwnerCheck::OtherAccount(502)),
            (Ok(Some(0)), OwnerCheck::OtherAccount(0)),
            (Ok(None), OwnerCheck::NotFound),
        ] {
            let check = check_connection_owner(FixedLookup::new(answer), 501, local, remote).await;
            assert_eq!(check, expected);
        }
        let check =
            check_connection_owner(FixedLookup::new(Err("no table".into())), 501, local, remote)
                .await;
        assert!(matches!(check, OwnerCheck::LookupFailed(_)), "{check:?}");
    }

    /// Connects once through the owner check: whether the connection came out
    /// of the acceptor, and what the client read when it did not.
    async fn accept_through(lookup: Arc<dyn SocketOwnerLookup>) -> (bool, Vec<u8>) {
        let acceptor = TcpListener::bind("127.0.0.1:0")
            .into_acceptor()
            .await
            .unwrap();
        let address = *acceptor
            .local_addr()
            .first()
            .unwrap()
            .as_socket_addr()
            .unwrap();
        let mut acceptor = same_account_acceptor(acceptor, lookup, 501);

        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_millis(500), acceptor.accept()).await;
        let mut received = Vec::new();
        if accepted.is_err() {
            // Refused: the connection is closed without a byte.
            let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut received))
                .await
                .unwrap();
        }
        (accepted.is_ok_and(|accepted| accepted.is_ok()), received)
    }

    #[tokio::test]
    async fn acceptor_passes_same_account_connections() {
        let (accepted, _) = accept_through(FixedLookup::new(Ok(Some(501)))).await;
        assert!(accepted);
    }

    #[tokio::test]
    async fn acceptor_closes_other_account_unknown_and_failed_connections() {
        for answer in [Ok(Some(502)), Ok(None), Err("no table".to_string())] {
            let (accepted, received) = accept_through(FixedLookup::new(answer.clone())).await;
            assert!(!accepted, "{answer:?}");
            assert!(received.is_empty(), "{answer:?}");
        }
    }

    /// A connection from this process, looked up in the real socket table,
    /// belongs to this process's account. Linux lists every socket in one
    /// table, so the client being in this same process changes nothing; on
    /// macOS see `kernel_table_finds_a_child_process_connection`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kernel_table_finds_our_own_connection() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(listener) = tokio::net::TcpListener::bind(bind).await else {
                // No IPv6 loopback on this machine.
                continue;
            };
            let listen_address = listener.local_addr().unwrap();
            let client = tokio::net::TcpStream::connect(listen_address)
                .await
                .unwrap();
            let (_server, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr().unwrap());

            let our_uid = effective_uid().unwrap();
            let check = check_connection_owner(
                Arc::new(KernelSocketTable::detect()),
                our_uid,
                listen_address,
                peer,
            )
            .await;
            assert_eq!(check, OwnerCheck::SameAccount, "{bind}");

            // An endpoint nobody holds is not found.
            let unused = SocketAddr::new(peer.ip(), 1);
            let check = check_connection_owner(
                Arc::new(KernelSocketTable::detect()),
                our_uid,
                listen_address,
                unused,
            )
            .await;
            assert_eq!(check, OwnerCheck::NotFound, "{bind}");
        }
    }

    /// On macOS the client is another process of this account (`nc`), as a
    /// browser would be: its socket is found in that process. A client in
    /// Warpgate's own process is never found, as its own sockets are skipped.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn kernel_table_finds_a_child_process_connection() {
        use std::process::{Command, Stdio};

        let our_uid = effective_uid().unwrap();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(listener) = tokio::net::TcpListener::bind(bind).await else {
                // No IPv6 loopback on this machine.
                continue;
            };
            let listen_address = listener.local_addr().unwrap();

            // `nc` connects and holds the connection open while its stdin is.
            let mut child = Command::new("/usr/bin/nc")
                .arg(listen_address.ip().to_string())
                .arg(listen_address.port().to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await;
            let check = match accepted {
                Ok(Ok((_server, peer))) => Some(
                    check_connection_owner(
                        Arc::new(KernelSocketTable::detect()),
                        our_uid,
                        listen_address,
                        peer,
                    )
                    .await,
                ),
                _ => None,
            };
            let _ = child.kill();
            let _ = child.wait();
            assert_eq!(check, Some(OwnerCheck::SameAccount), "{bind}");

            // The same kind of connection from this process.
            let client = tokio::net::TcpStream::connect(listen_address)
                .await
                .unwrap();
            let (_server, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr().unwrap());
            let check = check_connection_owner(
                Arc::new(KernelSocketTable::detect()),
                our_uid,
                listen_address,
                peer,
            )
            .await;
            assert_eq!(check, OwnerCheck::NotFound, "{bind}");
        }
    }

    #[test]
    fn single_owner_refuses_disagreeing_sockets() {
        assert_eq!(single_owner([]).unwrap(), None);
        assert_eq!(single_owner([501, 501]).unwrap(), Some(501));
        assert!(single_owner([501, 502]).is_err());
    }

    #[test]
    fn endpoints_compare_ipv4_mapped_addresses_as_ipv4() {
        assert!(same_endpoint(
            addr("127.0.0.1:8888"),
            addr("[::ffff:127.0.0.1]:8888")
        ));
        assert!(!same_endpoint(
            addr("127.0.0.1:8888"),
            addr("127.0.0.1:8889")
        ));
        assert!(!same_endpoint(addr("127.0.0.1:8888"), addr("[::1]:8888")));
    }

    // The kernel prints addresses as host-order words; these samples are
    // from a little-endian machine.
    #[cfg(target_endian = "little")]
    const PROC_NET_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000   501        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C37B 0100007F:22B8 01 00000000:00000000 00:00000000 00000000   502        0 1002 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:22B8 0100007F:C37B 01 00000000:00000000 00:00000000 00000000   501        0 1003 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:C37C 0100007F:22B8 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0000000000000000
   4: 0100007F:C37D 0100007F:22B8 01 00000000:00000000 00:00000000 00000000   501        0 1004 1 0000000000000000 20 4 30 10 -1
   5: 0100007F:C382 0100007F:22B8 05 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 20 4 30 10 -1
   6: 0100007F:C383 0100007F:22B8 03 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 20 4 30 10 -1
";

    #[cfg(target_endian = "little")]
    const PROC_NET_TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:C37E 00000000000000000000000001000000:22B8 01 00000000:00000000 00:00000000 00000000   503        0 2001 1 0000000000000000 20 4 30 10 -1
   1: 0000000000000000FFFF00000100007F:C37F 0000000000000000FFFF00000100007F:22B8 01 00000000:00000000 00:00000000 00000000   504        0 2002 1 0000000000000000 20 4 30 10 -1
";

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_net_tcp_finds_the_client_socket_owner() {
        let uids = |table, local, remote| {
            linux::matching_uids(table, addr(local), addr(remote)).collect::<Vec<_>>()
        };
        // The client end, not the server end with the same endpoints swapped.
        assert_eq!(
            uids(PROC_NET_TCP, "127.0.0.1:50043", "127.0.0.1:8888"),
            vec![502]
        );
        assert_eq!(
            uids(PROC_NET_TCP, "127.0.0.1:50045", "127.0.0.1:8888"),
            vec![501]
        );
        // TIME_WAIT, closed and pending rows (inode 0) belong to no one.
        assert!(uids(PROC_NET_TCP, "127.0.0.1:50044", "127.0.0.1:8888").is_empty());
        assert!(uids(PROC_NET_TCP, "127.0.0.1:50050", "127.0.0.1:8888").is_empty());
        assert!(uids(PROC_NET_TCP, "127.0.0.1:50051", "127.0.0.1:8888").is_empty());
        // Unknown endpoints and the listening socket match nothing.
        assert!(uids(PROC_NET_TCP, "127.0.0.1:50046", "127.0.0.1:8888").is_empty());
        assert!(uids(PROC_NET_TCP, "127.0.0.1:50043", "127.0.0.1:8889").is_empty());
    }

    /// A lookup in a fixed `/proc/net/tcp` table.
    #[cfg(target_endian = "little")]
    struct ProcTable(&'static str);

    #[cfg(target_endian = "little")]
    impl SocketOwnerLookup for ProcTable {
        fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>> {
            single_owner(linux::matching_uids(self.0, local, remote))
        }
    }

    /// Rows with no socket behind them are listed under uid 0; even a
    /// process running as uid 0 finds no owner in them.
    #[cfg(target_endian = "little")]
    #[tokio::test]
    async fn proc_net_tcp_rows_without_a_socket_match_no_account() {
        let listener = addr("127.0.0.1:8888");
        for client in ["127.0.0.1:50044", "127.0.0.1:50050", "127.0.0.1:50051"] {
            let lookup = Arc::new(ProcTable(PROC_NET_TCP));
            let check = check_connection_owner(lookup, 0, listener, addr(client)).await;
            assert_eq!(check, OwnerCheck::NotFound, "{client}");
        }
        let lookup = Arc::new(ProcTable(PROC_NET_TCP));
        let check = check_connection_owner(lookup, 0, listener, addr("127.0.0.1:50043")).await;
        assert_eq!(check, OwnerCheck::OtherAccount(502));
    }

    #[test]
    fn loopback_mode_refuses_to_serve_root() {
        let error = serving_uid(0).unwrap_err();
        assert!(error.to_string().contains("root"), "{error}");
        assert_eq!(serving_uid(501).unwrap(), 501);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_net_tcp6_finds_the_client_socket_owner() {
        let uids = |local, remote| {
            linux::matching_uids(PROC_NET_TCP6, addr(local), addr(remote)).collect::<Vec<_>>()
        };
        assert_eq!(uids("[::1]:50046", "[::1]:8888"), vec![503]);
        // An IPv6 socket talking IPv4 is listed with mapped addresses.
        assert_eq!(uids("127.0.0.1:50047", "127.0.0.1:8888"), vec![504]);
    }

    #[test]
    fn proc_net_tcp_endpoints_parse_in_host_order_words() {
        let word = |ip: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(ip));
        let v4 = format!("{}:1F90", word([127, 0, 0, 1]));
        assert_eq!(linux::parse_endpoint(&v4), Some(addr("127.0.0.1:8080")));

        let v6 = format!(
            "{}{}{}{}:0050",
            word([0, 0, 0, 0]),
            word([0, 0, 0, 0]),
            word([0, 0, 0, 0]),
            word([0, 0, 0, 1])
        );
        assert_eq!(linux::parse_endpoint(&v6), Some(addr("[::1]:80")));

        for bad in [
            "",
            "0100007F",
            "0100007F:",
            "XYZ0007F:1F90",
            "0100007F:1F9000",
            "01:1F90",
        ] {
            assert_eq!(linux::parse_endpoint(bad), None, "{bad:?}");
        }
    }

    /// Builds an established TCP socket's `struct socket_fdinfo` through the
    /// parser's own offsets (pinned on their own by
    /// `socket_fdinfo_layout_matches_the_header`).
    fn socket_fdinfo(kind: i32, local: SocketAddr, remote: SocketAddr) -> Vec<u8> {
        let mut record = vec![0u8; macos::SOCKET_FDINFO_LEN];
        let mut put = |offset: usize, bytes: &[u8]| {
            record[offset..offset + bytes.len()].copy_from_slice(bytes);
        };
        put(macos::SOI_KIND, &kind.to_ne_bytes());
        put(macos::TCPSI_STATE, &macos::TSI_S_ESTABLISHED.to_ne_bytes());
        // An `int` holding the network-order `u_short`.
        let port = |port: u16| i32::from(port.to_be()).to_ne_bytes();
        put(macos::INSI_LPORT, &port(local.port()));
        put(macos::INSI_FPORT, &port(remote.port()));
        for (union_offset, ip) in [
            (macos::INSI_LADDR, local.ip()),
            (macos::INSI_FADDR, remote.ip()),
        ] {
            match ip {
                IpAddr::V4(ip) => put(union_offset + macos::IN_ADDR_4IN6_OFFSET, &ip.octets()),
                IpAddr::V6(ip) => put(union_offset, &ip.octets()),
            }
        }
        put(
            macos::INSI_VFLAG,
            &[if local.is_ipv4() {
                macos::INI_IPV4
            } else {
                macos::INI_IPV6
            }],
        );
        record
    }

    #[test]
    fn socket_fdinfo_gives_tcp_endpoints() {
        for (local, remote) in [
            ("127.0.0.1:50043", "127.0.0.1:8888"),
            ("[::1]:50044", "[::1]:8888"),
        ] {
            let record = socket_fdinfo(macos::SOCKINFO_TCP, addr(local), addr(remote));
            assert_eq!(
                macos::parse_socket_fdinfo(&record).unwrap(),
                Some(macos::TcpSocket {
                    local: addr(local),
                    remote: addr(remote),
                    state: macos::TSI_S_ESTABLISHED,
                })
            );
        }
        // Not a TCP socket (`SOCKINFO_IN`: UDP).
        let udp = socket_fdinfo(1, addr("127.0.0.1:53"), addr("127.0.0.1:50043"));
        assert_eq!(macos::parse_socket_fdinfo(&udp).unwrap(), None);
    }

    /// The layout and constants, as literal numbers: `offsetof`, `sizeof`
    /// and the `#define`s of `sys/proc_info.h` in the MacOSX14.0 SDK,
    /// measured for arm64 and x86_64 alike.
    #[test]
    fn socket_fdinfo_layout_matches_the_header() {
        assert_eq!(macos::SOCKET_FDINFO_LEN, 792);
        assert_eq!(macos::SOI_KIND, 256);
        assert_eq!(macos::SOI_PROTO, 264);
        assert_eq!(macos::INSI_FPORT, 264);
        assert_eq!(macos::INSI_LPORT, 268);
        assert_eq!(macos::INSI_VFLAG, 288);
        assert_eq!(macos::INSI_FADDR, 296);
        assert_eq!(macos::INSI_LADDR, 312);
        assert_eq!(macos::IN_ADDR_4IN6_OFFSET, 12);
        assert_eq!(macos::TCPSI_STATE, 344);
        assert_eq!(macos::SOCKINFO_TCP, 2);
        assert_eq!(macos::INI_IPV4, 1);
        assert_eq!(macos::INI_IPV6, 2);
        assert_eq!(macos::TSI_S_ESTABLISHED, 4);
        assert_eq!(macos::TSI_S_CLOSE_WAIT, 5);
        assert_eq!(macos::TSI_S_FIN_WAIT_1, 6);
        assert_eq!(macos::TSI_S_FIN_WAIT_2, 9);
    }

    /// An established TCP socket 50043 -> 8888, written byte by byte at the
    /// header's offsets without the parser's constants.
    fn handwritten_socket_fdinfo(vflag: u8, laddr: [u8; 16], faddr: [u8; 16]) -> Vec<u8> {
        // An `int` holding the network-order `u_short`.
        let port = |port: u16| i32::from(port.to_be()).to_ne_bytes();
        let mut record = vec![0u8; 792];
        record[256..260].copy_from_slice(&2i32.to_ne_bytes()); // soi_kind: SOCKINFO_TCP
        record[264..268].copy_from_slice(&port(8888)); // insi_fport
        record[268..272].copy_from_slice(&port(50043)); // insi_lport
        record[288] = vflag; // insi_vflag
        record[296..312].copy_from_slice(&faddr); // insi_faddr
        record[312..328].copy_from_slice(&laddr); // insi_laddr
        record[344..348].copy_from_slice(&4i32.to_ne_bytes()); // tcpsi_state: ESTABLISHED
        record
    }

    /// An IPv4 address in a `struct in4in6_addr`: after 12 bytes of padding.
    fn in4in6(ip: [u8; 4]) -> [u8; 16] {
        let mut union = [0u8; 16];
        union[12..].copy_from_slice(&ip);
        union
    }

    #[test]
    fn handwritten_ipv4_socket_fdinfo_parses() {
        let local = in4in6([127, 0, 0, 1]);
        let remote = in4in6([127, 0, 0, 2]);
        // INI_IPV4, then both flags (an IPv6 socket talking IPv4): the
        // addresses are read as IPv4 either way.
        for vflag in [0x1, 0x3] {
            let record = handwritten_socket_fdinfo(vflag, local, remote);
            let socket = macos::parse_socket_fdinfo(&record).unwrap().unwrap();
            assert_eq!(socket.local, addr("127.0.0.1:50043"), "{vflag}");
            assert_eq!(socket.remote, addr("127.0.0.2:8888"), "{vflag}");
            assert!(socket.local.is_ipv4() && socket.remote.is_ipv4());
            assert_eq!(socket.state, 4);
        }
    }

    #[test]
    fn handwritten_ipv6_socket_fdinfo_parses() {
        let local = "::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
        let remote = "::2".parse::<std::net::Ipv6Addr>().unwrap().octets();
        let record = handwritten_socket_fdinfo(0x2, local, remote);
        let socket = macos::parse_socket_fdinfo(&record).unwrap().unwrap();
        assert_eq!(socket.local, addr("[::1]:50043"));
        assert_eq!(socket.remote, addr("[::2]:8888"));
        assert_eq!(socket.state, 4);
    }

    /// `struct socket_fdinfo` records of the client end of a loopback
    /// connection, captured with `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` on
    /// macOS 27.0.1 (26A434), Apple silicon, on jeremys-mac, 19 Oct 2026.
    /// Their opaque words (`soi_so`, `soi_pcb`, ...) are scrambled kernel
    /// addresses and are not read. Integers are little-endian.
    #[cfg(target_endian = "little")]
    const MACOS27_SOCKET_FDINFO_V4: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macos27-socket-fdinfo-v4.bin"
    ));
    #[cfg(target_endian = "little")]
    const MACOS27_SOCKET_FDINFO_V6: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/macos27-socket-fdinfo-v6.bin"
    ));

    #[cfg(target_endian = "little")]
    #[test]
    fn captured_ipv4_socket_fdinfo_parses() {
        assert_eq!(MACOS27_SOCKET_FDINFO_V4.len(), 792);
        let socket = macos::parse_socket_fdinfo(MACOS27_SOCKET_FDINFO_V4)
            .unwrap()
            .unwrap();
        assert_eq!(socket.local, addr("127.0.0.1:57616"));
        assert_eq!(socket.remote, addr("127.0.0.1:57615"));
        assert!(socket.local.is_ipv4() && socket.remote.is_ipv4());
        assert_eq!(socket.state, 4);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn captured_ipv6_socket_fdinfo_parses() {
        assert_eq!(MACOS27_SOCKET_FDINFO_V6.len(), 792);
        let socket = macos::parse_socket_fdinfo(MACOS27_SOCKET_FDINFO_V6)
            .unwrap()
            .unwrap();
        assert_eq!(socket.local, addr("[::1]:57618"));
        assert_eq!(socket.remote, addr("[::1]:57617"));
        assert!(socket.local.is_ipv6() && socket.remote.is_ipv6());
        assert_eq!(socket.state, 4);
    }

    #[test]
    fn socket_fdinfo_of_another_size_is_refused() {
        let record = socket_fdinfo(
            macos::SOCKINFO_TCP,
            addr("127.0.0.1:50043"),
            addr("127.0.0.1:8888"),
        );
        assert!(macos::parse_socket_fdinfo(&record[..record.len() - 1]).is_err());
        let mut longer = record.clone();
        longer.push(0);
        assert!(macos::parse_socket_fdinfo(&longer).is_err());
        assert!(macos::parse_socket_fdinfo(&[]).is_err());
    }

    const OWN_PID: i32 = 42;
    const LISTENER: &str = "127.0.0.1:8888";

    /// The sockets of a few processes; see `holder_uid` for their owners.
    fn process_sockets() -> Vec<macos::ProcessSocket> {
        let socket_in = |state, pid, local, remote| macos::ProcessSocket {
            pid,
            socket: macos::TcpSocket {
                local: addr(local),
                remote: addr(remote),
                state,
            },
        };
        let socket = |pid, local, remote| socket_in(macos::TSI_S_ESTABLISHED, pid, local, remote);
        vec![
            // A client of the listener, and Warpgate's accepted end of it.
            socket(100, "127.0.0.1:50043", LISTENER),
            socket(OWN_PID, LISTENER, "127.0.0.1:50043"),
            // A client socket held by Warpgate's own process.
            socket(OWN_PID, "127.0.0.1:50060", LISTENER),
            // The same local port, talking to another port.
            socket(101, "127.0.0.1:50044", "127.0.0.1:9999"),
            socket(102, "[::1]:50045", "[::1]:8888"),
            // One socket in two processes of the same account...
            socket(103, "127.0.0.1:50046", LISTENER),
            socket(104, "127.0.0.1:50046", LISTENER),
            // ...of two accounts...
            socket(105, "127.0.0.1:50047", LISTENER),
            socket(106, "127.0.0.1:50047", LISTENER),
            // ...and in a process that has exited since.
            socket(107, "127.0.0.1:50048", LISTENER),
            socket(108, "127.0.0.1:50048", LISTENER),
            // The same port on another local address.
            socket(109, "127.0.0.2:50049", LISTENER),
            // A socket of this account that is closed (`TSI_S_CLOSED`).
            socket_in(0, 110, "127.0.0.1:50061", LISTENER),
        ]
    }

    fn holder_uid(pid: i32) -> anyhow::Result<Option<u32>> {
        Ok(match pid {
            100..=105 | 107 | 110 => Some(501),
            106 => Some(502),
            108 => None,
            109 => Some(503),
            other => panic!("asked for the uid of process {other}"),
        })
    }

    fn find_in_processes(local: &str, remote: &str) -> anyhow::Result<Option<u32>> {
        macos::find_owner(
            &process_sockets(),
            OWN_PID,
            addr(local),
            addr(remote),
            holder_uid,
        )
    }

    #[test]
    fn process_sockets_find_the_client_socket_owner() {
        let find = |local, remote| find_in_processes(local, remote).unwrap();
        assert_eq!(find("127.0.0.1:50043", LISTENER), Some(501));
        assert_eq!(find("[::1]:50045", "[::1]:8888"), Some(501));
        // An IPv4 socket, asked for with IPv4-mapped addresses.
        assert_eq!(
            find("[::ffff:127.0.0.1]:50043", "[::ffff:127.0.0.1]:8888"),
            Some(501)
        );
        // Unknown endpoints match nothing.
        assert_eq!(find("127.0.0.1:50099", LISTENER), None);
    }

    #[test]
    fn process_sockets_match_the_full_four_tuple() {
        let find = |local, remote| find_in_processes(local, remote).unwrap();
        // Wrong remote port, wrong remote address, wrong local address.
        assert_eq!(find("127.0.0.1:50044", LISTENER), None);
        assert_eq!(find("127.0.0.1:50043", "127.0.0.2:8888"), None);
        assert_eq!(find("127.0.0.1:50049", LISTENER), None);
        assert_eq!(find("127.0.0.2:50049", LISTENER), Some(503));
    }

    #[test]
    fn process_sockets_count_only_connected_sockets() {
        // Established: found. Closed, its only holder ours: not found.
        assert_eq!(
            find_in_processes("127.0.0.1:50043", LISTENER).unwrap(),
            Some(501)
        );
        assert_eq!(
            find_in_processes("127.0.0.1:50061", LISTENER).unwrap(),
            None
        );
        for state in 0..=11 {
            let sockets = [macos::ProcessSocket {
                pid: 100,
                socket: macos::TcpSocket {
                    local: addr("127.0.0.1:50043"),
                    remote: addr(LISTENER),
                    state,
                },
            }];
            let owner = macos::find_owner(
                &sockets,
                OWN_PID,
                addr("127.0.0.1:50043"),
                addr(LISTENER),
                holder_uid,
            )
            .unwrap();
            // ESTABLISHED, CLOSE_WAIT, FIN_WAIT_1 and FIN_WAIT_2 hold a
            // connection; CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, CLOSING,
            // LAST_ACK, TIME_WAIT and anything else do not.
            let connected = matches!(state, 4 | 5 | 6 | 9);
            assert_eq!(owner, connected.then_some(501), "state {state}");
        }
    }

    #[test]
    fn process_sockets_of_our_own_process_are_skipped() {
        let find = |local, remote| find_in_processes(local, remote).unwrap();
        assert_eq!(find("127.0.0.1:50060", LISTENER), None);
        // Warpgate's accepted end, asked for as a client, is skipped too.
        assert_eq!(find(LISTENER, "127.0.0.1:50043"), None);
    }

    #[test]
    fn process_sockets_with_several_holders_need_one_owner() {
        assert_eq!(
            find_in_processes("127.0.0.1:50046", LISTENER).unwrap(),
            Some(501)
        );
        assert!(find_in_processes("127.0.0.1:50047", LISTENER).is_err());
        // A holder that has exited is passed over.
        assert_eq!(
            find_in_processes("127.0.0.1:50048", LISTENER).unwrap(),
            Some(501)
        );
    }

    #[test]
    fn process_sockets_whose_holder_cannot_be_read_are_refused() {
        let result = macos::find_owner(
            &process_sockets(),
            OWN_PID,
            addr("127.0.0.1:50043"),
            addr(LISTENER),
            |_| Err(anyhow::anyhow!("not permitted")),
        );
        assert!(result.is_err());
    }

    /// The process walk through the owner check: a client of another
    /// account, or none, is refused.
    #[tokio::test]
    async fn process_sockets_through_the_owner_check() {
        struct Processes;
        impl SocketOwnerLookup for Processes {
            fn owner_uid(
                &self,
                local: SocketAddr,
                remote: SocketAddr,
            ) -> anyhow::Result<Option<u32>> {
                macos::find_owner(&process_sockets(), OWN_PID, local, remote, holder_uid)
            }
        }
        let check = |our_uid, client| {
            check_connection_owner(Arc::new(Processes), our_uid, addr(LISTENER), addr(client))
        };
        assert_eq!(check(501, "127.0.0.1:50043").await, OwnerCheck::SameAccount);
        assert_eq!(
            check(502, "127.0.0.1:50043").await,
            OwnerCheck::OtherAccount(501)
        );
        assert_eq!(check(501, "127.0.0.1:50099").await, OwnerCheck::NotFound);
        assert!(matches!(
            check(501, "127.0.0.1:50047").await,
            OwnerCheck::LookupFailed(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn only_gone_and_uninspectable_processes_are_passed_over() {
        for errno in [0, libc::ESRCH, libc::EBADF, libc::EPERM] {
            assert!(macos::is_out_of_reach(Some(errno)), "{errno}");
        }
        for errno in [libc::EACCES, libc::EINVAL, libc::ENOMEM] {
            assert!(!macos::is_out_of_reach(Some(errno)), "{errno}");
        }
        assert!(!macos::is_out_of_reach(None));
    }

    /// A connection from this process, looked up through `sock_diag` and
    /// through `/proc/net/tcp`: both find it under this process's uid, and
    /// `detect` picks `sock_diag`. Covers IPv4, IPv6, and an IPv6 socket
    /// connected to an IPv4 listener through a mapped address, which the
    /// listener sees as plain IPv4.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sock_diag_and_proc_tables_find_our_own_connection() {
        assert!(KernelSocketTable::detect().sock_diag);
        let our_uid = effective_uid().unwrap();
        for (bind, connect_from_v6) in [
            ("127.0.0.1:0", false),
            ("[::1]:0", false),
            ("127.0.0.1:0", true),
        ] {
            let Ok(listener) = tokio::net::TcpListener::bind(bind).await else {
                // No IPv6 loopback on this machine.
                continue;
            };
            let listen_address = listener.local_addr().unwrap();
            let client = if connect_from_v6 {
                let Ok(socket) = tokio::net::TcpSocket::new_v6() else {
                    continue;
                };
                let mapped = SocketAddr::new(
                    IpAddr::V6(match listen_address.ip() {
                        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                        IpAddr::V6(ip) => ip,
                    }),
                    listen_address.port(),
                );
                socket.connect(mapped).await.unwrap()
            } else {
                tokio::net::TcpStream::connect(listen_address)
                    .await
                    .unwrap()
            };
            let (_server, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.port(), client.local_addr().unwrap().port());

            // The listener's view: the client is `peer`, the listener is
            // `listen_address`; the client socket's own view is the swap.
            assert_eq!(
                linux::sock_diag::owner_uid(peer, listen_address).unwrap(),
                Some(our_uid),
                "sock_diag {bind} v6:{connect_from_v6}"
            );
            assert_eq!(
                linux::owner_uid(peer, listen_address).unwrap(),
                Some(our_uid),
                "/proc {bind} v6:{connect_from_v6}"
            );
            // An endpoint nobody holds is not found.
            let unused = SocketAddr::new(peer.ip(), 1);
            assert_eq!(
                linux::sock_diag::owner_uid(unused, listen_address).unwrap(),
                None,
                "{bind} v6:{connect_from_v6}"
            );
        }
    }

    /// The listening socket is not the client: asked for endpoints whose
    /// local one is a listener's, `sock_diag` falls back to the listener,
    /// which is passed over.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sock_diag_does_not_take_a_listener_for_the_client() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_address = listener.local_addr().unwrap();
        let elsewhere = addr("127.0.0.1:9");
        assert_eq!(
            linux::sock_diag::owner_uid(listen_address, elsewhere).unwrap(),
            None
        );
    }

    fn sock_diag_reply(
        seq: u32,
        family: u8,
        state: u8,
        local: SocketAddr,
        remote: SocketAddr,
        uid: u32,
        inode: u32,
    ) -> Vec<u8> {
        use linux::sock_diag::{MSG_LEN, NLMSG_HDRLEN};
        let address = |ip: IpAddr| -> [u8; 16] {
            match ip {
                IpAddr::V4(ip) => {
                    let mut words = [0u8; 16];
                    words
                        .iter_mut()
                        .zip(ip.octets())
                        .for_each(|(out, byte)| *out = byte);
                    words
                }
                IpAddr::V6(ip) => ip.octets(),
            }
        };
        let mut out = Vec::new();
        out.extend_from_slice(&u32::try_from(NLMSG_HDRLEN + MSG_LEN).unwrap().to_ne_bytes());
        out.extend_from_slice(&20u16.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&[family, state, 0, 0]);
        out.extend_from_slice(&local.port().to_be_bytes());
        out.extend_from_slice(&remote.port().to_be_bytes());
        out.extend_from_slice(&address(local.ip()));
        out.extend_from_slice(&address(remote.ip()));
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&[0u8; 8]);
        // Expires, receive and send queues.
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&uid.to_ne_bytes());
        out.extend_from_slice(&inode.to_ne_bytes());
        assert_eq!(out.len(), NLMSG_HDRLEN + MSG_LEN);
        out
    }

    fn sock_diag_error(seq: u32, errno: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&36u32.to_ne_bytes());
        out.extend_from_slice(&2u16.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&(-errno).to_ne_bytes());
        // The request's own header, echoed back.
        out.extend_from_slice(&[0u8; 16]);
        out
    }

    #[test]
    fn sock_diag_request_asks_for_exactly_the_client_socket() {
        use linux::sock_diag::{AF_INET, AF_INET6, NLMSG_HDRLEN, REQ_LEN, request};
        let (local, remote) = (addr("127.0.0.1:50123"), addr("127.0.0.2:8888"));
        let bytes = request(local, remote, 7).unwrap();
        assert_eq!(bytes.len(), NLMSG_HDRLEN + REQ_LEN);
        let at = |from: usize, to: usize| bytes.get(from..to).unwrap().to_vec();
        assert_eq!(at(0, 4), 72u32.to_ne_bytes());
        // SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST only (one socket, no dump).
        assert_eq!(at(4, 6), 20u16.to_ne_bytes());
        assert_eq!(at(6, 8), 1u16.to_ne_bytes());
        assert_eq!(at(8, 12), 7u32.to_ne_bytes());
        assert_eq!(at(16, 20), [AF_INET, 6, 0, 0]);
        assert_eq!(at(20, 24), u32::MAX.to_ne_bytes());
        assert_eq!(at(24, 26), 50123u16.to_be_bytes());
        assert_eq!(at(26, 28), 8888u16.to_be_bytes());
        assert_eq!(
            at(28, 44),
            [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            at(44, 60),
            [127, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(at(60, 64), [0; 4]);
        assert_eq!(at(64, 72), [0xff; 8]);

        // IPv6, and IPv4-mapped addresses asked for as the IPv4 they are.
        let bytes = request(addr("[::1]:50123"), addr("[::1]:8888"), 8).unwrap();
        assert_eq!(bytes.get(16), Some(&AF_INET6));
        assert_eq!(
            bytes.get(28..44).unwrap(),
            std::net::Ipv6Addr::LOCALHOST.octets()
        );
        let bytes = request(addr("[::ffff:127.0.0.1]:50123"), addr("127.0.0.1:8888"), 9).unwrap();
        assert_eq!(bytes.get(16), Some(&AF_INET));

        // No socket has an IPv4 and an IPv6 end.
        assert!(request(addr("127.0.0.1:1"), addr("[::1]:2"), 1).is_none());
    }

    #[test]
    fn sock_diag_reply_gives_the_client_socket_owner() {
        use linux::sock_diag::{AF_INET, AF_INET6, TCP_LISTEN, parse_reply};
        let (local, remote) = (addr("127.0.0.1:50123"), addr("127.0.0.1:8888"));
        let established = 1;
        let parse = |reply: Vec<u8>| parse_reply(&reply, 5, local, remote);

        let found = sock_diag_reply(5, AF_INET, established, local, remote, 501, 4242);
        assert_eq!(parse(found).unwrap(), Some(501));
        // An IPv6 socket on mapped addresses is the same connection.
        let mapped = sock_diag_reply(
            5,
            AF_INET6,
            established,
            addr("[::ffff:127.0.0.1]:50123"),
            addr("[::ffff:127.0.0.1]:8888"),
            501,
            4242,
        );
        assert_eq!(parse(mapped).unwrap(), Some(501));

        // No such socket.
        assert_eq!(parse(sock_diag_error(5, 2)).unwrap(), None);
        // A socket with no descriptor behind it, a listener the kernel fell
        // back to, and a socket with other endpoints belong to no one.
        let no_descriptor = sock_diag_reply(5, AF_INET, established, local, remote, 0, 0);
        assert_eq!(parse(no_descriptor).unwrap(), None);
        let listening = sock_diag_reply(5, AF_INET, TCP_LISTEN, local, remote, 502, 4243);
        assert_eq!(parse(listening).unwrap(), None);
        let other = sock_diag_reply(
            5,
            AF_INET,
            established,
            addr("127.0.0.1:50124"),
            remote,
            502,
            4244,
        );
        assert_eq!(parse(other).unwrap(), None);

        // Anything else fails the lookup, which refuses the connection.
        // EACCES.
        assert!(parse(sock_diag_error(5, 13)).is_err());
        assert!(
            parse(sock_diag_reply(
                6,
                AF_INET,
                established,
                local,
                remote,
                501,
                1
            ))
            .is_err()
        );
        assert!(parse(vec![0u8; 8]).is_err());
        let mut truncated = sock_diag_reply(5, AF_INET, established, local, remote, 501, 1);
        truncated.truncate(40);
        assert!(parse(truncated).is_err());
    }

    /// However many connections arrive at once, no more than
    /// `MAX_CONCURRENT_LOOKUPS` lookups run together; the others wait their
    /// turn and are still answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lookups_run_at_most_the_cap_at_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct SlowLookup {
            running: AtomicUsize,
            most: AtomicUsize,
        }

        impl SocketOwnerLookup for SlowLookup {
            fn owner_uid(
                &self,
                _local: SocketAddr,
                _remote: SocketAddr,
            ) -> anyhow::Result<Option<u32>> {
                let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
                self.most.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                self.running.fetch_sub(1, Ordering::SeqCst);
                Ok(Some(501))
            }
        }

        let lookup = Arc::new(SlowLookup {
            running: AtomicUsize::new(0),
            most: AtomicUsize::new(0),
        });
        let (local, remote) = (addr("127.0.0.1:8888"), addr("127.0.0.1:50123"));
        let checks = (0..MAX_CONCURRENT_LOOKUPS * 3).map(|_| {
            let lookup: Arc<dyn SocketOwnerLookup> = lookup.clone();
            tokio::spawn(check_connection_owner(lookup, 501, local, remote))
        });
        for check in checks.collect::<Vec<_>>() {
            assert_eq!(check.await.unwrap(), OwnerCheck::SameAccount);
        }
        let most = lookup.most.load(Ordering::SeqCst);
        assert!(most <= MAX_CONCURRENT_LOOKUPS, "{most} lookups ran at once");
    }
}
