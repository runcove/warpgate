//! On a plain-HTTP loopback listener (`http.plain_http_on_loopback`), a
//! connection is served only when the connecting socket belongs to the OS
//! account Warpgate runs as. Other accounts on the same machine can reach the
//! loopback interface too; their connections are closed before any HTTP is
//! read.
//!
//! The owner comes from the kernel's socket table: the client socket is the
//! one whose local endpoint is the accepted connection's remote endpoint and
//! whose remote endpoint is the listener's. A lookup that fails, times out or
//! finds no such socket refuses the connection.
//!
//! Limits of the check:
//! - TCP carries no peer credentials: the owner is looked up by address and
//!   port after the connection is accepted.
//! - Every process of the account is trusted, relays included: an `ssh -R`
//!   forward, a proxy the account runs, a target pointing back at this
//!   listener. Whoever reaches such a relay is served as the account.
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
const MAX_SOCKET_TABLE_BYTES: usize = 16 * 1024 * 1024;

/// How long one lookup may take before the connection is refused.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Finds the OS account owning a TCP socket.
pub(crate) trait SocketOwnerLookup: Send + Sync + 'static {
    /// The uid owning the TCP socket whose local endpoint is `local` and whose
    /// remote endpoint is `remote`, or `None` when the table lists no such
    /// socket. Blocking: called off the async executor.
    fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>>;
}

/// The kernel's own socket table: `/proc/net/tcp{,6}` on Linux,
/// `net.inet.tcp.pcblist_n` on macOS.
pub(crate) struct KernelSocketTable;

impl SocketOwnerLookup for KernelSocketTable {
    #[cfg(target_os = "linux")]
    fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>> {
        linux::owner_uid(local, remote)
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

/// The uid a plain-HTTP loopback listener serves: this process's effective
/// uid, refused when it is root's.
pub(crate) fn listener_uid() -> anyhow::Result<u32> {
    serving_uid(effective_uid()?)
}

/// `uid`, unless it is root's: root owns system services' sockets as well,
/// and the kernel lists sockets with no process behind them under uid 0, so
/// serving root's connections would not tell them apart.
fn serving_uid(uid: u32) -> anyhow::Result<u32> {
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
/// `local` (as seen by the listener), off the async executor and within
/// [`LOOKUP_TIMEOUT`].
pub(crate) async fn check_connection_owner(
    lookup: Arc<dyn SocketOwnerLookup>,
    our_uid: u32,
    local: SocketAddr,
    remote: SocketAddr,
) -> OwnerCheck {
    // The client socket's endpoints are the accepted connection's, swapped.
    let task = tokio::task::spawn_blocking(move || lookup.owner_uid(remote, local));
    match tokio::time::timeout(LOOKUP_TIMEOUT, task).await {
        Err(_) => OwnerCheck::LookupFailed("timed out".into()),
        Ok(Err(error)) => OwnerCheck::LookupFailed(error.to_string()),
        Ok(Ok(Err(error))) => OwnerCheck::LookupFailed(format!("{error:#}")),
        Ok(Ok(Ok(None))) => OwnerCheck::NotFound,
        Ok(Ok(Ok(Some(uid)))) if uid == our_uid => OwnerCheck::SameAccount,
        Ok(Ok(Ok(Some(uid)))) => OwnerCheck::OtherAccount(uid),
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
}

/// `net.inet.tcp.pcblist_n`: a `struct xinpgen` header, then for each socket
/// a run of records (`xinpcb_n`, `xsocket_n`, buffers, stats, `xtcpcb_n`),
/// each starting with its length and kind and padded to 8 bytes, then a
/// closing `xinpgen`. Field offsets follow the kernel's `#pragma pack(4)`
/// layouts in `netinet/in_pcb.h` and `sys/socketvar.h`.
#[cfg(any(test, target_os = "macos"))]
mod macos {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use anyhow::Context;

    use super::{same_endpoint, single_owner};

    pub(super) const XSO_SOCKET: u32 = 0x001;
    pub(super) const XSO_INPCB: u32 = 0x010;
    pub(super) const INP_IPV4: u8 = 0x1;
    pub(super) const INP_IPV6: u8 = 0x2;

    /// `sizeof(struct xinpgen)`; a record no longer than this ends the list.
    pub(super) const XINPGEN_LEN: usize = 24;

    // `struct xinpcb_n`.
    pub(super) const INPCB_FPORT: usize = 16;
    pub(super) const INPCB_LPORT: usize = 18;
    pub(super) const INPCB_VFLAG: usize = 44;
    pub(super) const INPCB_FADDR: usize = 48;
    pub(super) const INPCB_LADDR: usize = 64;
    /// Within an address union, where an IPv4 address sits (`ia46_addr4`).
    pub(super) const IN_ADDR_4IN6_OFFSET: usize = 12;
    const INPCB_MIN_LEN: usize = INPCB_LADDR + 16;

    // `struct xsocket_n`.
    pub(super) const SOCKET_SO: usize = 8;
    pub(super) const SOCKET_UID: usize = 64;
    const SOCKET_MIN_LEN: usize = SOCKET_UID + 4;

    #[cfg(target_os = "macos")]
    pub(super) fn owner_uid(local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<u32>> {
        let table = read_pcblist()?;
        find_owner(&table, local, remote)
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn read_pcblist() -> anyhow::Result<Vec<u8>> {
        use super::MAX_SOCKET_TABLE_BYTES;

        const NAME: &std::ffi::CStr = c"net.inet.tcp.pcblist_n";
        // The table may grow between sizing and reading it; the kernel's
        // size estimate leaves room, and a few retries cover the rest.
        for _ in 0..3 {
            let mut size: libc::size_t = 0;
            // SAFETY: a size query: no output buffer, and `size` is a valid
            // pointer for the length.
            let rc = unsafe {
                libc::sysctlbyname(
                    NAME.as_ptr(),
                    std::ptr::null_mut(),
                    &raw mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error()).context("sizing the socket table");
            }
            if size > MAX_SOCKET_TABLE_BYTES {
                anyhow::bail!("the socket table is larger than {MAX_SOCKET_TABLE_BYTES} bytes");
            }
            let mut table = vec![0u8; size];
            let mut read = size;
            // SAFETY: `table` is writable for `read` bytes, and the kernel
            // writes at most that many, storing the count back into `read`.
            let rc = unsafe {
                libc::sysctlbyname(
                    NAME.as_ptr(),
                    table.as_mut_ptr().cast(),
                    &raw mut read,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc == 0 {
                table.truncate(read.min(size));
                return Ok(table);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOMEM) {
                return Err(error).context("reading the socket table");
            }
        }
        anyhow::bail!("the socket table kept growing while it was read")
    }

    fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
        let bytes = buf.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_ne_bytes(bytes.try_into().ok()?))
    }

    fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
        let bytes = buf.get(offset..offset.checked_add(8)?)?;
        Some(u64::from_ne_bytes(bytes.try_into().ok()?))
    }

    /// A port, stored in network order.
    fn read_port(buf: &[u8], offset: usize) -> Option<u16> {
        let bytes = buf.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_be_bytes(bytes.try_into().ok()?))
    }

    fn read_address(record: &[u8], union_offset: usize, vflag: u8) -> Option<IpAddr> {
        if vflag & INP_IPV4 != 0 {
            let start = union_offset + IN_ADDR_4IN6_OFFSET;
            let bytes: [u8; 4] = record.get(start..start + 4)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        } else if vflag & INP_IPV6 != 0 {
            let bytes: [u8; 16] = record
                .get(union_offset..union_offset + 16)?
                .try_into()
                .ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        } else {
            None
        }
    }

    /// An `xinpcb_n`'s (local, remote) endpoints.
    fn parse_inpcb(record: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
        if record.len() < INPCB_MIN_LEN {
            return None;
        }
        let vflag = *record.get(INPCB_VFLAG)?;
        let local = SocketAddr::new(
            read_address(record, INPCB_LADDR, vflag)?,
            read_port(record, INPCB_LPORT)?,
        );
        let remote = SocketAddr::new(
            read_address(record, INPCB_FADDR, vflag)?,
            read_port(record, INPCB_FPORT)?,
        );
        Some((local, remote))
    }

    /// An `xsocket_n`'s owner uid; `None` for a PCB without a socket (its
    /// record is zeroed past the header).
    fn parse_socket(record: &[u8]) -> Option<u32> {
        if record.len() < SOCKET_MIN_LEN || read_u64(record, SOCKET_SO)? == 0 {
            return None;
        }
        read_u32(record, SOCKET_UID)
    }

    const fn round_up_8(n: usize) -> Option<usize> {
        match n.checked_add(7) {
            Some(n) => Some(n & !7),
            None => None,
        }
    }

    /// The owner of the socket with these endpoints in a `pcblist_n` buffer.
    pub(super) fn find_owner(
        table: &[u8],
        local: SocketAddr,
        remote: SocketAddr,
    ) -> anyhow::Result<Option<u32>> {
        let header_len = read_u32(table, 0).context("the socket table is empty")? as usize;
        let mut offset = round_up_8(header_len).context("bad socket table header")?;

        let mut uids = Vec::new();
        // The record kinds seen for the current socket, and what they said.
        let mut seen = 0u32;
        let mut endpoints = None;
        let mut owner = None;

        while offset < table.len() {
            let len = read_u32(table, offset).context("truncated socket table")? as usize;
            let kind = read_u32(table, offset + 4).context("truncated socket table")?;
            if len <= XINPGEN_LEN {
                break;
            }
            let end = offset.checked_add(len).context("bad socket table record")?;
            let record = table.get(offset..end).context("truncated socket table")?;

            // A kind seen twice starts the next socket's records.
            if seen & kind != 0 {
                seen = 0;
                endpoints = None;
                owner = None;
            }
            seen |= kind;
            match kind {
                XSO_INPCB => endpoints = parse_inpcb(record),
                XSO_SOCKET => owner = parse_socket(record),
                _ => {}
            }
            if seen & (XSO_INPCB | XSO_SOCKET) == XSO_INPCB | XSO_SOCKET
                && kind & (XSO_INPCB | XSO_SOCKET) != 0
                && let (Some((socket_local, socket_remote)), Some(uid)) = (endpoints, owner)
                && same_endpoint(socket_local, local)
                && same_endpoint(socket_remote, remote)
            {
                uids.push(uid);
            }

            offset = round_up_8(end)
                .filter(|next| *next > offset)
                .context("bad socket table record")?;
        }
        single_owner(uids)
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
    /// belongs to this process's account.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
            let check =
                check_connection_owner(Arc::new(KernelSocketTable), our_uid, listen_address, peer)
                    .await;
            assert_eq!(check, OwnerCheck::SameAccount, "{bind}");

            // An endpoint nobody holds is not found.
            let unused = SocketAddr::new(peer.ip(), 1);
            let check = check_connection_owner(
                Arc::new(KernelSocketTable),
                our_uid,
                listen_address,
                unused,
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

    /// Builds a `pcblist_n` buffer the way the kernel lays it out.
    struct PcbList(Vec<u8>);

    impl PcbList {
        fn new() -> Self {
            let mut list = Self(Vec::new());
            list.xinpgen();
            list
        }

        fn xinpgen(&mut self) {
            let mut record = vec![0u8; macos::XINPGEN_LEN];
            put_u32(&mut record, 0, macos::XINPGEN_LEN as u32);
            self.push(&record);
        }

        fn push(&mut self, record: &[u8]) {
            self.0.extend_from_slice(record);
            while self.0.len() % 8 != 0 {
                self.0.push(0);
            }
        }

        fn other(&mut self, kind: u32, len: usize) {
            let mut record = vec![0u8; len];
            put_u32(&mut record, 0, len as u32);
            put_u32(&mut record, 4, kind);
            self.push(&record);
        }

        /// One TCP socket's records, in the kernel's order.
        fn socket(&mut self, local: SocketAddr, remote: SocketAddr, uid: Option<u32>) {
            // sizeof(struct xinpcb_n) under pack(4).
            let mut inpcb = vec![0u8; 104];
            put_u32(&mut inpcb, 0, 104);
            put_u32(&mut inpcb, 4, macos::XSO_INPCB);
            inpcb[macos::INPCB_FPORT..macos::INPCB_FPORT + 2]
                .copy_from_slice(&remote.port().to_be_bytes());
            inpcb[macos::INPCB_LPORT..macos::INPCB_LPORT + 2]
                .copy_from_slice(&local.port().to_be_bytes());
            let mut put_address = |union_offset: usize, ip: IpAddr| match ip {
                IpAddr::V4(ip) => {
                    let start = union_offset + macos::IN_ADDR_4IN6_OFFSET;
                    inpcb[start..start + 4].copy_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    inpcb[union_offset..union_offset + 16].copy_from_slice(&ip.octets());
                }
            };
            put_address(macos::INPCB_FADDR, remote.ip());
            put_address(macos::INPCB_LADDR, local.ip());
            inpcb[macos::INPCB_VFLAG] = if local.is_ipv4() {
                macos::INP_IPV4
            } else {
                macos::INP_IPV6
            };
            self.push(&inpcb);

            // sizeof(struct xsocket_n) under pack(4).
            let mut socket = vec![0u8; 108];
            put_u32(&mut socket, 0, 108);
            put_u32(&mut socket, 4, macos::XSO_SOCKET);
            if let Some(uid) = uid {
                socket[macos::SOCKET_SO..macos::SOCKET_SO + 8]
                    .copy_from_slice(&0x1234_u64.to_ne_bytes());
                put_u32(&mut socket, macos::SOCKET_UID, uid);
            }
            self.push(&socket);

            self.other(0x002, 36); // receive buffer
            self.other(0x004, 36); // send buffer
            self.other(0x008, 420); // stats
            self.other(0x020, 260); // TCP control block
        }

        fn finish(mut self) -> Vec<u8> {
            self.xinpgen();
            self.0
        }
    }

    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    #[test]
    fn pcblist_finds_the_client_socket_owner() {
        let listener = addr("127.0.0.1:8888");
        let mut list = PcbList::new();
        list.socket(listener, addr("0.0.0.0:0"), Some(501));
        list.socket(addr("127.0.0.1:50043"), listener, Some(502));
        list.socket(listener, addr("127.0.0.1:50043"), Some(501));
        list.socket(addr("[::1]:50044"), addr("[::1]:8888"), Some(503));
        list.socket(addr("127.0.0.1:50045"), listener, None);
        let table = list.finish();

        let find = |local, remote| macos::find_owner(&table, addr(local), addr(remote)).unwrap();
        assert_eq!(find("127.0.0.1:50043", "127.0.0.1:8888"), Some(502));
        assert_eq!(find("127.0.0.1:8888", "127.0.0.1:50043"), Some(501));
        assert_eq!(find("[::1]:50044", "[::1]:8888"), Some(503));
        // A PCB without a socket has no owner.
        assert_eq!(find("127.0.0.1:50045", "127.0.0.1:8888"), None);
        assert_eq!(find("127.0.0.1:50046", "127.0.0.1:8888"), None);
        assert_eq!(find("127.0.0.1:50043", "127.0.0.1:8889"), None);
    }

    #[test]
    fn pcblist_refuses_disagreeing_and_malformed_tables() {
        let listener = addr("127.0.0.1:8888");
        let client = addr("127.0.0.1:50043");
        let mut list = PcbList::new();
        list.socket(client, listener, Some(501));
        list.socket(client, listener, Some(502));
        assert!(macos::find_owner(&list.finish(), client, listener).is_err());

        assert!(macos::find_owner(&[], client, listener).is_err());
        let mut list = PcbList::new();
        list.socket(client, listener, Some(501));
        let mut table = list.finish();
        // Cut inside the first record.
        table.truncate(macos::XINPGEN_LEN + 40);
        assert!(macos::find_owner(&table, client, listener).is_err());

        let header_only = PcbList::new().finish();
        assert_eq!(
            macos::find_owner(&header_only, client, listener).unwrap(),
            None
        );
    }
}
