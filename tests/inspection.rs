use netsock::family::AddressFamilyFlags as Families;
use netsock::protocol::ProtocolFlags as Protocols;
use netsock::state::TcpState;
use netsock::{get_sockets, iter_sockets_without_processes};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::process;

#[test]
fn loopback_endpoints_states_and_owners() {
    for (ip, family) in [
        (IpAddr::V4(Ipv4Addr::LOCALHOST), Families::IPV4),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), Families::IPV6),
    ] {
        let listener = TcpListener::bind((ip, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (mut server, peer) = listener.accept().unwrap();
        let udp = UdpSocket::bind((ip, 0)).unwrap();
        let duplicate = udp.try_clone().unwrap();
        let port = udp.local_addr().unwrap().port();
        let sockets = get_sockets(family, Protocols::all()).unwrap();
        assert!(
            sockets
                .iter()
                .all(|s| s.local_addr().is_ipv4() == ip.is_ipv4())
        );
        let owned: Vec<_> = sockets
            .iter()
            .filter(|s| s.is_owned_by_pid(process::id()))
            .collect();
        let udp_rows: Vec<_> = owned
            .iter()
            .filter(|s| s.is_udp() && s.local_addr() == ip && s.local_port() == port)
            .collect();
        assert_eq!(udp_rows.len(), 1);
        assert_eq!(
            udp_rows[0]
                .processes
                .iter()
                .filter(|p| p.pid == process::id())
                .count(),
            1
        );
        assert!(
            udp_rows[0]
                .processes
                .iter()
                .any(|p| p.pid == process::id() && !p.name.is_empty())
        );
        assert!(
            owned
                .iter()
                .filter_map(|s| s.tcp_info())
                .any(|s| s.local_port == address.port()
                    && s.state == TcpState::Listen
                    && s.remote_port == 0
                    && s.remote_addr.is_unspecified())
        );
        assert!(
            owned
                .iter()
                .filter_map(|s| s.tcp_info())
                .any(|s| s.local_addr == ip
                    && s.local_port == address.port()
                    && s.remote_addr == peer.ip()
                    && s.remote_port == peer.port()
                    && s.state == TcpState::Established)
        );

        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(std::io::Read::read(&mut server, &mut [0u8; 1]).unwrap(), 0);
        let tcp = get_sockets(family, Protocols::TCP).unwrap();
        assert!(
            tcp.iter()
                .filter_map(|s| s.tcp_info())
                .any(|s| s.local_port == address.port()
                    && s.remote_port == peer.port()
                    && s.state == TcpState::CloseWait)
        );

        let raw: Vec<_> = iter_sockets_without_processes(family, Protocols::UDP)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(raw.iter().all(|s| s.is_udp() && s.processes.is_empty()));
        assert!(
            raw.iter()
                .any(|s| s.local_addr() == ip && s.local_port() == port)
        );
        drop((duplicate, server, client));
    }
}

#[test]
fn empty_filters_return_no_rows() {
    assert!(
        get_sockets(Families::empty(), Protocols::all())
            .unwrap()
            .is_empty()
    );
    assert!(
        get_sockets(Families::all(), Protocols::empty())
            .unwrap()
            .is_empty()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn complete_multipart_udp_dump() {
    use std::collections::HashSet;
    let sockets: Vec<_> = (0..160)
        .map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect();
    let mut missing: HashSet<_> = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect();
    for info in iter_sockets_without_processes(Families::IPV4, Protocols::UDP).unwrap() {
        let s = info.unwrap();
        if s.local_addr() == Ipv4Addr::LOCALHOST {
            missing.remove(&s.local_port());
        }
    }
    assert!(missing.is_empty(), "missing {} sockets", missing.len());
}

#[cfg(unix)]
#[test]
fn shared_socket_has_both_process_owners() {
    use std::os::fd::OwnedFd;
    use std::process::{Command, Stdio};

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let descriptor = OwnedFd::from(socket.try_clone().unwrap());
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(descriptor))
        .spawn()
        .unwrap();
    let pid = child.id();
    let snapshot = get_sockets(Families::IPV4, Protocols::UDP);
    drop(child.stdin.take());
    child.wait().unwrap();
    let snapshot = snapshot.unwrap();
    let port = socket.local_addr().unwrap().port();
    let rows: Vec<_> = snapshot
        .iter()
        .filter(|s| s.local_port() == port && s.local_addr() == Ipv4Addr::LOCALHOST)
        .collect();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_owned_by_pid(pid));
    assert!(rows[0].is_owned_by_pid(process::id()));
}

#[cfg(target_os = "linux")]
#[test]
fn cache_refresh_preserves_existing_snapshots() {
    use netsock::{ProcessCache, iter_sockets_with_cache};
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut cache = ProcessCache::default();
    let original = cache.clone();
    cache.refresh().unwrap();
    let row = iter_sockets_with_cache(Families::IPV4, Protocols::UDP, cache.clone())
        .unwrap()
        .map(Result::unwrap)
        .find(|s| s.local_port() == port && s.local_addr() == Ipv4Addr::LOCALHOST)
        .unwrap();
    assert!(row.is_owned_by_pid(process::id()));
    assert_eq!(cache.processes(row.inode).unwrap().as_ref(), row.processes);
    assert!(original.processes(row.inode).is_none());
}
