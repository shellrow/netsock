use netsock::family::AddressFamilyFlags;
use netsock::iter_sockets;
use netsock::protocol::ProtocolFlags;
use netsock::socket::ProtocolSocketInfo;
use std::net::SocketAddr;

fn main() -> Result<(), netsock::error::Error> {
    for result in iter_sockets(AddressFamilyFlags::all(), ProtocolFlags::all())? {
        let socket = result?;
        let local = SocketAddr::new(socket.local_addr(), socket.local_port());
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                let remote = SocketAddr::new(tcp.remote_addr, tcp.remote_port);
                println!(
                    "TCP {local} -> {remote} {} {:?}",
                    tcp.state, socket.processes
                );
            }
            ProtocolSocketInfo::Udp(_) => println!("UDP {local} {:?}", socket.processes),
        }
    }
    Ok(())
}
