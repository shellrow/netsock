// This example demonstrates how to use the `netsock` crate to retrieve socket information
// for both IPv4 and IPv6 addresses and for TCP and UDP protocols.
use netsock::family::AddressFamilyFlags;
use netsock::protocol::ProtocolFlags; 
use netsock::socket::ProtocolSocketInfo;
use netsock::get_sockets;

fn main() {
    // Combine IPv4 and IPv6 address family flags to search for sockets across both families.
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;

    // Combine TCP and UDP protocol flags to search for both types of sockets.
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    // Call get_sockets with the specified address family and protocol flags.
    // This function returns a Result, which we match on to handle both the Ok and Err cases.
    match get_sockets(af_flags, proto_flags) {
        Ok(sockets) => {
            // If successful, iterate over the returned sockets and print their information.
            for socket in sockets {
                // Print the socket information
                match socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(tcp_socket) => println!(
                        "[TCP] {}:{} -> {}:{} {:?} - [{}]",
                        tcp_socket.local_addr,
                        tcp_socket.local_port,
                        tcp_socket.remote_addr,
                        tcp_socket.remote_port,
                        socket.processes,
                        tcp_socket.state
                    ),
                    ProtocolSocketInfo::Udp(udp_socket) => println!(
                        "[UDP] {}:{} -> *:* {:?}",
                        udp_socket.local_addr, udp_socket.local_port, socket.processes
                    ),
                }
            }
        }
        Err(e) => {
            // If an error occurs, print the error message.
            eprintln!("Error: {}", e);
        }
    }
}
