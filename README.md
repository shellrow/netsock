[crates-badge]: https://img.shields.io/crates/v/netsock.svg
[crates-url]: https://crates.io/crates/netsock
[license-badge]: https://img.shields.io/crates/l/netsock.svg
[examples-url]: https://github.com/shellrow/netsock/tree/main/examples
[doc-url]: https://docs.rs/netsock/latest/netsock
[netsock-github-url]: https://github.com/shellrow/netsock

# netsock [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform library for network sockets information.

## Features
- Retrieve information for TCP and UDP sockets
- Support for IPv4 and IPv6
- Fetch socket information with process info

## Supported platform
- Linux
- macOS
- Windows

## Usage
Add `netsock` to your dependencies  
```toml:Cargo.toml
[dependencies]
netsock = "0.1"
```

For more details, see [examples][examples-url] or [doc][doc-url].  

## Example
```rust
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
                // Print the socket and process information
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
```

## Inspired by
- [netstat](https://crates.io/crates/netstat): unmaintained
- [netstat2](https://crates.io/crates/netstat2): unmaintained
