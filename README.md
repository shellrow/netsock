[crates-badge]: https://img.shields.io/crates/v/netsock.svg
[crates-url]: https://crates.io/crates/netsock
[license-badge]: https://img.shields.io/crates/l/netsock.svg
[examples-url]: https://github.com/shellrow/netsock/tree/main/examples
[doc-url]: https://docs.rs/netsock/latest/netsock

# netsock [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform library for network socket and process information.

## Features
- TCP and UDP socket inspection
- IPv4 and IPv6 support
- Optional process ownership information
- Iterator and query-based filtering API

## Supported Platforms
- Linux
- macOS
- Windows

## Usage
Add `netsock` to your dependencies:

```toml:Cargo.toml
[dependencies]
netsock = "0.5"
```

See [examples][examples-url] and [docs][doc-url] for more details.

## Basic Example
```rust
use netsock::family::AddressFamilyFlags;
use netsock::get_sockets;
use netsock::protocol::ProtocolFlags;
use netsock::socket::ProtocolSocketInfo;

fn main() {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    match get_sockets(af_flags, proto_flags) {
        Ok(sockets) => {
            for socket in sockets {
                match socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(tcp_socket) => println!(
                        "[TCP] {}:{} -> {}:{} {:?} ({})",
                        tcp_socket.local_addr,
                        tcp_socket.local_port,
                        tcp_socket.remote_addr,
                        tcp_socket.remote_port,
                        tcp_socket.state,
                        socket.processes.len()
                    ),
                    ProtocolSocketInfo::Udp(udp_socket) => println!(
                        "[UDP] {}:{} ({})",
                        udp_socket.local_addr,
                        udp_socket.local_port,
                        socket.processes.len()
                    ),
                }
            }
        }
        Err(err) => eprintln!("error: {err}"),
    }
}
```

## Query Filtering Example
```rust
use netsock::family::AddressFamilyFlags;
use netsock::iter_sockets;
use netsock::protocol::ProtocolFlags;
use netsock::socket::{SocketIteratorExt, SocketQuery};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let query = SocketQuery::new().with_local_port(443);

    for socket in iter_sockets(AddressFamilyFlags::all(), ProtocolFlags::TCP)?
        .filter_by_query(query)
    {
        println!("{:?}", socket?);
    }

    Ok(())
}
```

## Inspired by
- [netstat](https://crates.io/crates/netstat): unmaintained
- [netstat2](https://crates.io/crates/netstat2)
