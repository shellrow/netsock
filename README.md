[crates-badge]: https://img.shields.io/crates/v/netsock.svg
[crates-url]: https://crates.io/crates/netsock
[license-badge]: https://img.shields.io/crates/l/netsock.svg
[examples-url]: https://github.com/shellrow/netsock/tree/main/examples
[doc-url]: https://docs.rs/netsock/latest/netsock

# netsock [![Crates.io][crates-badge]][crates-url] ![License][license-badge]

Inspect IPv4 and IPv6 TCP and UDP sockets and their owning processes on Linux,
macOS, Windows, and FreeBSD. Requires Rust 1.88 or later. Builds for macOS and
FreeBSD also need a C compiler and the target system headers.

## Install

```sh
cargo add netsock
```

or

```toml
[dependencies]
netsock = "0.9"
```

## Usage

List TCP listeners on port 443 and print their local endpoints and visible owners.

```rust
use std::net::SocketAddr;

use netsock::family::AddressFamilyFlags;
use netsock::iter_sockets;
use netsock::protocol::ProtocolFlags;
use netsock::socket::{SocketIteratorExt, SocketQuery};
use netsock::state::TcpState;

fn main() -> Result<(), netsock::error::Error> {
    let query = SocketQuery::new()
        .with_local_port(443)
        .with_tcp_state(TcpState::Listen);

    let sockets = iter_sockets(AddressFamilyFlags::all(), ProtocolFlags::TCP)?;
    for result in sockets.filter_by_query(query) {
        let socket = result?;
        let endpoint = SocketAddr::new(socket.local_addr(), socket.local_port());
        println!("{endpoint} {:?}", socket.processes);
    }
    Ok(())
}
```

Use `get_sockets` to collect all matching rows, or `iter_sockets_without_processes`
to skip ownership lookup. Both take address family and protocol flags. An empty
selection returns no sockets. The optional `serde` feature enables serialization
and deserialization of socket records.

## Platform behavior

| Platform | Socket source | Process information |
| --- | --- | --- |
| Linux | Socket diagnostics via netlink in the current network namespace | Accessible descriptors in `/proc`, matched by inode |
| macOS | Socket descriptors visible through libproc | Processes holding those descriptors |
| Windows | TCP and UDP tables from IP Helper | Owner PID from the table and executable name from Tool Help |
| FreeBSD | TCP and UDP protocol control blocks from sysctl | Visible file descriptors matched to kernel socket records |

Enumeration spans multiple system calls. Sockets may close and PIDs may be
reused during a scan. An empty owner list means no owner was observed, and an
empty process name means the name was unavailable. On macOS, inaccessible
processes also limit which sockets can be returned. Linux callers can reuse a
`ProcessCache` across scans and refresh it when they need newer ownership data.

TCP rows include both endpoints and the connection state. UDP rows report only
the local endpoint. IP addresses do not carry IPv6 scope IDs. Linux records
also include the socket inode and UID. Deserializing a Linux record requires
both fields.

See [examples][examples-url] and [API docs][doc-url] for more details.
