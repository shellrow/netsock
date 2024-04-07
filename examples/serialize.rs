// This example demonstrates how to use `serde` feature of `netsock` crate to retrieve socket information
// for both IPv4 and IPv6 addresses and for TCP and UDP protocols.
use netsock::family::AddressFamilyFlags;
use netsock::get_sockets;
use netsock::protocol::ProtocolFlags;

fn main() {
    // Combine IPv4 and IPv6 address family flags to search for sockets across both families.
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;

    // Combine TCP and UDP protocol flags to search for both types of sockets.
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    // Call get_sockets with the specified address family and protocol flags.
    // This function returns a Result, which we match on to handle both the Ok and Err cases.
    match get_sockets(af_flags, proto_flags) {
        Ok(sockets) => {
            // If successful, print their information in a pretty JSON format.
            match serde_json::to_string_pretty(&sockets) {
                Ok(json) => {
                    println!("{}", json);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            }
        }
        Err(e) => {
            // If an error occurs, print the error message.
            eprintln!("Error: {}", e);
        }
    }
}
