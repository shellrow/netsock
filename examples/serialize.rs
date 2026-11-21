use netsock::family::AddressFamilyFlags;
use netsock::get_sockets;
use netsock::protocol::ProtocolFlags;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sockets = get_sockets(AddressFamilyFlags::all(), ProtocolFlags::all())?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer_pretty(&mut stdout, &sockets)?;
    writeln!(stdout)?;
    stdout.flush()?;
    Ok(())
}
