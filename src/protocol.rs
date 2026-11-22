use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    /// Transport protocols to include in a socket scan.
    pub struct ProtocolFlags: u8 {
        const TCP = 0b00000001;
        const UDP = 0b00000010;
    }
}
