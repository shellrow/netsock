use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    /// IP address families to include in a socket scan.
    pub struct AddressFamilyFlags: u8 {
        const IPV4 = 0b00000001;
        const IPV6 = 0b00000010;
    }
}
