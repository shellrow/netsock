use bitflags::bitflags;

bitflags! {
    /// Flags representing different network protocols.
    ///
    /// This structure utilizes the `bitflags` macro to define a set of flags that can be combined
    /// using bitwise OR (`|`) to represent multiple network protocols simultaneously. It's typically
    /// used to specify or check support for various network protocols, such as TCP and UDP, in network
    /// operations or configurations.
    ///
    /// # Flags
    /// - `TCP`: Represents the TCP (Transmission Control Protocol). When this flag is set, it indicates
    ///   that an operation should consider or is capable of handling TCP-based network communication.
    /// - `UDP`: Represents the UDP (User Datagram Protocol). When this flag is set, it signifies that an
    ///   operation should consider or is capable of handling UDP-based network communication.
    ///
    /// These flags can be combined to indicate support for both TCP and UDP, or they can be checked
    /// individually to determine the supported protocols.
    ///
    /// # Examples
    /// ```
    /// use netsock::protocol::ProtocolFlags;
    ///
    /// // Specify that an operation supports both TCP and UDP protocols.
    /// let flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    ///
    /// // Check if TCP is supported.
    /// assert!(flags.contains(ProtocolFlags::TCP));
    /// assert!(flags.contains(ProtocolFlags::UDP));
    /// ```
    pub struct ProtocolFlags: u8 {
        const TCP = 0b00000001;
        const UDP = 0b00000010;
    }
}
