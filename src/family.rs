use bitflags::bitflags;

bitflags! {
    /// Flags representing different address families for network operations.
    ///
    /// This structure uses the `bitflags` macro to create a set of flags that can be combined
    /// using bitwise OR (`|`) to represent multiple address families simultaneously. It is
    /// typically used to specify preferences or capabilities related to IPv4 and IPv6 addresses
    /// in network operations.
    ///
    /// # Flags
    /// - `IPV4`: Represents the IPv4 address family. When set, this flag indicates that an operation
    ///   should consider or is capable of handling IPv4 addresses.
    /// - `IPV6`: Represents the IPv6 address family. When set, this flag signifies that an operation
    ///   should consider or is capable of handling IPv6 addresses.
    ///
    /// These flags can be combined to indicate support for both IPv4 and IPv6, or checked individually
    /// to determine the supported address families.
    ///
    /// # Examples
    /// ```
    /// use your_crate::AddressFamilyFlags;
    ///
    /// // Specify that an operation supports both IPv4 and IPv6 addresses.
    /// let flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    ///
    /// // Check if IPv4 is supported.
    /// if flags.contains(AddressFamilyFlags::IPV4) {
    ///     println!("Supports IPv4");
    /// }
    ///
    /// // Check if IPv6 is supported.
    /// if flags.contains(AddressFamilyFlags::IPV6) {
    ///     println!("Supports IPv6");
    /// }
    /// ```
    pub struct AddressFamilyFlags: u8 {
        const IPV4 = 0b00000001;
        const IPV6 = 0b00000010;
    }
}
