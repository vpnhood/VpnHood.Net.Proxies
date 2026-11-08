namespace VpnHood.Net.Proxies.Socks5Proxy;

/// <summary>
/// Specifies a SOCKS5 authentication method (RFC 1928, section 3).
/// </summary>
public enum Socks5AuthenticationType : byte
{
    /// <summary>No authentication.</summary>
    NoAuthenticationRequired = 0x00,

    /// <summary>GSS-API authentication (RFC 1961). The clients and servers of this library do not support it.</summary>
    Gssapi = 0x01,

    /// <summary>Username and password authentication (RFC 1929).</summary>
    UsernamePassword = 0x02,

    /// <summary>The first value of the range IANA assigns.</summary>
    IanaAssignedRangeBegin = 0x03,

    /// <summary>The last value of the range IANA assigns.</summary>
    IanaAssignedRangeEnd = 0x7f,

    /// <summary>The first value of the range reserved for private methods.</summary>
    ReservedRangeBegin = 0x80,

    /// <summary>The last value of the range reserved for private methods.</summary>
    ReservedRangeEnd = 0xfe,

    /// <summary>Sent by a server in place of a method when none of the client's methods is acceptable.</summary>
    ReplyNoAcceptableMethods = 0xff
}
