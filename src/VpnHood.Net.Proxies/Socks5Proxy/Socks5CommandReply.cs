namespace VpnHood.Net.Proxies.Socks5Proxy;

/// <summary>
/// Specifies a SOCKS5 server's reply to a request: the REP field of RFC 1928, section 6.
/// </summary>
public enum Socks5CommandReply : byte
{
    /// <summary>The request succeeded.</summary>
    Succeeded = 0x00,

    /// <summary>The server failed for a reason of its own.</summary>
    GeneralSocksServerFailure = 0x01,

    /// <summary>The server's rules do not allow the connection.</summary>
    ConnectionNotAllowedByRuleset = 0x02,

    /// <summary>The destination's network cannot be reached.</summary>
    NetworkUnreachable = 0x03,

    /// <summary>The destination cannot be reached.</summary>
    HostUnreachable = 0x04,

    /// <summary>The destination refused the connection.</summary>
    ConnectionRefused = 0x05,

    /// <summary>
    /// The TTL expired. The server of this library also sends it when the destination does not accept the
    /// connection within its host connection timeout.
    /// </summary>
    TtlExpired = 0x06,

    /// <summary>The server does not support the request's command.</summary>
    CommandNotSupported = 0x07,

    /// <summary>The server does not support the request's address type.</summary>
    AddressTypeNotSupported = 0x08
}
