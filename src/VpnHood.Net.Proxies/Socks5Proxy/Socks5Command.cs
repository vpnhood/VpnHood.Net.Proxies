namespace VpnHood.Net.Proxies.Socks5Proxy;

/// <summary>
/// Specifies the command of a SOCKS5 request (RFC 1928, section 4).
/// </summary>
public enum Socks5Command : byte
{
    /// <summary>Open a TCP connection to the destination.</summary>
    Connect = 0x01,

    /// <summary>
    /// Wait for a TCP connection from the destination. The server of this library answers it with
    /// <see cref="Socks5CommandReply.CommandNotSupported"/>.
    /// </summary>
    Bind = 0x02,

    /// <summary>
    /// Relay UDP datagrams for the client, for as long as the request's TCP connection stays open.
    /// </summary>
    UdpAssociate = 0x03
}
