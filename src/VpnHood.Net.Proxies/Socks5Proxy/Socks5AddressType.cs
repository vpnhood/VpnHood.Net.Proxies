namespace VpnHood.Net.Proxies.Socks5Proxy;

/// <summary>
/// Specifies how a SOCKS5 message encodes an address: the ATYP field of RFC 1928.
/// </summary>
public enum Socks5AddressType : byte
{
    /// <summary>An IPv4 address, in 4 bytes.</summary>
    IpV4 = 0x01,

    /// <summary>A domain name: a length byte followed by the name. In a request, the proxy resolves it.</summary>
    DomainName = 0x03,

    /// <summary>An IPv6 address, in 16 bytes.</summary>
    IpV6 = 0x04
}
