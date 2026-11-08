using System.Net;

namespace VpnHood.Net.Proxies.Socks5Proxy;

/// <summary>
/// Represents an address and port in a SOCKS5 message: a domain name or an IP address.
/// </summary>
/// <param name="Host">The domain name, or <see langword="null"/> when the message carries an IP address.</param>
/// <param name="Address">The IP address, or <see langword="null"/> when the message carries a domain name.</param>
/// <param name="Port">The port.</param>
public readonly record struct Socks5Endpoint(string? Host, IPAddress? Address, int Port);
