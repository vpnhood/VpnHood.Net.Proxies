using System.Net;

namespace VpnHood.Net.Proxies.Socks4ProxyClients;

/// <summary>
/// Provides the settings of a <see cref="Socks4ProxyClient"/>.
/// </summary>
public class Socks4ProxyClientOptions
{
    /// <summary>
    /// Gets the address and port of the SOCKS4 proxy.
    /// </summary>
    public required IPEndPoint ProxyEndPoint { get; init; }

    /// <summary>
    /// Gets the user ID sent with each request, or <see langword="null"/> to send an empty one.
    /// </summary>
    public string? UserName { get; init; }
}
