using System.Net;

namespace VpnHood.Net.Proxies.Socks5ProxyClients;

/// <summary>
/// Provides the settings of a <see cref="Socks5ProxyClient"/>.
/// </summary>
public class Socks5ProxyClientOptions
{
    /// <summary>
    /// Gets the address and port of the SOCKS5 proxy.
    /// </summary>
    public required IPEndPoint ProxyEndPoint { get; init; }

    /// <summary>
    /// Gets or sets the user name for username and password authentication (RFC 1929), or
    /// <see langword="null"/> or empty to offer no credentials.
    /// </summary>
    /// <remarks>
    /// With a user name, the client offers the proxy both no authentication and username and password
    /// authentication, and the proxy chooses. Its UTF-8 form must not exceed 255 bytes.
    /// </remarks>
    public string? Username { get; set; }

    /// <summary>
    /// Gets or sets the password sent with <see cref="Username"/>. <see langword="null"/> is sent as an empty
    /// password. Its UTF-8 form must not exceed 255 bytes.
    /// </summary>
    public string? Password { get; set; }
}
