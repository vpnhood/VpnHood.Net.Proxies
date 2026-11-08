using System.Net;

namespace VpnHood.Net.Proxies.HttpProxyClients;

/// <summary>
/// Provides the settings of an <see cref="HttpProxyClient"/>.
/// </summary>
public class HttpProxyClientOptions
{
    /// <summary>
    /// Gets the address and port of the HTTP or HTTPS proxy.
    /// </summary>
    public required IPEndPoint ProxyEndPoint { get; init; }

    /// <summary>
    /// Gets the proxy's host name, which the TLS handshake uses as the server name when <see cref="UseTls"/> is
    /// <see langword="true"/>, or <see langword="null"/> to use the IP address of <see cref="ProxyEndPoint"/>.
    /// </summary>
    public string? ProxyHost { get; init; }

    /// <summary>
    /// Gets the user name for Basic authentication, sent in a Proxy-Authorization header, or
    /// <see langword="null"/> to send no credentials.
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// Gets the password sent with <see cref="Username"/>. <see langword="null"/> is sent as an empty password.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Gets a value indicating whether the connection to the proxy itself runs over TLS, as an HTTPS proxy
    /// expects. The default is <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// The system chooses the TLS version, and the certificate's revocation is not checked. Read and write the
    /// tunnel through <see cref="HttpProxyClient.GetStream"/>: the connection's own stream bypasses TLS.
    /// </remarks>
    public bool UseTls { get; init; }

    /// <summary>
    /// Gets a value indicating whether a proxy certificate that fails validation is accepted. The default is
    /// <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// Accepting such a certificate lets anyone between the client and the proxy read and change the traffic.
    /// </remarks>
    public bool AllowInvalidCertificates { get; init; }

    /// <summary>
    /// Gets headers sent with each CONNECT request after the client's own, or <see langword="null"/> for none.
    /// </summary>
    /// <remarks>
    /// Names and values are sent as given, so they must not contain line breaks.
    /// </remarks>
    public IReadOnlyDictionary<string, string>? ExtraHeaders { get; init; }
}
