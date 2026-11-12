using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace VpnHood.Net.Proxies.HttpProxyServers;

/// <summary>
/// Provides the settings of an <see cref="HttpProxyServer"/> or an <see cref="HttpsProxyServer"/>.
/// </summary>
public class HttpProxyServerOptions
{
    /// <summary>
    /// Gets the address and port the server listens on. Port 0 lets the system choose one, which
    /// <see cref="TcpProxyServerBase.ListenerEndPoint"/> shows once the server has started.
    /// </summary>
    public required IPEndPoint ListenEndPoint { get; init; }

    /// <summary>
    /// Gets the user name clients must give with Basic authentication, in a Proxy-Authorization header, or
    /// <see langword="null"/> to serve clients without credentials.
    /// </summary>
    /// <remarks>
    /// A client without the right credentials gets 407 Proxy Authentication Required.
    /// </remarks>
    public string? Username { get; init; }

    /// <summary>
    /// Gets the password clients must give with <see cref="Username"/>. <see langword="null"/> means an empty
    /// password.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Gets how long a client has to send its request line and headers. The default is 15 seconds.
    /// </summary>
    /// <remarks>
    /// An <see cref="HttpsProxyServer"/> gives the TLS handshake the same time again, before the request.
    /// It counts whole milliseconds, a fraction dropped: −1 ms (<see cref="Timeout.InfiniteTimeSpan"/>) sets no limit;
    /// zero cancels the handshake as soon as the cancel runs, so it fails unless it has passed already; −2 ms or less
    /// fails every handshake at its start, and the server closes the connection.
    /// </remarks>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Gets or sets how long the server may take to reach a destination: the lookup of its host name and the
    /// TCP connect. The default is 30 seconds.
    /// </summary>
    /// <remarks>
    /// When it elapses, a CONNECT request gets 502 Bad Gateway and a plain HTTP request 504 Gateway Timeout.
    /// It is read at each connect to a destination, so a change applies to the next connect, for a client accepted
    /// already too. It counts whole milliseconds, a fraction dropped: −1 ms (<see cref="Timeout.InfiniteTimeSpan"/>) sets
    /// no limit; zero cancels each connect as soon as the cancel runs, so it fails unless the destination has accepted
    /// already; −2 ms or less fails every connect at its start.
    /// </remarks>
    public TimeSpan HostConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets how long, after one direction of a tunnel has ended (a TCP half-close), the other direction may still
    /// carry data before the tunnel is closed. The default is 15 seconds.
    /// </summary>
    /// <remarks>
    /// The time includes passing the end on to the other side, which an <see cref="HttpsProxyServer"/> does over
    /// TLS, where it waits on a client that reads nothing. It counts whole milliseconds, a fraction dropped: −1 ms
    /// (<see cref="Timeout.InfiniteTimeSpan"/>) waits without a limit; zero, or −2 ms or less, closes the tunnel
    /// without a wait, right after it has started to pass the end on.
    /// </remarks>
    public TimeSpan TunnelHalfCloseTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Gets the maximum number of pending connections the listener queues. The default is 512.
    /// </summary>
    /// <remarks>
    /// It must be positive: the server's constructor throws <see cref="ArgumentOutOfRangeException"/> otherwise.
    /// </remarks>
    public int Backlog { get; init; } = 512;

    /// <summary>
    /// Gets the maximum number of client connections the server serves at once. The default is
    /// <see cref="int.MaxValue"/>, which means no limit.
    /// </summary>
    /// <remarks>
    /// A connection beyond it is accepted and closed at once. On a host with little memory, such as a mobile
    /// network extension, set a limit that fits its budget. It must be positive: the server's constructor
    /// throws <see cref="ArgumentOutOfRangeException"/> otherwise.
    /// </remarks>
    public int MaxConnections { get; init; } = int.MaxValue;

    /// <summary>
    /// Gets the certificate, with its private key, that an <see cref="HttpsProxyServer"/> presents to clients.
    /// </summary>
    /// <remarks>
    /// An <see cref="HttpsProxyServer"/> requires it; an <see cref="HttpProxyServer"/> ignores it. The server does
    /// not dispose it: keep it alive while the server runs, and until its connections' handlers have ended too, as
    /// stopping does not wait for them and one may still be in its TLS handshake; dispose it afterwards.
    /// </remarks>
    public X509Certificate2? ServerCertificate { get; init; }
}
