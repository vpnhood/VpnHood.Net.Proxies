using System.Net;

namespace VpnHood.Net.Proxies.Socks5ProxyServers;

/// <summary>
/// Provides the settings of a <see cref="Socks5ProxyServer"/>.
/// </summary>
public class Socks5ProxyServerOptions
{
    /// <summary>
    /// Gets the address and port the server listens on. Port 0 lets the system choose one, which
    /// <see cref="TcpProxyServerBase.ListenerEndPoint"/> shows once the server has started.
    /// </summary>
    public required IPEndPoint ListenEndPoint { get; init; }

    /// <summary>
    /// Gets the user name clients must give (RFC 1929), or <see langword="null"/> to serve clients without
    /// credentials.
    /// </summary>
    /// <remarks>
    /// When it is set, a client must authenticate with it and <see cref="Password"/>, and a client that offers
    /// no username and password authentication is refused. When it is <see langword="null"/>, a client that
    /// offers only username and password authentication is served whatever credentials it gives.
    /// </remarks>
    public string? Username { get; init; }

    /// <summary>
    /// Gets the password clients must give with <see cref="Username"/>. <see langword="null"/> means an empty
    /// password.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Gets how long a client has to complete the method negotiation and the authentication. The default is
    /// 15 seconds.
    /// </summary>
    /// <remarks>
    /// The request that follows, and the server's lookup of a domain name in it, have no deadline of their own.
    /// It counts whole milliseconds, a fraction dropped: −1 ms (<see cref="Timeout.InfiniteTimeSpan"/>) sets no limit;
    /// zero cancels the handshake as soon as the cancel runs, so it fails unless it has passed already; −2 ms or less
    /// fails every handshake at its start, and the server closes the connection.
    /// </remarks>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Gets or sets how long the server waits for a destination to accept a TCP connection. The default is
    /// 30 seconds.
    /// </summary>
    /// <remarks>
    /// When it elapses, the client gets <see cref="Socks5Proxy.Socks5CommandReply.TtlExpired"/>. It is read at each
    /// connect to a destination, so a change applies to the next connect, for a client accepted already too.
    /// It counts whole milliseconds, a fraction dropped: −1 ms (<see cref="Timeout.InfiniteTimeSpan"/>) sets no limit;
    /// zero cancels each connect as soon as the cancel runs, so it fails unless the destination has accepted already;
    /// −2 ms or less fails every connect at its start.
    /// </remarks>
    public TimeSpan HostConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets how long, after one direction of a tunnel has ended (a TCP half-close) and the server has passed that
    /// end on, the other direction may still carry data before the tunnel is closed. The default is 15 seconds.
    /// </summary>
    /// <remarks>
    /// It counts whole milliseconds, a fraction dropped: −1 ms (<see cref="Timeout.InfiniteTimeSpan"/>) waits for the
    /// other direction without a limit; zero, or −2 ms or less, closes the tunnel without that wait, once the ended
    /// direction's end has been passed on.
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
}
