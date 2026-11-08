using System.Net;
using System.Net.Sockets;

namespace VpnHood.Net.Proxies;

/// <summary>
/// Opens TCP connections to destinations through a proxy server.
/// </summary>
/// <remarks>
/// One instance can serve many connections at once; run one operation at a time on each connection. When the
/// exchange with the proxy fails, the method closes the <see cref="TcpClient"/> it was given. When an argument is
/// rejected, the connection may be left open: the caller still owns it and disposes it.
/// </remarks>
public interface IProxyClient
{
    /// <summary>
    /// Gets the address and port of the proxy server.
    /// </summary>
    IPEndPoint ProxyEndPoint { get; }

    /// <summary>
    /// Opens a tunnel through the proxy to a host, given by name or IP address.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> first.
    /// When the task completes, it carries the tunnel; when the exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="host">The destination's host name or IP address literal.</param>
    /// <param name="port">The destination's port, from 1 to 65535.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request or answered in a way the client cannot use;
    /// <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken);

    /// <summary>
    /// Opens a tunnel through the proxy to an IP endpoint.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> first.
    /// When the task completes, it carries the tunnel; when the exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="destination">The destination's address and port.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request or answered in a way the client cannot use;
    /// <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken);

    /// <summary>
    /// Connects to the proxy to see whether it works, without asking for a tunnel.
    /// </summary>
    /// <remarks>
    /// How much is checked depends on the protocol: a SOCKS5 client also negotiates the authentication, an
    /// HTTPS client completes the TLS handshake, and a SOCKS4 or plain HTTP client only opens the TCP
    /// connection. Close the connection after the check, and open a tunnel on a new one.
    /// </remarks>
    /// <param name="tcpClient">A connection that is not connected yet. When the check fails, it is closed.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the check passes.</returns>
    Task CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken);
}
