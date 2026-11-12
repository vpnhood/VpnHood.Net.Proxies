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
    /// <exception cref="ArgumentNullException">
    /// <paramref name="tcpClient"/> or <paramref name="host"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="host"/> is empty or white space; for SOCKS5, it or a credential in the options exceeds 255 bytes
    /// in UTF-8.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="port"/> is less than 1 or greater than 65535.
    /// </exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request or answered in a way the client cannot use, or, for SOCKS4, the destination is an
    /// IPv6 address; <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    /// <exception cref="System.Security.Authentication.AuthenticationException">
    /// The TLS handshake with an HTTPS proxy failed.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// A SOCKS5 proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">A SOCKS5 proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">
    /// A SOCKS5 proxy chose an authentication method the client lacks, or answered with an unknown address type.
    /// </exception>
    /// <exception cref="TimeoutException">An HTTP proxy did not answer within 30 seconds.</exception>
    /// <exception cref="IOException">An HTTP proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="EndOfStreamException">A SOCKS proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
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
    /// <exception cref="ArgumentNullException">
    /// <paramref name="tcpClient"/> or <paramref name="destination"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">For SOCKS5, a credential in the options exceeds 255 bytes in UTF-8.</exception>
    /// <exception cref="ArgumentOutOfRangeException">For HTTP and SOCKS4, the destination's port is zero.</exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request or answered in a way the client cannot use, or, for SOCKS4, the destination is an
    /// IPv6 address; <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    /// <exception cref="System.Security.Authentication.AuthenticationException">
    /// The TLS handshake with an HTTPS proxy failed.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// A SOCKS5 proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">A SOCKS5 proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">
    /// A SOCKS5 proxy chose an authentication method the client lacks, or answered with an unknown address type.
    /// </exception>
    /// <exception cref="TimeoutException">An HTTP proxy did not answer within 30 seconds.</exception>
    /// <exception cref="IOException">An HTTP proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="EndOfStreamException">A SOCKS proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken);

    /// <summary>
    /// Connects to the proxy to see whether it works, without asking for a tunnel.
    /// </summary>
    /// <remarks>
    /// How much is checked depends on the protocol: a SOCKS5 client also negotiates the authentication, an
    /// HTTPS client completes the TLS handshake, and a SOCKS4 or plain HTTP client only opens the TCP
    /// connection. A SOCKS or plain HTTP client can then open a tunnel on the checked connection; an HTTPS client
    /// keeps no TLS session from the check, so its tunnel needs a new connection.
    /// </remarks>
    /// <param name="tcpClient">A connection that is not connected yet. When the check fails, it is closed.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the check passes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">For SOCKS5, a credential in the options exceeds 255 bytes in UTF-8.</exception>
    /// <exception cref="System.Security.Authentication.AuthenticationException">
    /// The TLS handshake with an HTTPS proxy failed.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// A SOCKS5 proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">A SOCKS5 proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">A SOCKS5 proxy chose an authentication method the client lacks.</exception>
    /// <exception cref="EndOfStreamException">A SOCKS5 proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    Task CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken);
}
