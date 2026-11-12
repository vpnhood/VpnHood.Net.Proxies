using System.Net;
using System.Net.Sockets;
using System.Text;

namespace VpnHood.Net.Proxies.Socks4ProxyClients;

/// <summary>
/// Opens TCP tunnels through a SOCKS4 proxy, or a SOCKS4a proxy for host names. It supports CONNECT only, and
/// IPv4 destinations only.
/// </summary>
/// <remarks>
/// An instance keeps no per-connection state, so it can serve many connections at once.
/// </remarks>
/// <example>
/// <code snippet="Snippet:Socks4Connect" language="csharp">
/// var client = new Socks4ProxyClient(new Socks4ProxyClientOptions {
///     ProxyEndPoint = proxyEndPoint,
///     UserName = null // the SOCKS4 user ID, when the proxy wants one
/// });
///
/// using var tcp = new TcpClient();
/// await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None); // a host name uses SOCKS4a
///
/// var stream = tcp.GetStream(); // the tunnel
/// </code>
/// </example>
/// <param name="options">The proxy's address and the user ID to send.</param>
public class Socks4ProxyClient(Socks4ProxyClientOptions options) : IProxyClient
{
    /// <inheritdoc/>
    public IPEndPoint ProxyEndPoint => options.ProxyEndPoint;

    /// <summary>
    /// Opens a tunnel through the proxy to an IPv4 endpoint.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> first.
    /// When the task completes, its <see cref="TcpClient.GetStream"/> carries the tunnel; when the
    /// exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="destination">The destination's IPv4 address and port.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> or <paramref name="destination"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The port of <paramref name="destination"/> is zero.</exception>
    /// <exception cref="ProxyClientException">
    /// <paramref name="destination"/> is IPv6, which SOCKS4 cannot carry; the proxy's answer is not SOCKS4; or
    /// the proxy refused the request. <see cref="SocketException.SocketErrorCode"/> tells which.
    /// </exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="EndOfStreamException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.AddressFamily == AddressFamily.InterNetworkV6)
            throw new ProxyClientException(SocketError.AddressFamilyNotSupported, "SOCKS4 only supports IPv4 addresses.");

        return ConnectAsync(tcpClient, destination.Address.ToString(), destination.Port, cancellationToken);
    }

    /// <summary>
    /// Opens a tunnel through the proxy to a host, given by name or IPv4 address.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> first.
    /// When the task completes, its <see cref="TcpClient.GetStream"/> carries the tunnel; when the
    /// exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="host">
    /// The destination's host name or IPv4 address literal. A name is sent for the proxy to resolve, as SOCKS4a
    /// does; a proxy that speaks only SOCKS4 refuses it.
    /// </param>
    /// <param name="port">The destination's port, from 1 to 65535.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> or <paramref name="host"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="host"/> is empty or white space.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="port"/> is less than 1 or greater than 65535.</exception>
    /// <exception cref="ProxyClientException">
    /// <paramref name="host"/> is an IPv6 literal, which SOCKS4 cannot carry; the proxy's answer is not SOCKS4;
    /// or the proxy refused the request. <see cref="SocketException.SocketErrorCode"/> tells which.
    /// </exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="EndOfStreamException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, IPEndPoint.MaxPort); // the request has two bytes for it

        try {
            if (!tcpClient.Connected) {
                tcpClient.NoDelay = true;
                await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            }

            var stream = tcpClient.GetStream();
            var isIp = IPAddress.TryParse(host, out var ipAddress);
            if (isIp && ipAddress!.AddressFamily == AddressFamily.InterNetworkV6)
                throw new ProxyClientException(SocketError.AddressFamilyNotSupported, "SOCKS4 only supports IPv4 addresses.");
            if (!isIp)
                ipAddress = IPAddress.Parse("0.0.0.1"); // SOCKS4a marker; host is sent separately

            var request = BuildRequest(ipAddress!, port, isIp ? null : host, options.UserName);
            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var reply = new byte[8];
            await stream.ReadExactlyAsync(reply, cancellationToken).ConfigureAwait(false);
            if (reply[0] != 0)
                throw new ProxyClientException(SocketError.ProtocolNotSupported, $"Invalid SOCKS4 reply version: {reply[0]}");

            var code = (Socks4ReplyCode)reply[1];
            if (code != Socks4ReplyCode.RequestGranted)
                ThrowSocks4Error(code);
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    /// <summary>
    /// Opens a TCP connection to the proxy. SOCKS4 has no request that checks a proxy without opening a tunnel,
    /// so this checks only that the proxy accepts connections.
    /// </summary>
    /// <param name="tcpClient">A connection that is not connected yet. When the check fails, it is closed.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the connection is open.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);

        try {
            tcpClient.NoDelay = true;
            await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    private static ReadOnlyMemory<byte> BuildRequest(IPAddress ip, int port, string? domainName, string? userId)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            throw new ProxyClientException(SocketError.AddressFamilyNotSupported, "SOCKS4 only supports IPv4 addresses.");

        var user = userId ?? string.Empty;
        var userBytes = Encoding.UTF8.GetBytes(user);
        var hostBytes = domainName != null ? Encoding.UTF8.GetBytes(domainName) : null;
        var addressBytes = ip.GetAddressBytes();
        var buffer = new byte[1 + 1 + 2 + 4 + userBytes.Length + 1 + (hostBytes?.Length ?? 0) + (domainName != null ? 1 : 0)];
        var o = 0;
        buffer[o++] = 0x04; // VN
        buffer[o++] = 0x01; // CD=CONNECT
        buffer[o++] = (byte)(port >> 8);
        buffer[o++] = (byte)(port & 0xFF);
        Array.Copy(addressBytes, 0, buffer, o, 4); o += 4;
        if (userBytes.Length > 0) Array.Copy(userBytes, 0, buffer, o, userBytes.Length);
        o += userBytes.Length;
        buffer[o++] = 0x00; // user id null terminator
        if (hostBytes != null) {
            Array.Copy(hostBytes, 0, buffer, o, hostBytes.Length);
            o += hostBytes.Length;
            buffer[o++] = 0x00; // host null terminator (SOCKS4a)
        }
        return new ReadOnlyMemory<byte>(buffer, 0, o);
    }

    private static void ThrowSocks4Error(Socks4ReplyCode code)
    {
        throw new ProxyClientException(code switch {
            Socks4ReplyCode.RequestRejectedOrFailed => SocketError.AccessDenied,
            Socks4ReplyCode.CannotConnectToIdentd => SocketError.ConnectionRefused,
            Socks4ReplyCode.DifferingUserId => SocketError.AccessDenied,
            _ => SocketError.SocketError
        });
    }
}
