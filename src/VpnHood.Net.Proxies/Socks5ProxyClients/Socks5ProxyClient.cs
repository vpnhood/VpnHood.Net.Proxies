using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;
using VpnHood.Net.Proxies.Socks5Proxy;

namespace VpnHood.Net.Proxies.Socks5ProxyClients;

/// <summary>
/// Opens TCP tunnels and UDP associations through a SOCKS5 proxy (RFC 1928), with optional username and
/// password authentication (RFC 1929).
/// </summary>
/// <remarks>
/// One instance can serve many connections at once; run one operation at a time on each connection, as the
/// method negotiation and the authentication run once for each <see cref="TcpClient"/>. Keep the options
/// unchanged while the client is in use. A host name is sent to the proxy as a domain name, so the proxy
/// resolves it and no DNS query for it leaves this machine.
/// </remarks>
/// <example>
/// <code snippet="Snippet:Socks5Connect" language="csharp">
/// var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
///     ProxyEndPoint = proxyEndPoint
/// });
///
/// using var tcp = new TcpClient();
///
/// // A host name goes to the proxy as a SOCKS5 domain name, so the proxy resolves it: no local DNS query.
/// await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None);
///
/// var stream = tcp.GetStream(); // the tunnel: speak HTTP, TLS or anything else
/// </code>
/// </example>
/// <param name="options">The proxy's address and the credentials to offer.</param>
/// <param name="logger">The logger for the client's progress and failures, or <see langword="null"/> for none.</param>
public class Socks5ProxyClient(
    Socks5ProxyClientOptions options,
    ILogger<Socks5ProxyClient>? logger = null)
    : IProxyClient
{
    // The SOCKS5 method negotiation belongs to a connection, not to this client instance,
    // so track it per TcpClient. Entries disappear with their TcpClient.
    private readonly ConditionalWeakTable<TcpClient, object> _authenticatedConnections = new();

    /// <inheritdoc/>
    public IPEndPoint ProxyEndPoint => options.ProxyEndPoint;

    /// <summary>
    /// Opens a tunnel through the proxy to a host, given by name or IP address.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> and
    /// authenticated first. When the task completes, its <see cref="TcpClient.GetStream"/> carries the tunnel;
    /// when the exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="host">
    /// The destination's host name or IP address literal. A name is sent for the proxy to resolve.
    /// </param>
    /// <param name="port">The destination's port, from 1 to 65535.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> or <paramref name="host"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="host"/> is empty or white space, or its UTF-8 form exceeds 255 bytes; or a credential in
    /// the options exceeds 255 bytes.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="port"/> is zero or negative, or above 65535 when <paramref name="host"/> is an IP address
    /// literal.
    /// </exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request; <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">The proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">
    /// The proxy chose an authentication method this client lacks, or answered with an unknown address type.
    /// </exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="EndOfStreamException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);

        // IP literals are sent as-is; host names are sent as SOCKS5 domain addresses so the
        // proxy resolves them remotely (no local DNS lookup or leak)
        if (IPAddress.TryParse(host, out var ipAddress)) {
            await ConnectAsync(tcpClient, new IPEndPoint(ipAddress, port), cancellationToken).ConfigureAwait(false);
            return;
        }

        logger?.LogDebug("Connecting to {Host}:{Port} through SOCKS5 proxy {ProxyEndPoint}", host, port, ProxyEndPoint);

        try {
            var stream = await GetAuthenticatedStreamAsync(tcpClient, cancellationToken).ConfigureAwait(false);
            var result = await SendCommandAndReadReplyAsync(stream, Socks5Command.Connect, host, null, port, cancellationToken).ConfigureAwait(false);
            if (result.Reply != Socks5CommandReply.Succeeded)
                throw MapSocksErrorToException(result.Reply);

            logger?.LogDebug("SOCKS5 CONNECT tunnel established to {Host}:{Port}", host, port);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to connect to {Host}:{Port} through SOCKS5 proxy", host, port);
            tcpClient.Close();
            throw;
        }
    }

    /// <summary>
    /// Connects to the proxy and runs the method negotiation and the authentication, without asking for a
    /// tunnel.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to check. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> first.
    /// After the check it stays open and authenticated, so a later <see cref="ConnectAsync(TcpClient, string, int, CancellationToken)"/>
    /// or <see cref="CreateUdpAssociateAsync(TcpClient, CancellationToken)"/> on it skips the negotiation. When
    /// the check fails, it is closed.
    /// </param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the check passes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A credential in the options exceeds 255 bytes.</exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">The proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">The proxy chose an authentication method this client lacks.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="EndOfStreamException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);

        try {
            await GetAuthenticatedStreamAsync(tcpClient, cancellationToken).ConfigureAwait(false);
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    /// <summary>
    /// Opens a tunnel through the proxy to an IP endpoint.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> and
    /// authenticated first. When the task completes, its <see cref="TcpClient.GetStream"/> carries the tunnel;
    /// when the exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="destination">The destination's IPv4 or IPv6 address and port.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> or <paramref name="destination"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A credential in the options exceeds 255 bytes.</exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request; <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">The proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">
    /// The destination is neither IPv4 nor IPv6, or the proxy chose an authentication method this client
    /// lacks, or answered with an unknown address type.
    /// </exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="EndOfStreamException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentNullException.ThrowIfNull(destination);

        logger?.LogDebug("Connecting to {Destination} through SOCKS5 proxy {ProxyEndPoint}", destination, ProxyEndPoint);

        try {
            var stream = await GetAuthenticatedStreamAsync(tcpClient, cancellationToken).ConfigureAwait(false);
            var result = await SendCommandAndReadReplyAsync(stream, Socks5Command.Connect, null, destination.Address, destination.Port, cancellationToken).ConfigureAwait(false);
            if (result.Reply != Socks5CommandReply.Succeeded)
                throw MapSocksErrorToException(result.Reply);

            logger?.LogDebug("SOCKS5 CONNECT tunnel established to {Destination}", destination);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to connect to {Destination} through SOCKS5 proxy", destination);
            tcpClient.Close();
            throw;
        }
    }

    /// <summary>
    /// Asks the proxy to relay UDP datagrams for this client, without saying which local endpoint will send
    /// them.
    /// </summary>
    /// <remarks>
    /// The proxy learns the client's UDP endpoint from the datagrams it receives; the server of this library
    /// takes the first datagram from the address of <paramref name="tcpClient"/>'s connection.
    /// </remarks>
    /// <param name="tcpClient">
    /// The control connection. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> and
    /// authenticated first. The association lasts as long as it stays open: keep it open, and send nothing
    /// more on it, while datagrams flow; close it to end the association. The server of this library also
    /// ends it when anything arrives on it. When the exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. Its result is the proxy's relay endpoint: send each
    /// datagram there, wrapped by <see cref="WriteUdpRequest"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A credential in the options exceeds 255 bytes.</exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request; <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">The proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">
    /// The proxy chose an authentication method this client lacks, or gave its relay endpoint as a domain name
    /// or with an unknown address type.
    /// </exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="EndOfStreamException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task<IPEndPoint> CreateUdpAssociateAsync(TcpClient tcpClient, CancellationToken cancellationToken) =>
        await CreateUdpAssociateAsync(tcpClient, null, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Asks the proxy to relay UDP datagrams sent from a local endpoint.
    /// </summary>
    /// <example>
    /// <code snippet="Snippet:Socks5Udp" language="csharp">
    /// var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
    ///     ProxyEndPoint = proxyEndPoint
    /// });
    ///
    /// // the local UDP socket that exchanges datagrams with the proxy
    /// using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    /// var localUdpEndPoint = (IPEndPoint)udp.Client.LocalEndPoint!;
    ///
    /// // the association lasts while this TCP control connection stays open, with nothing more sent on it
    /// using var controlTcp = new TcpClient();
    /// var relayEndPoint = await client.CreateUdpAssociateAsync(controlTcp, localUdpEndPoint, CancellationToken.None);
    ///
    /// // wrap the payload in the SOCKS5 UDP header (10 bytes for IPv4, 22 for IPv6) and send it to the relay
    /// var buffer = new byte[22 + payload.Length];
    /// var length = Socks5ProxyClient.WriteUdpRequest(buffer, destination, payload);
    /// await udp.SendAsync(buffer.AsMemory(0, length), relayEndPoint);
    ///
    /// // receive the answer and unwrap it
    /// var result = await udp.ReceiveAsync();
    /// var from = Socks5ProxyClient.ParseUdpResponse(result.Buffer, out var answer);
    /// </code>
    /// </example>
    /// <param name="tcpClient">
    /// The control connection. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> and
    /// authenticated first. The association lasts as long as it stays open: keep it open, and send nothing
    /// more on it, while datagrams flow; close it to end the association. The server of this library also
    /// ends it when anything arrives on it. When the exchange with the proxy fails, it is closed.
    /// </param>
    /// <param name="clientUdpEndPoint">
    /// The address and port the client will send datagrams from, as the proxy sees them, or
    /// <see langword="null"/> when unknown, for example behind NAT. A proxy may relay only datagrams from it,
    /// as the server of this library does; that server takes a port of 0 as unknown, address included, and an
    /// unspecified address with a port as the control connection's address.
    /// </param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. Its result is the proxy's relay endpoint: send each
    /// datagram there, wrapped by <see cref="WriteUdpRequest"/>. When the proxy answers with an unspecified
    /// address, the result has the address of <see cref="ProxyEndPoint"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A credential in the options exceeds 255 bytes.</exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request; <see cref="SocketException.SocketErrorCode"/> tells why.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The proxy requires credentials the options lack, refused them, or accepts none of the offered methods.
    /// </exception>
    /// <exception cref="ProtocolViolationException">The proxy's answer is not SOCKS5.</exception>
    /// <exception cref="NotSupportedException">
    /// <paramref name="clientUdpEndPoint"/> is neither IPv4 nor IPv6, the proxy chose an authentication method
    /// this client lacks, or it gave its relay endpoint as a domain name or with an unknown address type.
    /// </exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="EndOfStreamException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task<IPEndPoint> CreateUdpAssociateAsync(TcpClient tcpClient, IPEndPoint? clientUdpEndPoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);

        logger?.LogDebug("Creating UDP associate through SOCKS5 proxy");

        try {
            var stream = await GetAuthenticatedStreamAsync(tcpClient, cancellationToken).ConfigureAwait(false);

            var endpointToSend = clientUdpEndPoint ?? new IPEndPoint(IPAddress.Any, 0);
            var result = await SendCommandAndReadReplyAsync(stream, Socks5Command.UdpAssociate, null, endpointToSend.Address, endpointToSend.Port, cancellationToken).ConfigureAwait(false);
            if (result.Reply != Socks5CommandReply.Succeeded)
                throw MapSocksErrorToException(result.Reply);

            var boundAddress = result.BoundEndpoint.Address;
            if (boundAddress == null)
            {
                throw new NotSupportedException("Proxy returned an unsupported address type for UDP ASSOCIATE");
            }

            // RFC 1928: if BND.ADDRESS is 0.0.0.0 (or ::), use the proxy's address for sending datagrams
            var resultAddress = boundAddress.Equals(IPAddress.Any) || boundAddress.Equals(IPAddress.IPv6Any)
                ? ProxyEndPoint.Address
                : boundAddress;

            var udpEndpoint = new IPEndPoint(resultAddress, result.BoundEndpoint.Port);
            logger?.LogDebug("UDP associate established on {UdpEndpoint}", udpEndpoint);

            return udpEndpoint;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to create UDP associate through SOCKS5 proxy");
            tcpClient.Close();
            throw;
        }
    }

    private async Task<NetworkStream> GetAuthenticatedStreamAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        if (!tcpClient.Connected) {
            tcpClient.NoDelay = true;
            await tcpClient.ConnectAsync(ProxyEndPoint, cancellationToken).ConfigureAwait(false);
        }

        var stream = tcpClient.GetStream();
        if (!_authenticatedConnections.TryGetValue(tcpClient, out _)) {
            await PerformAuthenticationAsync(stream, cancellationToken).ConfigureAwait(false);
            _authenticatedConnections.AddOrUpdate(tcpClient, new object());
        }

        return stream;
    }

    private async Task PerformAuthenticationAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        logger?.LogDebug("Performing SOCKS5 authentication negotiation");

        // Send authentication methods
        var hasCredentials = !string.IsNullOrEmpty(options.Username);
        var methods = hasCredentials
            ? new byte[] { 5, 2, (byte)Socks5AuthenticationType.NoAuthenticationRequired, (byte)Socks5AuthenticationType.UsernamePassword }
            : new byte[] { 5, 1, (byte)Socks5AuthenticationType.NoAuthenticationRequired };

        await stream.WriteAsync(methods, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Read server response
        var response = new byte[2];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);

        if (response[0] != 5)
            throw new ProtocolViolationException($"Invalid SOCKS version in response: {response[0]}");

        var selectedMethod = (Socks5AuthenticationType)response[1];
        logger?.LogDebug("Server selected authentication method: {Method}", selectedMethod);

        switch (selectedMethod)
        {
            case Socks5AuthenticationType.NoAuthenticationRequired:
                logger?.LogDebug("No authentication required");
                break;

            case Socks5AuthenticationType.UsernamePassword:
                if (string.IsNullOrEmpty(options.Username))
                {
                    throw new UnauthorizedAccessException("Server requires username/password authentication but no credentials provided");
                }
                await PerformUsernamePasswordAuthAsync(stream, options.Username, options.Password ?? string.Empty, cancellationToken).ConfigureAwait(false);
                break;

            case Socks5AuthenticationType.ReplyNoAcceptableMethods:
                throw new UnauthorizedAccessException("No acceptable authentication methods found");

            default:
                throw new NotSupportedException($"Authentication method {selectedMethod} is not supported");
        }
    }

    private async Task PerformUsernamePasswordAuthAsync(NetworkStream stream, string username, string password, CancellationToken cancellationToken)
    {
        logger?.LogDebug("Performing username/password authentication for user: {Username}", username);

        var authBuffer = ConstructAuthBuffer(username, password);
        await stream.WriteAsync(authBuffer, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var response = new byte[2];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);

        if (response[0] != 1)
            throw new ProtocolViolationException($"Invalid username/password auth version: {response[0]}");

        if (response[1] != 0)
            throw new UnauthorizedAccessException("Username/password authentication failed");

        logger?.LogDebug("Username/password authentication successful");
    }

    private static async Task<Socks5CommandResult> SendCommandAndReadReplyAsync(NetworkStream stream, Socks5Command command,
        string? host, IPAddress? address, int port, CancellationToken cancellationToken)
    {
        // Build destination address (ATYP + address bytes)
        byte addressType;
        byte[] addressBytes;
        if (address is not null) {
            addressType = GetAddressType(address.AddressFamily);
            addressBytes = address.GetAddressBytes();
        }
        else {
            var hostBytes = Encoding.UTF8.GetBytes(host ?? throw new ArgumentNullException(nameof(host)));
            if (hostBytes.Length > 255)
                throw new ArgumentException("Host name exceeds maximum length of 255 bytes.", nameof(host));

            addressType = (byte)Socks5AddressType.DomainName;
            addressBytes = new byte[1 + hostBytes.Length];
            addressBytes[0] = (byte)hostBytes.Length;
            hostBytes.CopyTo(addressBytes, 1);
        }

        // Build and send request
        var request = new byte[4 + addressBytes.Length + 2];
        request[0] = 5; // Version
        request[1] = (byte)command;
        request[2] = 0; // Reserved
        request[3] = addressType;

        addressBytes.CopyTo(request, 4);
        request[4 + addressBytes.Length] = (byte)(port >> 8);
        request[5 + addressBytes.Length] = (byte)(port & 0xFF);

        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Read response header
        var responseHeader = new byte[4];
        await stream.ReadExactlyAsync(responseHeader, cancellationToken).ConfigureAwait(false);

        if (responseHeader[0] != 5)
            throw new ProtocolViolationException($"Invalid SOCKS version in reply: {responseHeader[0]}");

        var reply = (Socks5CommandReply)responseHeader[1];
        var replyAddressType = (Socks5AddressType)responseHeader[3];

        // Read bound address and port
        var boundEndpoint = await ReadAddressPortAsync(stream, replyAddressType, cancellationToken).ConfigureAwait(false);

        return new Socks5CommandResult(command, reply, boundEndpoint);
    }

    private static async Task<Socks5Endpoint> ReadAddressPortAsync(NetworkStream stream, Socks5AddressType addressType, CancellationToken cancellationToken)
    {
        switch (addressType)
        {
            case Socks5AddressType.IpV4:
                var ipv4Buffer = new byte[6]; // 4 bytes IP + 2 bytes port
                await stream.ReadExactlyAsync(ipv4Buffer, cancellationToken).ConfigureAwait(false);
                var ipv4Address = new IPAddress(ipv4Buffer.AsSpan(0, 4));
                var ipv4Port = ipv4Buffer[4] << 8 | ipv4Buffer[5];
                return new Socks5Endpoint(null, ipv4Address, ipv4Port);

            case Socks5AddressType.IpV6:
                var ipv6Buffer = new byte[18]; // 16 bytes IP + 2 bytes port
                await stream.ReadExactlyAsync(ipv6Buffer, cancellationToken).ConfigureAwait(false);
                var ipv6Address = new IPAddress(ipv6Buffer.AsSpan(0, 16));
                var ipv6Port = ipv6Buffer[16] << 8 | ipv6Buffer[17];
                return new Socks5Endpoint(null, ipv6Address, ipv6Port);

            case Socks5AddressType.DomainName:
                var lengthBuffer = new byte[1];
                await stream.ReadExactlyAsync(lengthBuffer, cancellationToken).ConfigureAwait(false);
                var domainLength = lengthBuffer[0];

                var domainBuffer = new byte[domainLength + 2];
                await stream.ReadExactlyAsync(domainBuffer, cancellationToken).ConfigureAwait(false);

                var domain = Encoding.UTF8.GetString(domainBuffer.AsSpan(0, domainLength));
                var domainPort = domainBuffer[domainLength] << 8 | domainBuffer[domainLength + 1];

                return new Socks5Endpoint(domain, null, domainPort);

            default:
                throw new NotSupportedException($"Unsupported address type in reply: {addressType}");
        }
    }

    private static byte GetAddressType(AddressFamily addressFamily) =>
        addressFamily switch {
            AddressFamily.InterNetwork => (byte)Socks5AddressType.IpV4,
            AddressFamily.InterNetworkV6 => (byte)Socks5AddressType.IpV6,
            _ => throw new NotSupportedException($"Unsupported address family: {addressFamily}")
        };

    private static Memory<byte> ConstructAuthBuffer(string username, string password)
    {
        var usernameBytes = Encoding.UTF8.GetBytes(username);
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        if (usernameBytes.Length > 255)
        {
            throw new ArgumentException("Username exceeds maximum length of 255 bytes", nameof(username));
        }

        if (passwordBytes.Length > 255)
        {
            throw new ArgumentException("Password exceeds maximum length of 255 bytes", nameof(password));
        }

        var buffer = new byte[3 + usernameBytes.Length + passwordBytes.Length];
        buffer[0] = 1; // Version
        buffer[1] = (byte)usernameBytes.Length;
        usernameBytes.CopyTo(buffer, 2);
        buffer[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
        passwordBytes.CopyTo(buffer, 3 + usernameBytes.Length);

        return new Memory<byte>(buffer);
    }

    private static Exception MapSocksErrorToException(Socks5CommandReply reply) =>
        reply switch {
            Socks5CommandReply.GeneralSocksServerFailure => new ProxyClientException(SocketError.SocketError, "General SOCKS server failure"),
            Socks5CommandReply.ConnectionNotAllowedByRuleset => new ProxyClientException(SocketError.AccessDenied, "Connection not allowed by ruleset"),
            Socks5CommandReply.NetworkUnreachable => new ProxyClientException(SocketError.NetworkUnreachable, "Network unreachable"),
            Socks5CommandReply.HostUnreachable => new ProxyClientException(SocketError.HostUnreachable, "Host unreachable"),
            Socks5CommandReply.ConnectionRefused => new ProxyClientException(SocketError.ConnectionRefused, "Connection refused"),
            Socks5CommandReply.TtlExpired => new ProxyClientException(SocketError.TimedOut, "TTL expired"),
            Socks5CommandReply.CommandNotSupported => new ProxyClientException(SocketError.OperationNotSupported, "Command not supported"),
            Socks5CommandReply.AddressTypeNotSupported => new ProxyClientException(SocketError.AddressFamilyNotSupported, "Address type not supported"),
            _ => new ProxyClientException(SocketError.ProtocolNotSupported, $"Unknown SOCKS5 error: {reply}")
        };

    /// <summary>
    /// Wraps a datagram in the SOCKS5 UDP request header (RFC 1928, section 7), ready to send to the relay
    /// endpoint of a UDP association.
    /// </summary>
    /// <param name="destinationBuffer">
    /// The buffer to write to. It needs 10 bytes more than <paramref name="data"/> for an IPv4 destination and
    /// 22 bytes more for an IPv6 one.
    /// </param>
    /// <param name="destination">The datagram's destination.</param>
    /// <param name="data">The datagram's payload.</param>
    /// <returns>The number of bytes written to <paramref name="destinationBuffer"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="destination"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="destinationBuffer"/> is too small.</exception>
    /// <exception cref="NotSupportedException"><paramref name="destination"/> is neither IPv4 nor IPv6.</exception>
    public static int WriteUdpRequest(Span<byte> destinationBuffer, IPEndPoint destination, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(destination);

        var addressBytes = destination.Address.GetAddressBytes();
        var addressType = GetAddressType(destination.AddressFamily);
        var requiredSize = 3 + 1 + addressBytes.Length + 2 + data.Length;

        if (destinationBuffer.Length < requiredSize)
        {
            throw new ArgumentException($"Destination buffer too small. Required: {requiredSize}, Available: {destinationBuffer.Length}", nameof(destinationBuffer));
        }

        var offset = 0;
        destinationBuffer[offset++] = 0; // Reserved
        destinationBuffer[offset++] = 0; // Reserved
        destinationBuffer[offset++] = 0; // Fragment
        destinationBuffer[offset++] = addressType;

        addressBytes.CopyTo(destinationBuffer[offset..]);
        offset += addressBytes.Length;

        destinationBuffer[offset++] = (byte)(destination.Port >> 8);
        destinationBuffer[offset++] = (byte)(destination.Port & 0xFF);

        data.CopyTo(destinationBuffer[offset..]);
        offset += data.Length;

        return offset;
    }

    /// <summary>
    /// Reads the SOCKS5 UDP header of a datagram received from the relay endpoint of a UDP association.
    /// </summary>
    /// <param name="datagram">The datagram as received from the relay.</param>
    /// <param name="payload">
    /// When this method returns, the datagram's payload: a slice of <paramref name="datagram"/>, not a copy.
    /// </param>
    /// <returns>The address and port the payload came from.</returns>
    /// <exception cref="ArgumentException"><paramref name="datagram"/> is shorter than 7 bytes.</exception>
    /// <exception cref="NotSupportedException">
    /// The datagram is a fragment, its reserved bytes are not zero, or its address type is unknown.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">The datagram ends inside its address.</exception>
    /// <exception cref="IndexOutOfRangeException">The datagram ends inside its port.</exception>
    public static Socks5Endpoint ParseUdpResponse(ReadOnlySpan<byte> datagram, out ReadOnlySpan<byte> payload)
    {
        if (datagram.Length < 7)
            throw new ArgumentException("Datagram too short for SOCKS5 UDP response", nameof(datagram));

        if (datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0)
            throw new NotSupportedException("Fragmented or malformed SOCKS5 UDP packet");

        var addressType = (Socks5AddressType)datagram[3];
        var offset = 4;

        string? host = null;
        IPAddress? address = null;

        switch (addressType)
        {
            case Socks5AddressType.IpV4:
                address = new IPAddress(datagram.Slice(offset, 4));
                offset += 4;
                break;

            case Socks5AddressType.IpV6:
                address = new IPAddress(datagram.Slice(offset, 16));
                offset += 16;
                break;

            case Socks5AddressType.DomainName:
                var domainLength = datagram[offset++];
                host = Encoding.UTF8.GetString(datagram.Slice(offset, domainLength));
                offset += domainLength;
                break;

            default:
                throw new NotSupportedException($"Unsupported address type in UDP response: {addressType}");
        }

        var port = datagram[offset] << 8 | datagram[offset + 1];
        offset += 2;

        payload = datagram[offset..];
        return new Socks5Endpoint(host, address, port);
    }
}
