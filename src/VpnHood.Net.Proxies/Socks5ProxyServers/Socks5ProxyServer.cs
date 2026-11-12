using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using VpnHood.Net.Proxies.Socks5Proxy;
using System.Buffers;

namespace VpnHood.Net.Proxies.Socks5ProxyServers;

/// <summary>
/// Represents a SOCKS5 proxy server (RFC 1928) that serves CONNECT and UDP ASSOCIATE requests, with optional
/// username and password authentication (RFC 1929).
/// </summary>
/// <remarks>
/// <para>
/// The server resolves a domain name in a request itself, and prefers an IPv4 address; a name it cannot look
/// up gets <see cref="Socks5CommandReply.HostUnreachable"/>. It answers BIND, and any other command, with
/// <see cref="Socks5CommandReply.CommandNotSupported"/>, and an address type it does not know with
/// <see cref="Socks5CommandReply.AddressTypeNotSupported"/>.
/// </para>
/// <para>
/// A UDP association relays datagrams between the client and the destinations it sends to, until the
/// request's TCP connection closes; what arrives on that connection meanwhile is discarded. The client's
/// datagrams are taken from the UDP endpoint it declared, where an unspecified address stands for its TCP
/// connection's; when it declared none (port zero), the first datagram from its address claims the
/// association. Replies are taken from the destinations the client has sent to. Datagrams from any other
/// sender, and fragmented ones, are dropped. The relay socket takes the address family of the TCP connection,
/// so an association made over IPv4 reaches only IPv4 destinations. An association remembers up to 2048
/// destinations; past that, it forgets those silent for 60 seconds, then the least recently active, and drops
/// what a forgotten destination sends.
/// </para>
/// </remarks>
/// <example>
/// <code snippet="Snippet:Socks5Server" language="csharp">
/// using var server = new Socks5ProxyServer(new Socks5ProxyServerOptions {
///     ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
///     Username = null, // set a user name to require RFC 1929 authentication
///     Password = null
/// });
///
/// server.Start(); // or: await server.RunAsync(cancellationToken);
/// var proxyEndPoint = server.ListenerEndPoint;
/// </code>
/// </example>
/// <param name="options">The server's settings.</param>
/// <param name="logger">The logger for the server's events, or <see langword="null"/> for none.</param>
/// <exception cref="ArgumentNullException"><see cref="Socks5ProxyServerOptions.ListenEndPoint"/> is <see langword="null"/>.</exception>
/// <exception cref="ArgumentOutOfRangeException">
/// <see cref="Socks5ProxyServerOptions.Backlog"/> or <see cref="Socks5ProxyServerOptions.MaxConnections"/> is zero
/// or negative.
/// </exception>
public sealed class Socks5ProxyServer(
    Socks5ProxyServerOptions options,
    ILogger<Socks5ProxyServer>? logger = null)
    : TcpProxyServerBase(options.ListenEndPoint, options.Backlog, options.MaxConnections, logger)
{
    // Bounds for the per-association UDP destination table. A client can keep one association
    // open indefinitely and contact ever more endpoints; without a cap the table (and therefore
    // memory) would grow without limit.
    private const int MaxUdpDestinations = 2048;
    private static readonly TimeSpan UdpDestinationIdleTimeout = TimeSpan.FromSeconds(60);

    /// <inheritdoc/>
    protected override async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var clientEndpoint = TryGetRemoteEndPoint(client) ?? new IPEndPoint(IPAddress.None, 0);
        Logger.LogDebug("Handling SOCKS5 client connection from {ClientEndpoint}", clientEndpoint);

        try
        {
            using var clientToDispose = client; // ensure disposal on all paths
            client.NoDelay = true;
            var networkStream = client.GetStream();

            // Perform handshake
            var handshakeResult = await PerformHandshakeAsync(networkStream, clientEndpoint, cancellationToken).ConfigureAwait(false);
            if (!handshakeResult.IsValid)
                return;

            var request = handshakeResult.RequestHeader;
            Logger.LogDebug("Processing {Command} command from {ClientEndpoint}", request.Command, clientEndpoint);

            // Handle request based on command
            switch (request.Command)
            {
                case Socks5Command.Connect:
                    {
                        await HandleConnectCommandAsync(networkStream, request.Destination, clientEndpoint, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                case Socks5Command.UdpAssociate:
                    {
                        await HandleUdpAssociateCommandAsync(networkStream, client,
                            request.Destination, clientEndpoint, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                default:
                    {
                        Logger.LogWarning("Unsupported command {Command} from {ClientEndpoint}", request.Command, clientEndpoint);
                        await SendReplyAsync(networkStream, Socks5CommandReply.CommandNotSupported, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
                        break;
                    }
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpoint);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error handling SOCKS5 client {ClientEndpoint}", clientEndpoint);
        }
    }

    private async Task<Socks5HandshakeResult> PerformHandshakeAsync(NetworkStream networkStream,
        IPEndPoint clientEndpoint, CancellationToken cancellationToken)
    {
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(options.HandshakeTimeout);

            // Authentication negotiation
            var authType = await NegotiateAuthAsync(networkStream, requireAuth: options.Username != null, handshakeCts.Token).ConfigureAwait(false);
            if (authType == Socks5AuthenticationType.UsernamePassword)
            {
                var authResult = await HandleUserPassAuthAsync(networkStream, options.Username,
                    options.Password ?? string.Empty, handshakeCts.Token).ConfigureAwait(false);

                Logger.LogDebug("Authentication result for {ClientEndpoint}: {AuthResult}", clientEndpoint, authResult);
                if (!authResult)
                    return Socks5HandshakeResult.Invalid;
            }

            // The request shares the handshake's time: a client that negotiates and then asks for nothing would
            // hold its connection for as long as it liked
            var requestHeader = await ReadRequestHeaderAsync(networkStream, handshakeCts.Token).ConfigureAwait(false);
            if (requestHeader is null)
            {
                Logger.LogWarning("Unsupported address type from {ClientEndpoint}", clientEndpoint);
                await SendReplyAsync(networkStream, Socks5CommandReply.AddressTypeNotSupported, IPAddress.Any, 0, handshakeCts.Token).ConfigureAwait(false);
                return Socks5HandshakeResult.Invalid;
            }

            return Socks5HandshakeResult.Valid(authType, requestHeader);
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Handshake cancelled for {ClientEndpoint}", clientEndpoint);
            return Socks5HandshakeResult.Invalid;
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error during handshake for {ClientEndpoint}", clientEndpoint);
            return Socks5HandshakeResult.Invalid;
        }
    }

    private static async Task<Socks5AuthenticationType> NegotiateAuthAsync(NetworkStream stream, bool requireAuth, CancellationToken cancellationToken)
    {
        // Read version and number of methods
        var header = new byte[2];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        if (header[0] != 5)
        {
            throw new ProtocolViolationException($"Invalid SOCKS version: {header[0]}");
        }

        var numberOfMethods = header[1];
        if (numberOfMethods == 0)
        {
            throw new ProtocolViolationException("No authentication methods provided");
        }

        // Read supported methods
        var methods = new byte[numberOfMethods];
        await stream.ReadExactlyAsync(methods, cancellationToken).ConfigureAwait(false);

        var supportsUserPass = methods.Contains((byte)Socks5AuthenticationType.UsernamePassword);
        var supportsNoAuth = methods.Contains((byte)Socks5AuthenticationType.NoAuthenticationRequired);

        Socks5AuthenticationType selectedAuthType;

        if (requireAuth)
        {
            if (!supportsUserPass)
            {
                // Send "no acceptable methods" response
                await stream.WriteAsync(new byte[] { 5, (byte)Socks5AuthenticationType.ReplyNoAcceptableMethods }, cancellationToken).ConfigureAwait(false);
                throw new UnauthorizedAccessException("Client does not support required authentication method");
            }
            selectedAuthType = Socks5AuthenticationType.UsernamePassword;
        }
        else
        {
            // Prefer no auth if available, otherwise username/password
            selectedAuthType = supportsNoAuth ? Socks5AuthenticationType.NoAuthenticationRequired :
                      supportsUserPass ? Socks5AuthenticationType.UsernamePassword :
                      Socks5AuthenticationType.ReplyNoAcceptableMethods;

            if (selectedAuthType == Socks5AuthenticationType.ReplyNoAcceptableMethods)
            {
                await stream.WriteAsync(new byte[] { 5, (byte)selectedAuthType }, cancellationToken).ConfigureAwait(false);
                throw new UnauthorizedAccessException("No acceptable authentication methods found");
            }
        }

        // Send selected method
        await stream.WriteAsync(new byte[] { 5, (byte)selectedAuthType }, cancellationToken).ConfigureAwait(false);

        return selectedAuthType;
    }

    private static async Task<bool> HandleUserPassAuthAsync(NetworkStream stream, string? expectedUsername, string expectedPassword, CancellationToken cancellationToken)
    {
        // Read version
        var version = new byte[1];
        await stream.ReadExactlyAsync(version, cancellationToken).ConfigureAwait(false);

        if (version[0] != 1)
        {
            await stream.WriteAsync(new byte[] { 1, 0xFF }, cancellationToken).ConfigureAwait(false);
            return false;
        }

        // Read username length
        var usernameLengthBuffer = new byte[1];
        await stream.ReadExactlyAsync(usernameLengthBuffer, cancellationToken).ConfigureAwait(false);
        var usernameLength = usernameLengthBuffer[0];

        // Read username
        var usernameBytes = new byte[usernameLength];
        await stream.ReadExactlyAsync(usernameBytes, cancellationToken).ConfigureAwait(false);

        // Read password length
        var passwordLengthBuffer = new byte[1];
        await stream.ReadExactlyAsync(passwordLengthBuffer, cancellationToken).ConfigureAwait(false);
        var passwordLength = passwordLengthBuffer[0];

        // Read password
        var passwordBytes = new byte[passwordLength];
        await stream.ReadExactlyAsync(passwordBytes, cancellationToken).ConfigureAwait(false);

        // Validate credentials; when the server has no credentials configured, any client
        // credentials are accepted (the client just insisted on the user/pass method)
        var username = Encoding.UTF8.GetString(usernameBytes);
        var password = Encoding.UTF8.GetString(passwordBytes);

        var isValid = expectedUsername == null ||
                      (string.Equals(username, expectedUsername, StringComparison.Ordinal) &&
                       string.Equals(password, expectedPassword, StringComparison.Ordinal));

        // Send response
        await stream.WriteAsync(new byte[] { 1, (byte)(isValid ? 0 : 0xFF) }, cancellationToken).ConfigureAwait(false);

        return isValid;
    }

    // Reads the whole request: its header, then the destination's address and port. The result is null for an
    // address type the server does not know, as nothing tells how many of the bytes that follow belong to it.
    private static async Task<RequestHeader?> ReadRequestHeaderAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var requestHeaderBytes = new byte[4];
        await stream.ReadExactlyAsync(requestHeaderBytes, cancellationToken).ConfigureAwait(false);

        if (requestHeaderBytes[0] != 5)
        {
            throw new ProtocolViolationException($"Invalid SOCKS version in request: {requestHeaderBytes[0]}");
        }

        var destination = await ReadDestinationAsync(stream, (Socks5AddressType)requestHeaderBytes[3], cancellationToken).ConfigureAwait(false);
        if (destination is null)
            return null;

        return new RequestHeader
        {
            Command = (Socks5Command)requestHeaderBytes[1],
            Destination = destination.Value
        };
    }

    private async Task HandleConnectCommandAsync(NetworkStream clientStream, Socks5Endpoint destination,
        IPEndPoint clientEndpoint, CancellationToken cancellationToken)
    {
        try
        {
            Logger.LogDebug("Connecting to {Destination} for {ClientEndpoint}", destination, clientEndpoint);

            using var remoteClient = await ConnectToDestinationAsync(destination, cancellationToken).ConfigureAwait(false);

            var localEndPoint = (IPEndPoint)remoteClient.Client.LocalEndPoint!;
            await SendReplyAsync(clientStream, Socks5CommandReply.Succeeded, localEndPoint.Address, localEndPoint.Port, cancellationToken).ConfigureAwait(false);

            Logger.LogDebug("Tunneling established between {ClientEndpoint} and {Destination}", clientEndpoint, destination);

            var remoteStream = remoteClient.GetStream();
            await ProxyStreamPump.PumpStreamsAsync(clientStream, remoteStream, options.TunnelHalfCloseTimeout,
                cancellationToken, remoteSocket: remoteClient.Client).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.TtlExpired, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException exception) when (exception.SocketErrorCode == SocketError.ConnectionRefused)
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.ConnectionRefused, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException exception) when (exception.SocketErrorCode == SocketError.HostUnreachable || IsNameLookupFailure(exception))
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.HostUnreachable, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException exception) when (exception.SocketErrorCode == SocketError.NetworkUnreachable)
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.NetworkUnreachable, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Failed to establish connection to {Destination} for {ClientEndpoint}", destination, clientEndpoint);
            await SendReplyAsync(clientStream, Socks5CommandReply.GeneralSocksServerFailure, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
    }

    // The lookup of a domain name and the connect share one limit: both are the time the destination takes
    private async Task<TcpClient> ConnectToDestinationAsync(Socks5Endpoint destination, CancellationToken cancellationToken)
    {
        using var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectionCts.CancelAfter(options.HostConnectionTimeout);

        var address = await ResolveAddressAsync(destination, connectionCts.Token).ConfigureAwait(false);
        var remoteClient = new TcpClient(address.AddressFamily);
        try
        {
            remoteClient.NoDelay = true;
            await remoteClient.ConnectAsync(address, destination.Port, connectionCts.Token).ConfigureAwait(false);
            return remoteClient;
        }
        catch
        {
            remoteClient.Dispose();
            throw;
        }
    }

    // A domain name gives its IPv4 address when it has one
    private static async Task<IPAddress> ResolveAddressAsync(Socks5Endpoint endpoint, CancellationToken cancellationToken)
    {
        if (endpoint.Address is not null)
            return endpoint.Address;

        var host = endpoint.Host ?? throw new ArgumentException("The endpoint has neither an address nor a host name.", nameof(endpoint));
        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        return addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork)
               ?? addresses.FirstOrDefault()
               ?? throw new SocketException((int)SocketError.HostNotFound);
    }

    private static bool IsNameLookupFailure(SocketException exception) =>
        exception.SocketErrorCode is SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoRecovery or SocketError.NoData;

    private async Task HandleUdpAssociateCommandAsync(NetworkStream stream, TcpClient controlTcpClient,
        Socks5Endpoint declaredEndpoint, IPEndPoint clientEndpoint, CancellationToken cancellationToken)
    {
        // The client's declared UDP endpoint; all zeros means "unknown" (e.g., client behind NAT)
        var declaredAddress = await TryResolveDeclaredAddressAsync(stream, declaredEndpoint, clientEndpoint, cancellationToken).ConfigureAwait(false);
        if (declaredAddress is null)
            return; // the refusal is sent

        var expectedClientUdpEndpoint = GetExpectedClientUdpEndpoint(new IPEndPoint(declaredAddress, declaredEndpoint.Port), clientEndpoint);

        // Create UDP socket for communicating with the SOCKS5 client; use the control
        // connection's address family
        var controlLocalEndPoint = (IPEndPoint)controlTcpClient.Client.LocalEndPoint!;
        var bindAddress = controlLocalEndPoint.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
        using var proxyUdpClient = new UdpClient(new IPEndPoint(bindAddress, 0));
        var localEndPoint = (IPEndPoint)proxyUdpClient.Client.LocalEndPoint!;

        using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var relayTask = UdpRelayLoopAsync(proxyUdpClient, clientEndpoint, expectedClientUdpEndpoint, relayCts.Token);

        // Reply with the server address the client already reached; 0.0.0.0 confuses clients
        // that don't implement the RFC 1928 fallback
        await SendReplyAsync(stream, Socks5CommandReply.Succeeded, controlLocalEndPoint.Address,
            localEndPoint.Port, cancellationToken).ConfigureAwait(false);

        Logger.LogDebug("UDP associate established for {ClientEndpoint} on port {Port}", clientEndpoint, localEndPoint.Port);

        // RFC 1928: the association lives as long as the TCP control connection. This is the
        // only reader of the control stream: it discards whatever the client sends there, as
        // only the connection's close, or a cancellation, ends the association.
        try
        {
            var buffer = new byte[256];
            while (await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false) > 0)
            {
            }
        }
        catch (Exception ex)
        {
            Logger.LogDebug(ex, "TCP connection closed for UDP associate with {ClientEndpoint}", clientEndpoint);
        }
        finally
        {
            await relayCts.CancelAsync().ConfigureAwait(false);
            proxyUdpClient.Dispose();
            try { await relayTask.ConfigureAwait(false); }
            catch { /* relay errors are already logged */ }
        }
    }

    // A client may name its UDP endpoint by domain. A name that cannot be looked up in time refuses the
    // request: the reply is sent here, and the result is null.
    private async Task<IPAddress?> TryResolveDeclaredAddressAsync(NetworkStream stream, Socks5Endpoint declaredEndpoint,
        IPEndPoint clientEndpoint, CancellationToken cancellationToken)
    {
        try
        {
            using var lookupCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            lookupCts.CancelAfter(options.HostConnectionTimeout);
            return await ResolveAddressAsync(declaredEndpoint, lookupCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // the server stops, or the lookup ran out of time
            cancellationToken.ThrowIfCancellationRequested();
            await SendReplyAsync(stream, Socks5CommandReply.TtlExpired, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
            return null;
        }
        catch (SocketException exception)
        {
            Logger.LogWarning(exception, "Could not look up the UDP endpoint {DeclaredEndpoint} of {ClientEndpoint}", declaredEndpoint, clientEndpoint);
            await SendReplyAsync(stream, Socks5CommandReply.HostUnreachable, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
            return null;
        }
    }

    // The declared endpoint may be all zeros (unknown) or carry only a port; fall back to the
    // control connection's address in those cases
    private static IPEndPoint? GetExpectedClientUdpEndpoint(IPEndPoint declared, IPEndPoint controlClientEndpoint)
    {
        if (declared.Port == 0)
            return null;

        var address = declared.Address.Equals(IPAddress.Any) || declared.Address.Equals(IPAddress.IPv6Any)
            ? controlClientEndpoint.Address
            : declared.Address;

        return new IPEndPoint(address, declared.Port);
    }

    private async Task UdpRelayLoopAsync(UdpClient proxyUdpClient, IPEndPoint clientEndpoint,
        IPEndPoint? expectedClientUdpEndpoint, CancellationToken cancellationToken)
    {
        var clientUdpEndpoint = expectedClientUdpEndpoint;

        // destination -> last-activity (Environment.TickCount64); bounded, see TouchDestination
        var destinations = new Dictionary<IPEndPoint, long>();

        try
        {
            Logger.LogDebug("Starting UDP relay loop for {ClientEndpoint}", clientEndpoint);

            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await proxyUdpClient.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                var sourceEndpoint = result.RemoteEndPoint;
                var data = result.Buffer;

                // When the client did not declare its UDP endpoint, the first datagram coming
                // from the control connection's address claims the association
                if (clientUdpEndpoint == null && sourceEndpoint.Address.Equals(clientEndpoint.Address))
                    clientUdpEndpoint = sourceEndpoint;

                if (sourceEndpoint.Equals(clientUdpEndpoint))
                {
                    // Packet from client -> parse and forward to destination
                    await HandleUdpClientToDestinationAsync(proxyUdpClient, data, clientUdpEndpoint, destinations, cancellationToken).ConfigureAwait(false);
                }
                else if (clientUdpEndpoint != null && destinations.ContainsKey(sourceEndpoint))
                {
                    // Packet from a destination the client has contacted -> wrap and send back
                    // to client; refresh the activity stamp so live flows survive pruning
                    destinations[sourceEndpoint] = Environment.TickCount64;
                    await HandleUdpDestinationToClientAsync(proxyUdpClient, data, sourceEndpoint, clientUdpEndpoint, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    // Unknown source; do not let third parties inject datagrams into the association
                    Logger.LogDebug("Dropped UDP packet from unexpected source {Source} for {ClientEndpoint}", sourceEndpoint, clientEndpoint);
                }
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("UDP relay loop cancelled for {ClientEndpoint}", clientEndpoint);
        }
        catch (ObjectDisposedException)
        {
            Logger.LogDebug("UDP relay socket closed for {ClientEndpoint}", clientEndpoint);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error in UDP relay loop for {ClientEndpoint}", clientEndpoint);
        }
    }

    // Registers a destination while keeping the table bounded: prune idle entries first,
    // then evict the least-recently-active one if the cap is still exceeded.
    private static void TouchDestination(Dictionary<IPEndPoint, long> destinations, IPEndPoint destination)
    {
        var now = Environment.TickCount64;
        destinations[destination] = now;
        if (destinations.Count <= MaxUdpDestinations)
            return;

        var idleThreshold = now - (long)UdpDestinationIdleTimeout.TotalMilliseconds;
        foreach (var stale in destinations.Where(entry => entry.Value < idleThreshold).ToList())
            destinations.Remove(stale.Key);

        if (destinations.Count > MaxUdpDestinations)
            destinations.Remove(destinations.MinBy(entry => entry.Value).Key);
    }

    private async Task HandleUdpClientToDestinationAsync(UdpClient proxyUdpClient, byte[] data,
        IPEndPoint clientUdpEndpoint, Dictionary<IPEndPoint, long> destinations, CancellationToken cancellationToken)
    {
        if (data.Length < 7 || data[0] != 0 || data[1] != 0 || data[2] != 0)
        {
            Logger.LogWarning("Invalid SOCKS5 UDP packet format from {ClientEndpoint}", clientUdpEndpoint);
            return;
        }

        try
        {
            var offset = 3;
            var addressType = (Socks5AddressType)data[offset++];

            IPAddress? destinationAddress;

            switch (addressType)
            {
                case Socks5AddressType.IpV4:
                    destinationAddress = new IPAddress(new ReadOnlySpan<byte>(data, offset, 4));
                    offset += 4;
                    break;

                case Socks5AddressType.IpV6:
                    destinationAddress = new IPAddress(new ReadOnlySpan<byte>(data, offset, 16));
                    offset += 16;
                    break;

                case Socks5AddressType.DomainName:
                    var domainLength = data[offset++];
                    var domain = Encoding.UTF8.GetString(data, offset, domainLength);
                    offset += domainLength;

                    var addresses = await Dns.GetHostAddressesAsync(domain, cancellationToken).ConfigureAwait(false);
                    destinationAddress = addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0];
                    break;

                default:
                    Logger.LogWarning("Unsupported address type {AddressType} from {ClientEndpoint}", addressType, clientUdpEndpoint);
                    return;
            }

            var destinationPort = data[offset] << 8 | data[offset + 1];
            offset += 2;

            // Remember the destination so its responses can be relayed back to the client
            var destinationEndpoint = new IPEndPoint(destinationAddress, destinationPort);
            TouchDestination(destinations, destinationEndpoint);

            // Avoid extra allocation/copy by sending a slice of the original buffer
            _ = await proxyUdpClient.SendAsync(data.AsMemory(offset), destinationEndpoint, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogWarning(exception, "Failed to relay UDP packet from client {ClientEndpoint}", clientUdpEndpoint);
        }
    }

    private async Task HandleUdpDestinationToClientAsync(
        UdpClient proxyUdpClient,
        byte[] data,
        IPEndPoint sourceEndpoint,
        IPEndPoint clientUdpEndpoint,
        CancellationToken cancellationToken)
    {
        byte[]? packet = null;
        try
        {
            var addressBytes = sourceEndpoint.Address.GetAddressBytes();
            var headerLength = 3 + 1 + addressBytes.Length + 2;
            var totalLength = headerLength + data.Length;

            // ArrayPool over MemoryPool: no owner object allocation per datagram
            packet = ArrayPool<byte>.Shared.Rent(totalLength);
            var span = packet.AsSpan(0, totalLength);

            // RSV + FRAG
            span[0] = 0;
            span[1] = 0;
            span[2] = 0;

            // Address type
            span[3] = (byte)(sourceEndpoint.Address.AddressFamily == AddressFamily.InterNetworkV6
                ? Socks5AddressType.IpV6
                : Socks5AddressType.IpV4);

            var offset = 4;
            addressBytes.CopyTo(span[offset..]);
            offset += addressBytes.Length;

            // Port
            span[offset++] = (byte)(sourceEndpoint.Port >> 8);
            span[offset] = (byte)(sourceEndpoint.Port & 0xFF);

            // Payload
            data.AsSpan().CopyTo(span[headerLength..]);

            await proxyUdpClient.SendAsync(packet.AsMemory(0, totalLength), clientUdpEndpoint, cancellationToken).ConfigureAwait(false);

            Logger.LogDebug(
                "Relayed UDP response from {Source} to {ClientEndpoint}, payload size: {Size}, response size: {ResponseSize}",
                sourceEndpoint, clientUdpEndpoint, data.Length, totalLength);
        }
        catch (Exception exception)
        {
            Logger.LogWarning(exception,
                "Failed to relay UDP response from {Source} to client {ClientEndpoint}",
                sourceEndpoint, clientUdpEndpoint);
        }
        finally
        {
            // safe to return here: SendAsync has completed (or failed) by now
            if (packet is not null)
                ArrayPool<byte>.Shared.Return(packet);
        }
    }

    // Reads a request's address and port as the client gave them, or null for an unknown address type. A
    // domain name is not looked up here: this read is on the client's time, the lookup on the destination's.
    private static async Task<Socks5Endpoint?> ReadDestinationAsync(NetworkStream stream, Socks5AddressType addressType, CancellationToken cancellationToken)
    {
        switch (addressType)
        {
            case Socks5AddressType.IpV4:
                {
                    var buffer = new byte[6];
                    await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
                    return new Socks5Endpoint(null, new IPAddress(buffer.AsSpan(0, 4)), buffer[4] << 8 | buffer[5]);
                }
            case Socks5AddressType.IpV6:
                {
                    var buffer = new byte[18];
                    await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
                    return new Socks5Endpoint(null, new IPAddress(buffer.AsSpan(0, 16)), buffer[16] << 8 | buffer[17]);
                }
            case Socks5AddressType.DomainName:
                {
                    var lengthBuffer = new byte[1];
                    await stream.ReadExactlyAsync(lengthBuffer, cancellationToken).ConfigureAwait(false);
                    var length = lengthBuffer[0];

                    byte[]? rented = null;
                    try
                    {
                        rented = ArrayPool<byte>.Shared.Rent(length + 2);
                        var mem = rented.AsMemory(0, length + 2);
                        await stream.ReadExactlyAsync(mem, cancellationToken).ConfigureAwait(false);
                        var span = mem.Span;
                        var port = span[length] << 8 | span[length + 1];
                        var hostname = Encoding.UTF8.GetString(span[..length]);
                        return new Socks5Endpoint(hostname, null, port);
                    }
                    finally
                    {
                        if (rented is not null)
                            ArrayPool<byte>.Shared.Return(rented);
                    }
                }
            default:
                return null;
        }
    }

    private static async Task SendReplyAsync(NetworkStream stream, Socks5CommandReply reply, IPAddress bindAddress, int bindPort, CancellationToken cancellationToken)
    {
        var addressBytes = bindAddress.GetAddressBytes();
        var addressType = bindAddress.AddressFamily == AddressFamily.InterNetworkV6 ? Socks5AddressType.IpV6 : Socks5AddressType.IpV4;
        var length = 4 + addressBytes.Length + 2;
        byte[]? response = null;
        try
        {
            response = ArrayPool<byte>.Shared.Rent(length);
            response[0] = 5; response[1] = (byte)reply; response[2] = 0; response[3] = (byte)addressType;
            addressBytes.CopyTo(response, 4);
            response[4 + addressBytes.Length] = (byte)(bindPort >> 8);
            response[4 + addressBytes.Length + 1] = (byte)(bindPort & 0xFF);
            await stream.WriteAsync(response.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (response is not null)
                ArrayPool<byte>.Shared.Return(response);
        }
    }
}
