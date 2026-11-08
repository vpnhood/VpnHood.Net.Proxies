using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VpnHood.Net.Proxies.HttpProxyServers;

/// <summary>
/// Represents an HTTP proxy server that opens CONNECT tunnels and forwards plain HTTP requests, with optional
/// Basic authentication.
/// </summary>
/// <remarks>
/// A request with an absolute URI, such as <c>GET http://example.com/ HTTP/1.1</c>, goes to its origin with the
/// client's headers, minus the hop-by-hop ones (RFC 9110, section 7.6.1), and with <c>Connection: close</c>, so
/// each such request takes a client connection of its own. A request with an invalid URI gets 400 Bad Request,
/// and one whose origin cannot be reached gets 502 Bad Gateway, or 504 Gateway Timeout when the connection
/// attempt runs out of time. A request rejected while it is parsed may get 400 Bad Request or be closed without
/// an answer.
/// </remarks>
/// <example>
/// <code snippet="Snippet:HttpServer" language="csharp">
/// using var server = new HttpProxyServer(new HttpProxyServerOptions {
///     ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
///     Username = "user", // set a user name to require Basic authentication
///     Password = "pass"
/// });
///
/// server.Start();
/// var proxyEndPoint = server.ListenerEndPoint;
/// </code>
/// </example>
/// <param name="options">The server's settings. <see cref="HttpProxyServerOptions.ServerCertificate"/> is ignored.</param>
/// <param name="logger">The logger for the server's events, or <see langword="null"/> for none.</param>
/// <exception cref="ArgumentOutOfRangeException">
/// <see cref="HttpProxyServerOptions.Backlog"/> or <see cref="HttpProxyServerOptions.MaxConnections"/> is zero or
/// negative.
/// </exception>
public sealed class HttpProxyServer(
    HttpProxyServerOptions options,
    ILogger<HttpProxyServer>? logger = null)
    : TcpProxyServerBase(options.ListenEndPoint, options.Backlog, options.MaxConnections, logger)
{
    // headers that describe the client-to-proxy connection and must not be forwarded (RFC 9110 §7.6.1)
    private static readonly HashSet<string> HopByHopHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authorization", "Proxy-Authenticate", "TE", "Trailer", "Upgrade"
    };

    /// <inheritdoc/>
    protected override async Task HandleClientAsync(TcpClient client, CancellationToken serverCancellationToken)
    {
        var clientEndpointAddress = TryGetRemoteEndPoint(client)?.ToString() ?? "unknown";
        Logger.LogDebug("Handling client connection from {ClientEndpoint}", clientEndpointAddress);

        using var tcpClient = client;

        try
        {
            tcpClient.NoDelay = true;
            var networkStream = tcpClient.GetStream();

            // Perform handshake
            var handshakeResult = await HttpProxyHandler.PerformHandshakeAsync(networkStream, options.Username, options.Password,
                options.HandshakeTimeout, Logger, clientEndpointAddress, serverCancellationToken).ConfigureAwait(false);
            if (!handshakeResult.IsValid)
            {
                return;
            }

            // Handle request based on method
            if (handshakeResult.Method == "CONNECT")
            {
                await HttpProxyHandler.HandleConnectRequestAsync(handshakeResult.Target, networkStream, clientSocket: null,
                    handshakeResult.Remainder, options.HostConnectionTimeout, options.TunnelHalfCloseTimeout,
                    Logger, clientEndpointAddress, serverCancellationToken).ConfigureAwait(false);
            }
            else
            {
                await HandleHttpRequestAsync(handshakeResult, networkStream, serverCancellationToken, clientEndpointAddress).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpointAddress);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error handling client {ClientEndpoint}", clientEndpointAddress);
        }
    }

    private async Task HandleHttpRequestAsync(HttpHandshakeResult handshake, Stream clientStream, CancellationToken cancellationToken, string clientEndpointAddress)
    {
        var headers = handshake.Headers;
        var responseStarted = false;
        try
        {
            if (!Uri.TryCreate(handshake.Target, UriKind.Absolute, out var targetUri))
            {
                Logger.LogWarning("Invalid URI {Uri} from {ClientEndpoint}", handshake.Target, clientEndpointAddress);
                await HttpProxyHandler.WriteErrorResponseAsync(clientStream, "400 Bad Request", cancellationToken).ConfigureAwait(false);
                return;
            }

            var hostname = targetUri.Host;
            var port = targetUri.IsDefaultPort ? targetUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80 : targetUri.Port;

            using var remoteClient = new TcpClient();
            remoteClient.NoDelay = true;

            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(options.HostConnectionTimeout);
                await remoteClient.ConnectAsync(hostname, port, connectionCts.Token).ConfigureAwait(false);
            }

            var remoteStream = remoteClient.GetStream();

            // RFC 9110 §7.6.1: besides the fixed hop-by-hop set, every header named in the
            // incoming Connection value is also connection-specific and must be stripped
            // (e.g. "Connection: Foo" makes "Foo" hop-by-hop for this request)
            var excludedHeaders = HopByHopHeaders;
            if (headers.TryGetValue("Connection", out var connectionValue))
            {
                excludedHeaders = new HashSet<string>(HopByHopHeaders, StringComparer.OrdinalIgnoreCase);
                foreach (var token in connectionValue.Split(','))
                {
                    var name = token.Trim();
                    if (name.Length > 0)
                        excludedHeaders.Add(name);
                }
            }

            // Rebuild the request line with the origin-form target and forward the client's headers
            var requestBuilder = new StringBuilder();
            requestBuilder.Append(handshake.Method).Append(' ').Append(targetUri.PathAndQuery).Append(" HTTP/1.1\r\n");

            if (!headers.ContainsKey("Host"))
                requestBuilder.Append("Host: ").Append(targetUri.Authority).Append("\r\n");

            foreach (var header in headers)
            {
                if (excludedHeaders.Contains(header.Key))
                    continue;
                requestBuilder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
            }

            requestBuilder.Append("Connection: close\r\n\r\n");

            var requestBytes = Encoding.UTF8.GetBytes(requestBuilder.ToString());
            await remoteStream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
            await remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            // Pump the remaining request body and the response; the handshake remainder holds
            // any body bytes that arrived together with the headers. From here on origin bytes
            // may reach the client, so an error response is no longer safe to inject.
            responseStarted = true;
            await ProxyStreamPump.PumpStreamsAsync(clientStream, remoteStream, options.TunnelHalfCloseTimeout, cancellationToken,
                remoteSocket: remoteClient.Client, clientPrefix: handshake.Remainder).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Failed to handle HTTP request for {ClientEndpoint}", clientEndpointAddress);

            if (!responseStarted)
            {
                // a connect timeout is the gateway timing out; everything else is a bad gateway
                var status = exception is OperationCanceledException && !cancellationToken.IsCancellationRequested
                    ? "504 Gateway Timeout"
                    : "502 Bad Gateway";
                try
                {
                    await HttpProxyHandler.WriteErrorResponseAsync(clientStream, status, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    // client already disconnected
                }
            }
        }
    }
}
