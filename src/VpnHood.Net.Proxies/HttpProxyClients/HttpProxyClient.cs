using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VpnHood.Net.Proxies.HttpProxyClients;

/// <summary>
/// Opens TCP tunnels through an HTTP proxy with the CONNECT method, optionally over TLS to the proxy itself (an
/// HTTPS proxy) and with Basic authentication.
/// </summary>
/// <remarks>
/// <para>
/// One instance can serve many connections at once. With <see cref="HttpProxyClientOptions.UseTls"/>, a tunnel
/// runs inside a TLS session, so read and write it through <see cref="GetStream"/>, not
/// <see cref="TcpClient.GetStream"/>.
/// </para>
/// <para>
/// Any 2xx answer opens the tunnel. The answer is read only up to its end, so data that a destination sends
/// first, such as an SMTP or SSH banner, stays in the stream for the caller.
/// </para>
/// </remarks>
/// <example>
/// <code snippet="Snippet:HttpConnect" language="csharp">
/// var client = new HttpProxyClient(new HttpProxyClientOptions {
///     ProxyEndPoint = proxyEndPoint,
///     Username = "user", // Basic authentication, sent with every request
///     Password = "pass",
///     UseTls = false // true for an HTTPS proxy, with ProxyHost as the name on its certificate
/// });
///
/// using var tcp = new TcpClient();
/// await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None);
///
/// // Take the tunnel from the client: with UseTls, the connection's own stream would bypass TLS.
/// var stream = client.GetStream(tcp);
/// </code>
/// </example>
/// <param name="options">The proxy's address, credentials and TLS settings.</param>
/// <param name="logger">The logger for the client's progress and failures, or <see langword="null"/> for none.</param>
public class HttpProxyClient(
    HttpProxyClientOptions options,
    ILogger<HttpProxyClient>? logger = null)
    : IProxyClient
{
    // With UseTls the tunnel runs inside an SslStream; keep it per connection so callers can
    // retrieve it after ConnectAsync (tcpClient.GetStream() would bypass the TLS layer)
    private readonly ConditionalWeakTable<TcpClient, Stream> _tunnelStreams = new();

    /// <summary>
    /// Opens a tunnel through the proxy to an IP endpoint.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> first.
    /// When the task completes, <see cref="GetStream"/> gives the tunnel; when the exchange with the proxy fails, it is
    /// closed.
    /// </param>
    /// <param name="destination">The destination's address and port.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> or <paramref name="destination"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The port of <paramref name="destination"/> is zero.</exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request or did not answer as an HTTP proxy; <see cref="SocketException.SocketErrorCode"/>
    /// tells why.
    /// </exception>
    /// <exception cref="AuthenticationException">The TLS handshake with the proxy failed.</exception>
    /// <exception cref="TimeoutException">The proxy's answer did not arrive within 30 seconds of the request.</exception>
    /// <exception cref="IOException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentNullException.ThrowIfNull(destination);
        await ConnectAsync(tcpClient, destination.Address.ToString(), destination.Port, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public IPEndPoint ProxyEndPoint => options.ProxyEndPoint;

    /// <summary>
    /// Gets the stream that carries the tunnel of a connection opened by <see cref="ConnectAsync(TcpClient, string, int, CancellationToken)"/>.
    /// </summary>
    /// <param name="tcpClient">The connection.</param>
    /// <returns>
    /// The TLS stream when <see cref="HttpProxyClientOptions.UseTls"/> is <see langword="true"/>; otherwise, and
    /// for a connection this client opened no tunnel on, the connection's <see cref="NetworkStream"/>.
    /// </returns>
    /// <remarks>
    /// Dispose both: the TLS stream, whose disposal leaves the TCP connection open, and the <see cref="TcpClient"/>,
    /// which closes the tunnel.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// No tunnel of this client is on <paramref name="tcpClient"/>, and it is not connected.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// No tunnel of this client is on <paramref name="tcpClient"/>, and it is disposed.
    /// </exception>
    public Stream GetStream(TcpClient tcpClient)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        return _tunnelStreams.TryGetValue(tcpClient, out var stream) ? stream : tcpClient.GetStream();
    }

    /// <summary>
    /// Opens a tunnel through the proxy to a host, given by name or IP address.
    /// </summary>
    /// <param name="tcpClient">
    /// The connection to use. When it is not connected, it is connected to <see cref="ProxyEndPoint"/> first.
    /// When the task completes, <see cref="GetStream"/> gives the tunnel; when the exchange with the proxy fails, it is
    /// closed.
    /// </param>
    /// <param name="host">The destination's host name or IP address literal. A name is sent for the proxy to resolve.</param>
    /// <param name="port">The destination's port, from 1 to 65535.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the tunnel is open.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> or <paramref name="host"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="host"/> is empty or white space.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="port"/> is less than 1 or greater than 65535.</exception>
    /// <exception cref="ProxyClientException">
    /// The proxy refused the request, did not answer as an HTTP proxy, or sent headers over 8 KB;
    /// <see cref="SocketException.SocketErrorCode"/> tells why. For example, 407 gives
    /// <see cref="SocketError.AccessDenied"/>, and 502 gives <see cref="SocketError.HostUnreachable"/>.
    /// </exception>
    /// <exception cref="AuthenticationException">The TLS handshake with the proxy failed.</exception>
    /// <exception cref="TimeoutException">The proxy's answer did not arrive within 30 seconds of the request.</exception>
    /// <exception cref="IOException">The proxy closed the connection before its answer was complete.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, IPEndPoint.MaxPort);

        logger?.LogDebug("Connecting to {Host}:{Port} through HTTP proxy {ProxyEndPoint}", host, port, options.ProxyEndPoint);

        try {
            if (!tcpClient.Connected) {
                tcpClient.NoDelay = true;
                await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            }

            var stream = options.UseTls
                ? await OpenTunnelOverTlsAsync(tcpClient.GetStream(), host, port, cancellationToken).ConfigureAwait(false)
                : await OpenTunnelAsync(tcpClient.GetStream(), host, port, cancellationToken).ConfigureAwait(false);

            _tunnelStreams.AddOrUpdate(tcpClient, stream);
            logger?.LogDebug("HTTP CONNECT tunnel established to {Host}:{Port}", host, port);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to connect to {Host}:{Port} through HTTP proxy", host, port);
            tcpClient.Close();
            throw;
        }
    }

    /// <summary>
    /// Connects to the proxy and, with <see cref="HttpProxyClientOptions.UseTls"/>, completes the TLS handshake,
    /// without asking for a tunnel.
    /// </summary>
    /// <param name="tcpClient">
    /// A connection that is not connected yet. With TLS, close it after the check: its TLS session is not kept, so it
    /// cannot carry a tunnel; without TLS, a tunnel can follow on it. When the check fails, it is closed.
    /// </param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation. It completes when the check passes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tcpClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="AuthenticationException">The TLS handshake with the proxy failed.</exception>
    /// <exception cref="SocketException">The connection to the proxy failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public async Task CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        try {
            tcpClient.NoDelay = true;
            await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);

            // The check keeps no TLS session, so its stream is released here; the connection stays the caller's
            if (options.UseTls) {
                var sslStream = await AuthenticateTlsAsync(tcpClient.GetStream(), cancellationToken).ConfigureAwait(false);
                await sslStream.DisposeAsync().ConfigureAwait(false);
            }
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    // Asks the proxy for the tunnel on a stream to it, and returns that stream once the proxy has opened it
    private async Task<Stream> OpenTunnelAsync(Stream stream, string host, int port, CancellationToken cancellationToken)
    {
        await SendConnectRequest(stream, host, port, cancellationToken).ConfigureAwait(false);
        await ReadConnectResponse(stream, cancellationToken).ConfigureAwait(false);
        return stream;
    }

    // The TLS stream becomes the caller's only with an open tunnel: a refused request must not leave it behind
    private async Task<Stream> OpenTunnelOverTlsAsync(NetworkStream networkStream, string host, int port, CancellationToken cancellationToken)
    {
        var sslStream = await AuthenticateTlsAsync(networkStream, cancellationToken).ConfigureAwait(false);
        try {
            return await OpenTunnelAsync(sslStream, host, port, cancellationToken).ConfigureAwait(false);
        }
        catch {
            await sslStream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    // The TCP connection stays open when the TLS stream is disposed: closing it is the TcpClient's part
    private async Task<SslStream> AuthenticateTlsAsync(NetworkStream networkStream, CancellationToken cancellationToken)
    {
        logger?.LogDebug("Establishing TLS connection to proxy");
        var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: true, UserCertificateValidationCallback);
        try {
            await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                TargetHost = options.ProxyHost ?? options.ProxyEndPoint.Address.ToString(),
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, cancellationToken).ConfigureAwait(false);

            logger?.LogDebug("TLS connection established");
            return sslStream;
        }
        catch {
            await sslStream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private bool UserCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (options.AllowInvalidCertificates) {
            logger?.LogWarning("Accepting invalid certificate due to AllowInvalidCertificates option");
            return true;
        }
        
        if (sslPolicyErrors != SslPolicyErrors.None) {
            logger?.LogWarning("SSL certificate validation failed: {SslPolicyErrors}", sslPolicyErrors);
            return false;
        }
        
        return true;
    }

    private static string BuildAuthority(string host, int port)
    {
        // IPv6 addresses need to be enclosed in brackets
        var isIpv6Literal = host.Contains(':') && host.IndexOf(':') != host.LastIndexOf(':');
        return isIpv6Literal ? $"[{host}]:{port}" : $"{host}:{port}";
    }

    private async Task SendConnectRequest(Stream stream, string host, int port, CancellationToken cancellationToken)
    {
        var authority = BuildAuthority(host, port);
        var requestBuilder = new StringBuilder();
        
        requestBuilder.Append($"CONNECT {authority} HTTP/1.1\r\n");
        requestBuilder.Append($"Host: {authority}\r\n");
        requestBuilder.Append("Connection: keep-alive\r\n");
        
        // Add authentication if provided
        if (options.Username != null) {
            var credentials = $"{options.Username}:{options.Password ?? string.Empty}";
            var encodedCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
            requestBuilder.Append($"Proxy-Authorization: Basic {encodedCredentials}\r\n");
            logger?.LogDebug("Added proxy authentication for user: {Username}", options.Username);
        }
        
        // Add extra headers if provided
        if (options.ExtraHeaders != null) {
            foreach (var header in options.ExtraHeaders) {
                requestBuilder.Append($"{header.Key}: {header.Value}\r\n");
            }
        }

        requestBuilder.Append("\r\n");
        
        var requestBytes = Encoding.UTF8.GetBytes(requestBuilder.ToString());
        await stream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        
        logger?.LogDebug("Sent CONNECT request to proxy");
    }

    private async Task ReadConnectResponse(Stream stream, CancellationToken cancellationToken)
    {
        const int maxResponseSize = 8192; // Reasonable limit for HTTP response headers
        var buffer = new byte[maxResponseSize];
        var totalReceived = 0;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30)); // Response timeout

        try {
            // Read one byte at a time so nothing beyond the response headers is consumed.
            // The destination may speak first (e.g., SMTP or SSH banners), and those bytes
            // must stay in the stream for the caller.
            while (totalReceived < buffer.Length) {
                var bytesRead = await stream.ReadAsync(
                    buffer.AsMemory(totalReceived, 1),
                    timeout.Token).ConfigureAwait(false);

                if (bytesRead == 0)
                    throw new IOException("Proxy closed connection before sending complete response");

                totalReceived += bytesRead;

                // Look for end of HTTP headers (double CRLF)
                if (totalReceived >= 4 &&
                    buffer[totalReceived - 4] == '\r' && buffer[totalReceived - 3] == '\n' &&
                    buffer[totalReceived - 2] == '\r' && buffer[totalReceived - 1] == '\n') {
                    var responseText = Encoding.UTF8.GetString(buffer, 0, totalReceived);
                    ValidateConnectResponse(responseText);
                    logger?.LogDebug("Received successful CONNECT response from proxy");
                    return;
                }
            }

            throw new ProxyClientException(SocketError.ProtocolNotSupported, "HTTP proxy response headers too large");
        }
        catch (OperationCanceledException) when (timeout.Token.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
            throw new TimeoutException("Timeout waiting for proxy response");
        }
    }

    private static void ValidateConnectResponse(string responseText)
    {
        if (string.IsNullOrWhiteSpace(responseText))
            throw new ProxyClientException(SocketError.ProtocolNotSupported, "Empty or non-HTTP response");

        // Remove BOM if present
        if (responseText[0] == '\ufeff')
            responseText = responseText[1..];

        if (!responseText.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            throw new ProxyClientException(SocketError.ProtocolNotSupported, "Not an HTTP proxy");

        var lines = responseText.Split(new[] { "\r\n" }, StringSplitOptions.None);
        var parts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var code))
            throw new ProxyClientException(SocketError.ProtocolNotSupported, "Malformed HTTP status line");

        // RFC 9110: any 2xx response indicates a successful CONNECT
        if (code is >= 200 and < 300)
            return;

        var reason = parts.Length > 2 ? parts[2] : "Unknown";

        throw code switch {
            // Valid proxy, needs or failed auth
            407 => new ProxyClientException(SocketError.AccessDenied,
                $"Proxy authentication required or failed (status {code}: {reason})"),

            // Proxy timeout (client-side or idle)
            408 => new ProxyClientException(SocketError.TimedOut,
                $"Proxy connection timed out (status {code}: {reason})"),

            // Target or proxy host not found
            404 => new ProxyClientException(SocketError.HostNotFound,
                $"HTTP proxy or target not found (status {code}: {reason})"),

            // CONNECT disallowed or plain HTTP server
            400 or 401 or 403 or 405 => new ProxyClientException(SocketError.ProtocolNotSupported,
                $"HTTP server does not support CONNECT (status {code}: {reason})"),

            // Upstream errors: proxy could not reach target
            500 or 502 or 503 or 504 => new ProxyClientException(SocketError.HostUnreachable,
                $"Proxy failed to connect to target (status {code}: {reason})"),

            // Rate limits or custom non-standard responses
            429 => new ProxyClientException(SocketError.TryAgain,
                $"Proxy rate limited request (status {code}: {reason})"),

            // Everything else: generic proxy failure
            _ => new ProxyClientException(SocketError.SocketError,
                $"Unexpected HTTP proxy response (status {code}: {reason})")
        };

    }


}
