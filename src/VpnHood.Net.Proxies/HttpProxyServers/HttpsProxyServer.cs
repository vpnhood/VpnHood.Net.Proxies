using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace VpnHood.Net.Proxies.HttpProxyServers;

/// <summary>
/// Represents an HTTPS proxy server: an HTTP proxy that clients reach over TLS, and that opens CONNECT tunnels.
/// </summary>
/// <remarks>
/// It speaks TLS 1.2 and 1.3 with <see cref="HttpProxyServerOptions.ServerCertificate"/> and asks for no client
/// certificate. It serves only CONNECT: once the TLS handshake, the request's parsing and any configured authentication
/// have passed, another method gets 405 Method Not Allowed. With authentication on, missing or wrong credentials get
/// 407 Proxy Authentication Required; a request refused otherwise gets 400 Bad Request or a closed connection.
/// </remarks>
/// <example>
/// <code snippet="Snippet:HttpsServer" language="csharp">
/// using var server = new HttpsProxyServer(new HttpProxyServerOptions {
///     ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
///     ServerCertificate = certificate // an X509Certificate2 with its private key
/// });
///
/// server.Start();
/// </code>
/// </example>
/// <param name="options">The server's settings, with its certificate.</param>
/// <param name="logger">The logger for the server's events, or <see langword="null"/> for none.</param>
/// <exception cref="ArgumentNullException"><see cref="HttpProxyServerOptions.ListenEndPoint"/> is <see langword="null"/>.</exception>
/// <exception cref="ArgumentException"><see cref="HttpProxyServerOptions.ServerCertificate"/> is <see langword="null"/>.</exception>
/// <exception cref="ArgumentOutOfRangeException">
/// <see cref="HttpProxyServerOptions.Backlog"/> or <see cref="HttpProxyServerOptions.MaxConnections"/> is zero or
/// negative.
/// </exception>
public sealed class HttpsProxyServer(
    HttpProxyServerOptions options,
    ILogger<HttpsProxyServer>? logger = null)
    : TcpProxyServerBase(options.ListenEndPoint, options.Backlog, options.MaxConnections, logger)
{
    private readonly X509Certificate2 _serverCertificate = options.ServerCertificate
        ?? throw new ArgumentException("ServerCertificate is required for HTTPS proxy server", nameof(options));

    /// <inheritdoc/>
    protected override async Task HandleClientAsync(TcpClient client, CancellationToken serverCancellationToken)
    {
        var clientEndpointAddress = TryGetRemoteEndPoint(client)?.ToString() ?? "unknown";
        Logger.LogDebug("Handling HTTPS client connection from {ClientEndpoint}", clientEndpointAddress);

        using var tcpClient = client;

        try
        {
            tcpClient.NoDelay = true;
            var networkStream = tcpClient.GetStream();

            // Establish TLS connection
            await using var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);

            Logger.LogDebug("Establishing TLS connection with {ClientEndpoint}", clientEndpointAddress);

            using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken))
            {
                handshakeCts.CancelAfter(options.HandshakeTimeout);
                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCertificate,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, handshakeCts.Token).ConfigureAwait(false);
            }

            Logger.LogDebug("TLS connection established with {ClientEndpoint}", clientEndpointAddress);

            // Perform handshake
            var handshakeResult = await HttpProxyHandler.PerformHandshakeAsync(sslStream, options.Username, options.Password,
                options.HandshakeTimeout, Logger, clientEndpointAddress, serverCancellationToken).ConfigureAwait(false);
            if (!handshakeResult.IsValid)
            {
                return;
            }

            // Handle CONNECT request (HTTPS proxy only supports CONNECT)
            if (handshakeResult.Method == "CONNECT")
            {
                // SslStream hides the socket, so pass it explicitly for half-close propagation
                await HttpProxyHandler.HandleConnectRequestAsync(handshakeResult.Target, sslStream, tcpClient.Client,
                    handshakeResult.Remainder, options.HostConnectionTimeout, options.TunnelHalfCloseTimeout,
                    Logger, clientEndpointAddress, serverCancellationToken).ConfigureAwait(false);
            }
            else
            {
                Logger.LogWarning("Unsupported method {Method} from {ClientEndpoint}", handshakeResult.Method, clientEndpointAddress);
                await HttpProxyHandler.WriteErrorResponseAsync(sslStream, "405 Method Not Allowed", serverCancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpointAddress);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error handling HTTPS client {ClientEndpoint}", clientEndpointAddress);
        }
    }
}
