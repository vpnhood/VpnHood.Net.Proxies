using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using VpnHood.Net.Proxies.HttpProxyClients;
using VpnHood.Net.Proxies.HttpProxyServers;
using VpnHood.Net.Proxies.Tests.TestHelpers;
// ReSharper disable AccessToDisposedClosure

namespace VpnHood.Net.Proxies.Tests;

[TestClass]
public class HttpProxyClientTests
{
    private static Task<HttpProxyServer> StartHttpProxyAsync(string? user = null, string? pass = null)
    {
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new HttpProxyServerOptions { ListenEndPoint = listenEp, Username = user, Password = pass };
        var server = new HttpProxyServer(serverOptions);
        server.Start();
        return Task.FromResult(server);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(user: "u", pass: "p");

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            Username = "u",
            Password = "p",
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);

        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(user: "u", pass: "p");

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        var ex = await Assert.ThrowsExactlyAsync<ProxyClientException>(() => 
            client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None)
        );
        Assert.AreEqual(SocketError.AccessDenied, ex.SocketErrorCode);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_NoAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(); // No auth required

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello no auth"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);

        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WrongCredentials_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(user: "u", pass: "p");

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            Username = "wrong",
            Password = "credentials",
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        var ex = await Assert.ThrowsExactlyAsync<ProxyClientException>(() =>
            client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None)
        );
        Assert.AreEqual(SocketError.AccessDenied, ex.SocketErrorCode);
    }

    [TestMethod]
    public async Task HttpProxy_CheckConnection_Succeeds()
    {
        using var server = await StartHttpProxyAsync(); // No auth required
        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        await client.CheckConnectionAsync(tcp, CancellationToken.None);
        Assert.IsTrue(tcp.Connected);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_ServerSpeaksFirst_BannerIsPreserved()
    {
        // regression: bytes the destination sends right after the tunnel opens (SMTP/SSH
        // banners) must not be swallowed while reading the CONNECT response
        var banner = "220 welcome to the banner server\r\n"u8.ToArray();
        using var bannerServer = new BannerServer(IPAddress.Loopback, banner);
        using var server = await StartHttpProxyAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, bannerServer.EndPoint.Address.ToString(), bannerServer.EndPoint.Port, cts.Token);

        var stream = tcp.GetStream();
        var buf = new byte[banner.Length];
        await stream.ReadExactlyAsync(buf, cts.Token);
        CollectionAssert.AreEqual(banner, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_Accepts2xxResponse()
    {
        // RFC 9110: any 2xx response to CONNECT indicates success, not just 200
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var proxyEndPoint = (IPEndPoint)listener.LocalEndpoint;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var stubProxyTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            var stream = accepted.GetStream();

            // read request headers until CRLF CRLF
            var bytes = new List<byte>();
            var one = new byte[1];
            while (true)
            {
                var n = await stream.ReadAsync(one, cts.Token);
                if (n == 0) return;
                bytes.Add(one[0]);
                if (bytes.Count >= 4 &&
                    bytes[^4] == '\r' && bytes[^3] == '\n' &&
                    bytes[^2] == '\r' && bytes[^1] == '\n')
                    break;
            }

            await stream.WriteAsync("HTTP/1.1 202 Accepted\r\n\r\n"u8.ToArray(), cts.Token);

            // echo tunneled data afterwards
            var buf = new byte[1024];
            while (true)
            {
                var n = await stream.ReadAsync(buf, cts.Token);
                if (n <= 0) break;
                await stream.WriteAsync(buf.AsMemory(0, n), cts.Token);
            }
        }, cts.Token);

        try
        {
            var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = proxyEndPoint });
            using var tcp = new TcpClient();
            await client.ConnectAsync(tcp, "example.com", 443, cts.Token);

            var stream = tcp.GetStream();
            var payload = "abc"u8.ToArray();
            await stream.WriteAsync(payload, cts.Token);
            var echoed = new byte[payload.Length];
            await stream.ReadExactlyAsync(echoed, cts.Token);
            CollectionAssert.AreEqual(payload, echoed);
        }
        finally
        {
            listener.Stop();
            try { await stubProxyTask; } catch { /* listener stopped */ }
        }
    }

    [TestMethod]
    public async Task HttpProxy_Connect_PortAbove65535_Throws()
    {
        using var server = await StartHttpProxyAsync();
        var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var tcp = new TcpClient();

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(() =>
            client.ConnectAsync(tcp, "example.com", 65536, cts.Token));
        Assert.IsFalse(tcp.Connected, "the port is refused before anything is sent");
    }

    [TestMethod]
    public async Task HttpProxy_Connect_NullDestination_Throws()
    {
        var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = new IPEndPoint(IPAddress.Loopback, 8080) });
        using var tcp = new TcpClient();

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(() =>
            client.ConnectAsync(tcp, (IPEndPoint)null!, CancellationToken.None));
        await Assert.ThrowsExactlyAsync<ArgumentNullException>(() =>
            client.ConnectAsync(null!, new IPEndPoint(IPAddress.Loopback, 80), CancellationToken.None));
    }

    private static HttpsProxyServer StartHttpsProxy(X509Certificate2 certificate, string? user = null, string? pass = null)
    {
        var server = new HttpsProxyServer(new HttpProxyServerOptions {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ServerCertificate = certificate,
            Username = user,
            Password = pass
        });
        server.Start();
        return server;
    }

    // The paths below release the client's TLS stream themselves. Nothing outside the client can see that
    // release; these tests hold what a caller does see: the exception, and what becomes of the connection.

    [TestMethod]
    public async Task HttpsProxy_Connect_RefusedAfterTlsHandshake_ThrowsAndClosesConnection()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var certificate = TestCertificates.CreateSelfSigned();
        using var server = StartHttpsProxy(certificate, user: "u", pass: "p");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // TLS succeeds, then the proxy refuses the request: no credentials
        var client = new HttpProxyClient(new HttpProxyClientOptions {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = true,
            AllowInvalidCertificates = true
        });
        using var tcp = new TcpClient();

        var ex = await Assert.ThrowsExactlyAsync<ProxyClientException>(() =>
            client.ConnectAsync(tcp, echo.EndPoint, cts.Token));
        Assert.AreEqual(SocketError.AccessDenied, ex.SocketErrorCode);
        Assert.IsFalse(tcp.Connected, "a failed exchange closes the connection");
    }

    [TestMethod]
    public async Task HttpsProxy_Connect_UntrustedCertificate_ThrowsAndClosesConnection()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var certificate = TestCertificates.CreateSelfSigned();
        using var server = StartHttpsProxy(certificate);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // the self-signed certificate fails validation, so the TLS handshake itself fails
        var client = new HttpProxyClient(new HttpProxyClientOptions {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = true
        });
        using var tcp = new TcpClient();

        await Assert.ThrowsExactlyAsync<AuthenticationException>(() =>
            client.ConnectAsync(tcp, echo.EndPoint, cts.Token));
        Assert.IsFalse(tcp.Connected, "a failed exchange closes the connection");
    }

    [TestMethod]
    public async Task HttpsProxy_CheckConnection_CompletesTlsHandshake_LeavesConnectionOpen()
    {
        using var certificate = TestCertificates.CreateSelfSigned();
        using var server = StartHttpsProxy(certificate);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var client = new HttpProxyClient(new HttpProxyClientOptions {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = true,
            AllowInvalidCertificates = true
        });
        using var tcp = new TcpClient();

        await client.CheckConnectionAsync(tcp, cts.Token);
        Assert.IsTrue(tcp.Connected, "the check leaves closing the connection to its caller");
    }

    [TestMethod]
    public async Task HttpsProxy_CheckConnection_UntrustedCertificate_ThrowsAndClosesConnection()
    {
        using var certificate = TestCertificates.CreateSelfSigned();
        using var server = StartHttpsProxy(certificate);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var client = new HttpProxyClient(new HttpProxyClientOptions {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = true
        });
        using var tcp = new TcpClient();

        await Assert.ThrowsExactlyAsync<AuthenticationException>(() => client.CheckConnectionAsync(tcp, cts.Token));
        Assert.IsFalse(tcp.Connected, "a failed check closes the connection");
    }
}
