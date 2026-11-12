using System.Net;
using System.Net.Sockets;
using System.Text;
using VpnHood.Net.Proxies.HttpProxyClients;
using VpnHood.Net.Proxies.HttpProxyServers;
using VpnHood.Net.Proxies.Tests.TestHelpers;

namespace VpnHood.Net.Proxies.Tests;

[TestClass]
public class HttpProxyServerTests
{
    private static HttpProxyServer StartHttpProxy(string? user = null, string? pass = null)
    {
        var server = new HttpProxyServer(new HttpProxyServerOptions {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            Username = user,
            Password = pass
        });
        server.Start();
        return server;
    }

    // reads exactly up to the end of the response headers so any tunneled bytes that follow stay in the stream
    private static async Task<string> ReadResponseHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>();
        var one = new byte[1];
        while (true) {
            var n = await stream.ReadAsync(one, cancellationToken);
            if (n == 0) throw new IOException("Connection closed before response headers completed");
            bytes.Add(one[0]);
            if (bytes.Count >= 4 &&
                bytes[^4] == '\r' && bytes[^3] == '\n' &&
                bytes[^2] == '\r' && bytes[^1] == '\n')
                return Encoding.ASCII.GetString(bytes.ToArray());
        }
    }

    [TestMethod]
    public async Task HttpProxy_Get_ForwardsClientHeaders()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        var request = $"GET http://{origin.EndPoint}/hello?q=1 HTTP/1.1\r\n" +
                      $"Host: {origin.EndPoint}\r\n" +
                      "X-Custom: abc\r\n" +
                      "Proxy-Connection: keep-alive\r\n" +
                      "\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        await origin.RequestReceived.WaitAsync(cts.Token);
        StringAssert.Contains(origin.ReceivedHeaders, "GET /hello?q=1 HTTP/1.1");
        StringAssert.Contains(origin.ReceivedHeaders, $"Host: {origin.EndPoint}");
        StringAssert.Contains(origin.ReceivedHeaders, "X-Custom: abc");
        StringAssert.Contains(origin.ReceivedHeaders, "Connection: close");
        Assert.IsFalse(origin.ReceivedHeaders.Contains("Proxy-Connection", StringComparison.OrdinalIgnoreCase),
            "hop-by-hop headers must not be forwarded");
    }

    [TestMethod]
    public async Task HttpProxy_Post_PipelinedBody_IsForwarded()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // headers and body in a single write so the body arrives together with the headers;
        // the proxy must not swallow it while parsing the headers
        const string body = "hello world";
        var request = $"POST http://{origin.EndPoint}/submit HTTP/1.1\r\n" +
                      $"Host: {origin.EndPoint}\r\n" +
                      $"Content-Length: {body.Length}\r\n" +
                      "\r\n" +
                      body;
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        await origin.RequestReceived.WaitAsync(cts.Token);
        Assert.AreEqual(body, Encoding.ASCII.GetString(origin.ReceivedBody));
    }

    [TestMethod]
    public async Task HttpProxy_Connect_PipelinedClientData_IsForwarded()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // CONNECT headers and tunnel payload in a single write; the payload must reach the target
        var payload = "hello tunnel"u8.ToArray();
        var connect = Encoding.ASCII.GetBytes($"CONNECT {echo.EndPoint} HTTP/1.1\r\nHost: {echo.EndPoint}\r\n\r\n");
        await stream.WriteAsync(connect.Concat(payload).ToArray(), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf, cts.Token);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_IPv6Authority_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.IPv6Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // HttpProxyClient formats the authority as [::1]:port; the server must parse it
        var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, "::1", echo.EndPoint.Port, cts.Token);

        var stream = tcp.GetStream();
        var payload = "hello ipv6"u8.ToArray();
        await stream.WriteAsync(payload, cts.Token);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf, cts.Token);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Server_StopStart_Restarts()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        Assert.IsTrue(server.IsStarted);

        server.Stop();
        Assert.IsFalse(server.IsStarted);

        server.Start();
        Assert.IsTrue(server.IsStarted);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, cts.Token);
        Assert.IsTrue(tcp.Connected);
    }

    [TestMethod]
    public async Task HttpsProxy_Connect_ThroughTls_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var cert = TestCertificates.CreateSelfSigned();
        using var server = new HttpsProxyServer(new HttpProxyServerOptions {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ServerCertificate = cert
        });
        server.Start();

        var client = new HttpProxyClient(new HttpProxyClientOptions {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = true,
            AllowInvalidCertificates = true
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, cts.Token);

        // tunnel traffic must go through the TLS stream, not the raw socket
        var stream = client.GetStream(tcp);
        var payload = "hello tls proxy"u8.ToArray();
        await stream.WriteAsync(payload, cts.Token);
        await stream.FlushAsync(cts.Token);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf, cts.Token);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_HalfClose_ResponseDeliveredAfterClientShutdown()
    {
        // the destination responds only after seeing EOF, so this passes only when the
        // proxy propagates the client's Shutdown(Send) instead of tearing the tunnel down
        using var origin = new ReadAllThenRespondServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, origin.EndPoint.Address.ToString(), origin.EndPoint.Port, cts.Token);

        var stream = tcp.GetStream();
        var payload = "request that expects an answer after EOF"u8.ToArray();
        await stream.WriteAsync(payload, cts.Token);
        tcp.Client.Shutdown(SocketShutdown.Send);

        var response = new byte[payload.Length];
        await stream.ReadExactlyAsync(response, cts.Token);
        CollectionAssert.AreEqual(payload, response);

        // after the response the destination closes; the proxy should pass the EOF on
        Assert.AreEqual(0, await stream.ReadAsync(new byte[1], cts.Token));
    }

    [TestMethod]
    public async Task HttpProxy_Tunnel_ReleasedAfterHalfCloseTimeout()
    {
        // destination half-closes immediately but keeps reading; the client never closes.
        // Without the linger timeout the tunnel (and the destination's read) would hang
        // until someone gives up; with it the proxy tears the tunnel down.
        var destinationReadCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var destinationListener = new TcpListener(IPAddress.Loopback, 0);
        destinationListener.Start();
        var destinationEndPoint = (IPEndPoint)destinationListener.LocalEndpoint;

        _ = Task.Run(async () =>
        {
            try
            {
                using var accepted = await destinationListener.AcceptTcpClientAsync();
                accepted.Client.Shutdown(SocketShutdown.Send); // EOF toward the proxy
                _ = await accepted.GetStream().ReadAsync(new byte[1]); // wait for tunnel teardown
            }
            catch { /* teardown may surface as an exception; that still counts */ }
            finally { destinationReadCompleted.TrySetResult(); }
        });

        try
        {
            using var server = new HttpProxyServer(new HttpProxyServerOptions
            {
                ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
                TunnelHalfCloseTimeout = TimeSpan.FromMilliseconds(250)
            });
            server.Start();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
            using var tcp = new TcpClient();
            await client.ConnectAsync(tcp, destinationEndPoint.Address.ToString(), destinationEndPoint.Port, cts.Token);

            // the client deliberately keeps its connection open and silent
            await destinationReadCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5), cts.Token);
        }
        finally
        {
            destinationListener.Stop();
        }
    }

    [TestMethod]
    public async Task HttpProxy_HeadersTooLarge_ConnectionClosed()
    {
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // ~42 KB of headers exceeds the 32 KB total cap; the server must drop the
        // connection instead of buffering unbounded header data
        var filler = new string('a', 7000);
        try
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes("GET http://127.0.0.1:1/ HTTP/1.1\r\n"), cts.Token);
            for (var i = 0; i < 6; i++)
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"X-Filler-{i}: {filler}\r\n"), cts.Token);
            await stream.WriteAsync("\r\n"u8.ToArray(), cts.Token);
        }
        catch (IOException)
        {
            // server may already have closed while we were still writing — that's the point
        }

        int read;
        try { read = await stream.ReadAsync(new byte[1], cts.Token); }
        catch (IOException) { read = 0; }
        Assert.AreEqual(0, read, "server should close the connection without a response");
    }

    [TestMethod]
    public async Task HttpProxy_Get_ConnectionNominatedHeader_NotForwarded()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // RFC 9110 §7.6.1: "Connection: X-Secret" makes X-Secret hop-by-hop for this request
        var request = $"GET http://{origin.EndPoint}/x HTTP/1.1\r\n" +
                      $"Host: {origin.EndPoint}\r\n" +
                      "Connection: X-Secret\r\n" +
                      "X-Secret: do-not-forward\r\n" +
                      "X-Keep: forward-me\r\n" +
                      "\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        await origin.RequestReceived.WaitAsync(cts.Token);
        StringAssert.Contains(origin.ReceivedHeaders, "X-Keep: forward-me");
        Assert.IsFalse(origin.ReceivedHeaders.Contains("X-Secret", StringComparison.OrdinalIgnoreCase),
            "Connection-nominated headers must not be forwarded");
    }

    [TestMethod]
    public async Task HttpProxy_Get_TargetUnreachable_Returns502()
    {
        // reserve a port with nothing listening on it so the proxy's connect is refused
        var portHolder = new TcpListener(IPAddress.Loopback, 0);
        portHolder.Start();
        var deadPort = ((IPEndPoint)portHolder.LocalEndpoint).Port;
        portHolder.Stop();

        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        var request = $"GET http://127.0.0.1:{deadPort}/ HTTP/1.1\r\nHost: 127.0.0.1:{deadPort}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        // the client must get an HTTP error, not a silently dropped connection
        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 502");
    }

    [TestMethod]
    public async Task HttpProxy_MaxConnections_ExcessConnectionClosed()
    {
        using var server = new HttpProxyServer(new HttpProxyServerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            MaxConnections = 1
        });
        server.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // first connection occupies the only slot (it idles inside the handshake)
        using var first = new TcpClient();
        await first.ConnectAsync(server.ListenerEndPoint, cts.Token);

        // give the accept loop time to register the first connection
        await Task.Delay(300, cts.Token);
        Assert.AreEqual(1, server.ActiveConnectionCount);

        // the second connection must be closed immediately without service
        using var second = new TcpClient();
        await second.ConnectAsync(server.ListenerEndPoint, cts.Token);

        int read;
        try { read = await second.GetStream().ReadAsync(new byte[1], cts.Token); }
        catch (IOException) { read = 0; }
        Assert.AreEqual(0, read, "connection over the limit should be closed immediately");
    }

    [TestMethod]
    public async Task HttpProxy_Get_RepeatedHeader_EveryLineForwardedInOrder()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // a name may come on several lines; each line and their order are the request's
        var request = $"GET http://{origin.EndPoint}/x HTTP/1.1\r\n" +
                      $"Host: {origin.EndPoint}\r\n" +
                      "X-Tag: one\r\n" +
                      "Accept: text/html\r\n" +
                      "X-Tag: two\r\n" +
                      "Accept: application/json\r\n" +
                      "X-Tag: three\r\n" +
                      "\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        await origin.RequestReceived.WaitAsync(cts.Token);
        var forwarded = origin.ReceivedHeaders.Split("\r\n")
            .Where(line => line.StartsWith("X-Tag:") || line.StartsWith("Accept:"))
            .ToArray();
        CollectionAssert.AreEqual(
            new[] { "X-Tag: one", "Accept: text/html", "X-Tag: two", "Accept: application/json", "X-Tag: three" },
            forwarded);
    }

    [TestMethod]
    public async Task HttpProxy_Get_SeveralConnectionLines_EachLinesHeadersNotForwarded()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // the second Connection line must not make the proxy forget what the first one named
        var request = $"GET http://{origin.EndPoint}/x HTTP/1.1\r\n" +
                      $"Host: {origin.EndPoint}\r\n" +
                      "Connection: X-First\r\n" +
                      "Connection: keep-alive, X-Second\r\n" +
                      "X-First: do-not-forward\r\n" +
                      "X-Second: do-not-forward\r\n" +
                      "X-Keep: forward-me\r\n" +
                      "\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        await origin.RequestReceived.WaitAsync(cts.Token);
        StringAssert.Contains(origin.ReceivedHeaders, "X-Keep: forward-me");
        Assert.IsFalse(origin.ReceivedHeaders.Contains("X-First", StringComparison.OrdinalIgnoreCase),
            "a header named by the first Connection line must not be forwarded");
        Assert.IsFalse(origin.ReceivedHeaders.Contains("X-Second", StringComparison.OrdinalIgnoreCase),
            "a header named by the second Connection line must not be forwarded");
    }

    [TestMethod]
    public async Task HttpProxy_Get_HeaderBytesAbove127_ArriveUnchanged()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // "café" in Latin-1 and in UTF-8: neither may be re-encoded on its way through the proxy
        byte[] latin1Line = [.. "X-Latin1: caf"u8, 0xE9, (byte)'\r', (byte)'\n'];
        byte[] utf8Line = [.. "X-Utf8: caf"u8, 0xC3, 0xA9, (byte)'\r', (byte)'\n'];
        byte[] request = [
            .. Encoding.ASCII.GetBytes($"GET http://{origin.EndPoint}/x HTTP/1.1\r\nHost: {origin.EndPoint}\r\n"),
            .. latin1Line,
            .. utf8Line,
            .. "\r\n"u8
        ];
        await stream.WriteAsync(request, cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        await origin.RequestReceived.WaitAsync(cts.Token);
        Assert.IsTrue(origin.ReceivedHeaderBytes.AsSpan().IndexOf(latin1Line) >= 0, "the Latin-1 header line should arrive byte for byte");
        Assert.IsTrue(origin.ReceivedHeaderBytes.AsSpan().IndexOf(utf8Line) >= 0, "the UTF-8 header line should arrive byte for byte");
    }

    [TestMethod]
    public async Task HttpProxy_Post_HeadersUnderTheLimit_BodyBehindThem_IsAccepted()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // 32,600 bytes of request line and headers, under the limit of 32,768, and the body right behind them
        // in one write: the body's bytes are no part of the headers and must not count as theirs
        const int headersLength = 32_600;
        const string lastHeaderName = "X-Last: ";
        const string headersEnd = "\r\n\r\n";
        var body = new byte[9000];
        Random.Shared.NextBytes(body);
        var headers = new StringBuilder();
        headers.Append($"POST http://{origin.EndPoint}/submit HTTP/1.1\r\n");
        headers.Append($"Host: {origin.EndPoint}\r\n");
        headers.Append($"Content-Length: {body.Length}\r\n");
        for (var i = 0; i < 4; i++)
            headers.Append($"X-Filler-{i}: {new string('a', 7800)}\r\n");
        var lastHeaderValueLength = headersLength - headers.Length - lastHeaderName.Length - headersEnd.Length;
        headers.Append(lastHeaderName).Append('b', lastHeaderValueLength).Append(headersEnd);
        Assert.AreEqual(headersLength, headers.Length);

        byte[] request = [.. Encoding.ASCII.GetBytes(headers.ToString()), .. body];
        await stream.WriteAsync(request, cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 200");

        await origin.RequestReceived.WaitAsync(cts.Token);
        CollectionAssert.AreEqual(body, origin.ReceivedBody);
    }

    [TestMethod]
    public async Task HttpProxy_Get_HttpsUri_Returns501_AndReachesNoOrigin()
    {
        using var origin = new HttpOriginServer(IPAddress.Loopback);
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // the proxy speaks no TLS to origins: sent on, this request would cross the network in the clear
        var request = $"GET https://{origin.EndPoint}/secret HTTP/1.1\r\nHost: {origin.EndPoint}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 501");
        Assert.AreEqual(0, origin.ConnectionCount, "an https: request must not reach its origin");
    }

    [TestMethod]
    public async Task HttpProxy_Get_PathInsteadOfAbsoluteUri_Returns400()
    {
        using var server = StartHttpProxy();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // a request meant for an origin server, not for a proxy
        var request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var responseHeaders = await ReadResponseHeadersAsync(stream, cts.Token);
        StringAssert.StartsWith(responseHeaders, "HTTP/1.1 400");
    }
}
