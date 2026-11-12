using System.Net;
using System.Net.Sockets;
using VpnHood.Net.Proxies.Socks5ProxyClients;
using VpnHood.Net.Proxies.Socks5ProxyServers;
using VpnHood.Net.Proxies.Tests.TestHelpers;
using IPEndPoint = System.Net.IPEndPoint;

namespace VpnHood.Net.Proxies.Tests;

[TestClass]
public class Socks5ProxyClientTests
{
    private static Task<Socks5ProxyServer> StartSocks5ProxyAsync(string? user = null, string? pass = null)
    {
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new Socks5ProxyServerOptions { ListenEndPoint = listenEp, Username = user, Password = pass };
        var server = new Socks5ProxyServer(serverOptions);
        server.Start();
        return Task.FromResult(server);
    }

    [TestMethod]
    public async Task Socks5_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "user", Password = "pass" };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello socks5"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task Socks5_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_Connect_NoAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello socks5 no auth"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task Socks5_Connect_WrongCredentials_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "wrong", Password = "credentials" };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_WithAuth_Succeeds()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "user", Password = "pass" };
        var client = new Socks5ProxyClient(options);

        // Create UDP client for sending/receiving data
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        // Establish TCP control connection and UDP association
        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

        // Give some time for the UDP relay to be established
        await Task.Delay(100);

        // Prepare test data
        var testMessage = "Hello UDP through SOCKS5!"u8.ToArray();
        
        // Create SOCKS5 UDP request packet
        var requestBuffer = new byte[1024];
        var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, testMessage);
        var udpRequest = requestBuffer.AsMemory(0, requestLength);

        // Send UDP packet through proxy
        await udpClient.SendAsync(udpRequest.ToArray(), proxyUdpEndpoint);

        // Receive response through proxy
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await udpClient.ReceiveAsync(timeoutCts.Token);

        // Parse SOCKS5 UDP response
        var responseEndpoint = Socks5ProxyClient.ParseUdpResponse(response.Buffer, out var responsePayload);
        
        // Verify the response
        Assert.IsNotNull(responseEndpoint.Address);
        Assert.AreEqual(udpEcho.EndPoint.Address, responseEndpoint.Address);
        Assert.AreEqual(udpEcho.EndPoint.Port, responseEndpoint.Port);
        CollectionAssert.AreEqual(testMessage, responsePayload.ToArray());
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_WithoutAuth_Fails()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint }; // No credentials
        var client = new Socks5ProxyClient(options);

        using var controlTcp = new TcpClient();
        
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(async () =>
        {
            await client.CreateUdpAssociateAsync(controlTcp, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_NoAuth_Succeeds()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        // Create UDP client
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        // Establish UDP association
        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

        // Give some time for the UDP relay to be established
        await Task.Delay(100);

        // Test UDP communication
        var testMessage = "Hello UDP no auth!"u8.ToArray();
        var requestBuffer = new byte[1024];
        var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, testMessage);
        
        await udpClient.SendAsync(requestBuffer.AsMemory(0, requestLength).ToArray(), proxyUdpEndpoint);

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await udpClient.ReceiveAsync(timeoutCts.Token);

        var responseEndpoint = Socks5ProxyClient.ParseUdpResponse(response.Buffer, out var responsePayload);
        
        Assert.IsNotNull(responseEndpoint.Address);
        CollectionAssert.AreEqual(testMessage, responsePayload.ToArray());
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_Simple_Test()
    {
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        // Just test the UDP ASSOCIATE command without actual UDP traffic
        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, CancellationToken.None);
        
        // Verify we got a valid UDP endpoint from the proxy
        Assert.IsNotNull(proxyUdpEndpoint);
        Assert.IsTrue(proxyUdpEndpoint.Port > 0);
        
        // The control connection should remain open
        Assert.IsTrue(controlTcp.Connected);
    }

    [TestMethod]
    public async Task UdpEchoServer_DirectTest()
    {
        using var echoServer = new UdpEchoServer(IPAddress.Loopback);
        using var testClient = new UdpClient();

        var testMessage = "Test UDP Echo"u8.ToArray();
        
        // Send test message to echo server
        await testClient.SendAsync(testMessage, echoServer.EndPoint);
        
        // Receive echoed response
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var response = await testClient.ReceiveAsync(cts.Token);
        
        // Verify echo
        CollectionAssert.AreEqual(testMessage, response.Buffer);
        Assert.AreEqual(echoServer.EndPoint, response.RemoteEndPoint);
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_SendPacket_Test()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        // Create UDP client
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        // Establish UDP association
        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

        // Give some time for the UDP relay to be established
        await Task.Delay(100);

        // Create SOCKS5 UDP request to the echo server
        var testMessage = "Hello UDP test!"u8.ToArray();
        var requestBuffer = new byte[1024];
        var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, testMessage);
        
        // Send UDP packet through proxy
        await udpClient.SendAsync(requestBuffer.AsMemory(0, requestLength).ToArray(), proxyUdpEndpoint);
        
        // Receive echoed response via proxy and validate
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await udpClient.ReceiveAsync(timeoutCts.Token);
        var responseEndpoint = Socks5ProxyClient.ParseUdpResponse(response.Buffer, out var responsePayload);
        
        Assert.IsNotNull(responseEndpoint.Address);
        Assert.AreEqual(udpEcho.EndPoint.Address, responseEndpoint.Address);
        Assert.AreEqual(udpEcho.EndPoint.Port, responseEndpoint.Port);
        CollectionAssert.AreEqual(testMessage, responsePayload.ToArray());
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_NoAuth_Succeeds()
    {
        using var server = await StartSocks5ProxyAsync();
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await client.CheckConnectionAsync(tcp, CancellationToken.None);
        Assert.IsTrue(tcp.Connected);
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_WithAuth_Succeeds()
    {
        using var server = await StartSocks5ProxyAsync(user: "u", pass: "p");
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "u", Password = "p" };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await client.CheckConnectionAsync(tcp, CancellationToken.None);
        Assert.IsTrue(tcp.Connected);
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_WithoutAuth_Fails()
    {
        using var server = await StartSocks5ProxyAsync(user: "u", pass: "p");
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(async () =>
        {
            await client.CheckConnectionAsync(tcp, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_WrongCredentials_Fails()
    {
        using var server = await StartSocks5ProxyAsync(user: "u", pass: "p");
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "wrong", Password = "creds" };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(async () =>
        {
            await client.CheckConnectionAsync(tcp, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_ClientReuse_AcrossConnections_Succeeds()
    {
        // regression: the auth handshake belongs to a connection, not the client instance;
        // reusing one client for several connections must negotiate on each of them
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "user", Password = "pass" };
        var client = new Socks5ProxyClient(options);

        for (var i = 0; i < 2; i++)
        {
            using var tcp = new TcpClient();
            await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);

            var stream = tcp.GetStream();
            var payload = System.Text.Encoding.ASCII.GetBytes($"hello reuse {i}");
            await stream.WriteAsync(payload);
            var buf = new byte[payload.Length];
            await stream.ReadExactlyAsync(buf);
            CollectionAssert.AreEqual(payload, buf);
        }
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_Then_Connect_OnNewConnection_Succeeds()
    {
        // regression: a health check on one connection must not skip the handshake
        // on a later connection made by the same client instance
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "user", Password = "pass" };
        var client = new Socks5ProxyClient(options);

        using var checkTcp = new TcpClient();
        await client.CheckConnectionAsync(checkTcp, CancellationToken.None);

        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello after check"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task Socks5_Connect_ByHostname_ResolvedByProxy_Succeeds()
    {
        // host names are sent as SOCKS5 domain addresses and resolved by the proxy
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync();

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, "localhost", echo.EndPoint.Port, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello domain"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task Socks5_Server_NoAuth_AcceptsUserPassOnlyClient()
    {
        // regression: a client that only offers username/password must still be able to
        // use a server that has no credentials configured
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(); // no auth configured
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);
        var stream = tcp.GetStream();

        // greeting: version 5, 1 method, username/password only
        await stream.WriteAsync(new byte[] { 5, 1, 2 }, cts.Token);
        var method = new byte[2];
        await stream.ReadExactlyAsync(method, cts.Token);
        Assert.AreEqual(5, method[0]);
        Assert.AreEqual(2, method[1], "server should select username/password");

        // sub-negotiation with arbitrary credentials must succeed
        await stream.WriteAsync(new byte[] { 1, 1, (byte)'u', 1, (byte)'p' }, cts.Token);
        var auth = new byte[2];
        await stream.ReadExactlyAsync(auth, cts.Token);
        Assert.AreEqual(0, auth[1], "authentication should be accepted");

        // CONNECT to the echo server
        var ip = echo.EndPoint.Address.GetAddressBytes();
        var port = echo.EndPoint.Port;
        await stream.WriteAsync(new byte[] { 5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], (byte)(port >> 8), (byte)port }, cts.Token);
        var reply = new byte[10]; // VER REP RSV ATYP + IPv4 + port
        await stream.ReadExactlyAsync(reply, cts.Token);
        Assert.AreEqual(0, reply[1], "CONNECT should succeed");

        var payload = "hello"u8.ToArray();
        await stream.WriteAsync(payload, cts.Token);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf, cts.Token);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task Socks5_Connect_HalfClose_ResponseDeliveredAfterClientShutdown()
    {
        // the destination responds only after seeing EOF, so this passes only when the
        // proxy propagates the client's Shutdown(Send) instead of tearing the tunnel down
        using var origin = new ReadAllThenRespondServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var client = new Socks5ProxyClient(new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, origin.EndPoint, cts.Token);

        var stream = tcp.GetStream();
        var payload = "socks5 half-close request"u8.ToArray();
        await stream.WriteAsync(payload, cts.Token);
        tcp.Client.Shutdown(SocketShutdown.Send);

        var response = new byte[payload.Length];
        await stream.ReadExactlyAsync(response, cts.Token);
        CollectionAssert.AreEqual(payload, response);
    }

    [TestMethod]
    public async Task Socks5_Connect_HostNameWithPortAbove65535_Throws()
    {
        // the request has two bytes for the port: a larger one must be refused, not cut down to them
        using var server = await StartSocks5ProxyAsync();
        var client = new Socks5ProxyClient(new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using var tcp = new TcpClient();
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(() =>
            client.ConnectAsync(tcp, "localhost", 65536, cts.Token));
        Assert.IsFalse(tcp.Connected, "the port is refused before anything is sent");
    }

    [TestMethod]
    public async Task Socks5_OperationsAtOnce_OnOneConnection_RunOneAtATime()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "user", Password = "pass" };
        var client = new Socks5ProxyClient(options);

        // connected ahead, so each operation below finds the connection open and not yet negotiated
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server.ListenerEndPoint, cts.Token);

        // unserialized, each of them would start a negotiation of its own on the one stream
        await Task.WhenAll(
            client.CheckConnectionAsync(tcp, cts.Token),
            client.CheckConnectionAsync(tcp, cts.Token),
            client.CheckConnectionAsync(tcp, cts.Token),
            client.ConnectAsync(tcp, echo.EndPoint, cts.Token));

        var stream = tcp.GetStream();
        var payload = "hello after the crowd"u8.ToArray();
        await stream.WriteAsync(payload, cts.Token);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf, cts.Token);
        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task Socks5_OperationCanceledWhileItWaits_LeavesConnectionOpen()
    {
        // a stand-in proxy that accepts and never answers, so the first operation stays in its negotiation
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var client = new Socks5ProxyClient(new Socks5ProxyClientOptions { ProxyEndPoint = (IPEndPoint)listener.LocalEndpoint });
            using var firstCts = new CancellationTokenSource();
            using var tcp = new TcpClient();
            var first = client.CheckConnectionAsync(tcp, firstCts.Token);
            using var accepted = await listener.AcceptTcpClientAsync();

            // the second one waits for the first; its cancellation is no failure of the connection
            using var secondCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
            await Assert.ThrowsAsync<OperationCanceledException>(() => client.CheckConnectionAsync(tcp, secondCts.Token));
            Assert.IsTrue(tcp.Connected, "the operation ahead still uses the connection");

            await firstCts.CancelAsync();
            await Assert.ThrowsAsync<OperationCanceledException>(() => first);
        }
        finally
        {
            listener.Stop();
        }
    }

    [TestMethod]
    public void Socks5_ParseUdpResponse_ReadsEachAddressType()
    {
        byte[] payload = [0xAA, 0xBB];

        byte[] ipV4 = [0, 0, 0, 1, 10, 0, 0, 7, 0x1F, 0x90, .. payload];
        var endpoint = Socks5ProxyClient.ParseUdpResponse(ipV4, out var data);
        Assert.AreEqual(IPAddress.Parse("10.0.0.7"), endpoint.Address);
        Assert.IsNull(endpoint.Host);
        Assert.AreEqual(8080, endpoint.Port);
        CollectionAssert.AreEqual(payload, data.ToArray());

        byte[] ipV6 = [0, 0, 0, 4, .. IPAddress.IPv6Loopback.GetAddressBytes(), 0, 53, .. payload];
        endpoint = Socks5ProxyClient.ParseUdpResponse(ipV6, out data);
        Assert.AreEqual(IPAddress.IPv6Loopback, endpoint.Address);
        Assert.AreEqual(53, endpoint.Port);
        CollectionAssert.AreEqual(payload, data.ToArray());

        byte[] domain = [0, 0, 0, 3, 4, (byte)'h', (byte)'o', (byte)'s', (byte)'t', 1, 187, .. payload];
        endpoint = Socks5ProxyClient.ParseUdpResponse(domain, out data);
        Assert.AreEqual("host", endpoint.Host);
        Assert.IsNull(endpoint.Address);
        Assert.AreEqual(443, endpoint.Port);
        CollectionAssert.AreEqual(payload, data.ToArray());

        // a header with nothing after it: an empty payload
        byte[] noPayload = [0, 0, 0, 1, 10, 0, 0, 7, 0, 80];
        Socks5ProxyClient.ParseUdpResponse(noPayload, out data);
        Assert.AreEqual(0, data.Length);
    }

    [TestMethod]
    public void Socks5_ParseUdpResponse_DatagramCutInsideItsHeader_ThrowsArgumentException()
    {
        // each one ends inside its address or its port; a relay's datagram is outside input, so the caller
        // must get the one exception that says so, not whichever the slicing happens to throw
        byte[][] datagrams = [
            [0, 0, 0, 1, 10, 0, 0], // IPv4: three of four address bytes
            [0, 0, 0, 1, 10, 0, 0, 7], // IPv4: no port
            [0, 0, 0, 1, 10, 0, 0, 7, 0], // IPv4: half a port
            [0, 0, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], // IPv6: twelve of sixteen address bytes
            [0, 0, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0], // IPv6: half a port
            [0, 0, 0, 3, 9, (byte)'h', (byte)'o', (byte)'s', (byte)'t'], // domain: four of nine name bytes
            [0, 0, 0, 3, 4, (byte)'h', (byte)'o', (byte)'s', (byte)'t', 1] // domain: half a port
        ];

        foreach (var datagram in datagrams)
            Assert.ThrowsExactly<ArgumentException>(() => Socks5ProxyClient.ParseUdpResponse(datagram, out _),
                $"A datagram of {datagram.Length} bytes with address type {datagram[3]}.");
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_BytesOnControlConnection_DoNotEndAssociation()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync();

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

        // RFC 1928 ends an association with its TCP connection, not with what a client sends on it
        await controlTcp.GetStream().WriteAsync(new byte[] { 1, 2, 3 });
        await Task.Delay(300); // time for the server to read them

        var message = "still associated"u8.ToArray();
        var requestBuffer = new byte[1024];
        var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, message);
        await udpClient.SendAsync(requestBuffer.AsMemory(0, requestLength).ToArray(), proxyUdpEndpoint);

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await udpClient.ReceiveAsync(timeoutCts.Token);
        Socks5ProxyClient.ParseUdpResponse(response.Buffer, out var responsePayload);
        CollectionAssert.AreEqual(message, responsePayload.ToArray());
    }

    [TestMethod]
    public async Task Socks5_Udp_PacketFromUnknownSource_IsDropped()
    {
        // security: a third party that discovers the relay port must not be able to
        // inject datagrams into the association
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync();

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);
        await Task.Delay(100);

        // legitimate round trip works
        var message = "legit"u8.ToArray();
        var requestBuffer = new byte[1024];
        var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, message);
        await udpClient.SendAsync(requestBuffer.AsMemory(0, requestLength).ToArray(), proxyUdpEndpoint);
        using (var okCts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            var ok = await udpClient.ReceiveAsync(okCts.Token);
            Socks5ProxyClient.ParseUdpResponse(ok.Buffer, out var okPayload);
            CollectionAssert.AreEqual(message, okPayload.ToArray());
        }

        // attacker on a different port sends a datagram to the relay
        using var attacker = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var evil = "evil"u8.ToArray();
        var evilBuffer = new byte[1024];
        var evilLength = Socks5ProxyClient.WriteUdpRequest(evilBuffer, clientUdpEndpoint, evil);
        await attacker.SendAsync(evilBuffer.AsMemory(0, evilLength).ToArray(), proxyUdpEndpoint);

        // the client must not receive anything
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(700));
        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            await udpClient.ReceiveAsync(timeoutCts.Token);
        });
    }
}
