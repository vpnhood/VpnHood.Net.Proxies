using System.Net;
using System.Net.Sockets;
using VpnHood.Net.Proxies.HttpProxyClients;
using VpnHood.Net.Proxies.HttpProxyServers;
using VpnHood.Net.Proxies.Socks4ProxyClients;
using VpnHood.Net.Proxies.Socks5ProxyClients;
using VpnHood.Net.Proxies.Socks5ProxyServers;
using VpnHood.Net.Proxies.Tests.TestHelpers;

namespace VpnHood.Net.Proxies.Tests;

// The README's quick starts and the doc comments' examples are copies of the Snippet regions here, made by
// VpnHood's pub/lib/Update-Snippets.ps1; CI fails when a copy differs. Edit a region, then run the script.
[TestClass]
public class ReadmeExampleTests
{
    [TestMethod]
    [Timeout(30_000)]
    public async Task Socks5_server_and_tcp_client()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var destinationHost = echo.EndPoint.Address.ToString();
        var destinationPort = echo.EndPoint.Port;

        #region Snippet:Socks5Server
        using var server = new Socks5ProxyServer(new Socks5ProxyServerOptions {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
            Username = null, // set a user name to require RFC 1929 authentication
            Password = null
        });

        server.Start(); // or: await server.RunAsync(cancellationToken);
        var proxyEndPoint = server.ListenerEndPoint;
        #endregion

        #region Snippet:Socks5Connect
        var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
            ProxyEndPoint = proxyEndPoint
        });

        using var tcp = new TcpClient();

        // A host name goes to the proxy as a SOCKS5 domain name, so the proxy resolves it: no local DNS query.
        await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None);

        var stream = tcp.GetStream(); // the tunnel: speak HTTP, TLS or anything else
        #endregion

        await AssertEchoAsync(stream);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Socks5_udp_associate()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = new Socks5ProxyServer(new Socks5ProxyServerOptions { ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0) });
        server.Start();
        var proxyEndPoint = server.ListenerEndPoint;
        var destination = udpEcho.EndPoint;
        var payload = "hello over udp"u8.ToArray();

        #region Snippet:Socks5Udp
        var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
            ProxyEndPoint = proxyEndPoint
        });

        // the local UDP socket that exchanges datagrams with the proxy
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var localUdpEndPoint = (IPEndPoint)udp.Client.LocalEndPoint!;

        // the association lasts while this TCP control connection stays open
        using var controlTcp = new TcpClient();
        var relayEndPoint = await client.CreateUdpAssociateAsync(controlTcp, localUdpEndPoint, CancellationToken.None);

        // wrap the payload in the SOCKS5 UDP header (10 bytes for IPv4, 22 for IPv6) and send it to the relay
        var buffer = new byte[22 + payload.Length];
        var length = Socks5ProxyClient.WriteUdpRequest(buffer, destination, payload);
        await udp.SendAsync(buffer.AsMemory(0, length), relayEndPoint);

        // receive the answer and unwrap it
        var result = await udp.ReceiveAsync();
        var from = Socks5ProxyClient.ParseUdpResponse(result.Buffer, out var answer);
        #endregion

        CollectionAssert.AreEqual(payload, answer.ToArray());
        Assert.AreEqual(destination.Port, from.Port);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Http_server_and_client()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var destinationHost = echo.EndPoint.Address.ToString();
        var destinationPort = echo.EndPoint.Port;

        #region Snippet:HttpServer
        using var server = new HttpProxyServer(new HttpProxyServerOptions {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
            Username = "user", // set a user name to require Basic authentication
            Password = "pass"
        });

        server.Start();
        var proxyEndPoint = server.ListenerEndPoint;
        #endregion

        #region Snippet:HttpConnect
        var client = new HttpProxyClient(new HttpProxyClientOptions {
            ProxyEndPoint = proxyEndPoint,
            Username = "user", // Basic authentication, sent with every request
            Password = "pass",
            UseTls = false // true for an HTTPS proxy, with ProxyHost as the name on its certificate
        });

        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None);

        // Take the tunnel from the client: with UseTls, the connection's own stream would bypass TLS.
        var stream = client.GetStream(tcp);
        #endregion

        await AssertEchoAsync(stream);
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Https_server()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var certificate = TestCertificates.CreateSelfSigned();

        #region Snippet:HttpsServer
        using var server = new HttpsProxyServer(new HttpProxyServerOptions {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0), // 0: the system picks a free port
            ServerCertificate = certificate // an X509Certificate2 with its private key
        });

        server.Start();
        #endregion

        // The test certificate is self-signed, which only AllowInvalidCertificates accepts: not an example.
        var client = new HttpProxyClient(new HttpProxyClientOptions {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = true,
            AllowInvalidCertificates = true
        });
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
        await AssertEchoAsync(client.GetStream(tcp));
    }

    [TestMethod]
    [Timeout(30_000)]
    public async Task Socks4_client()
    {
        // The library has no SOCKS4 server: a stand-in grants one request, then echoes.
        using var listener = new TcpListenerScope();
        var proxyEndPoint = listener.EndPoint;
        var standIn = GrantSocks4AndEchoAsync(listener.Listener);
        var destinationHost = "127.0.0.1";
        var destinationPort = 7;

        #region Snippet:Socks4Connect
        var client = new Socks4ProxyClient(new Socks4ProxyClientOptions {
            ProxyEndPoint = proxyEndPoint,
            UserName = null // the SOCKS4 user ID, when the proxy wants one
        });

        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, destinationHost, destinationPort, CancellationToken.None); // a host name uses SOCKS4a

        var stream = tcp.GetStream(); // the tunnel
        #endregion

        await AssertEchoAsync(stream);
        tcp.Close();
        await standIn;
    }

    private static async Task AssertEchoAsync(Stream stream)
    {
        var payload = "hello through the proxy"u8.ToArray();
        await stream.WriteAsync(payload);
        await stream.FlushAsync();
        var received = new byte[payload.Length];
        await stream.ReadExactlyAsync(received);
        CollectionAssert.AreEqual(payload, received);
    }

    // Reads one SOCKS4 CONNECT request for an IPv4 destination, grants it, then echoes the tunnel.
    private static async Task GrantSocks4AndEchoAsync(TcpListener listener)
    {
        using var accepted = await listener.AcceptTcpClientAsync();
        var stream = accepted.GetStream();

        var header = new byte[8]; // VN, CD, DSTPORT, DSTIP
        await stream.ReadExactlyAsync(header);
        var oneByte = new byte[1];
        do { await stream.ReadExactlyAsync(oneByte); } while (oneByte[0] != 0); // USERID, null-terminated

        await stream.WriteAsync(new byte[] { 0x00, (byte)Socks4ReplyCode.RequestGranted, 0, 0, 0, 0, 0, 0 });

        var buffer = new byte[1024];
        int read;
        while ((read = await stream.ReadAsync(buffer)) > 0)
            await stream.WriteAsync(buffer.AsMemory(0, read));
    }

    private sealed class TcpListenerScope : IDisposable
    {
        public TcpListener Listener { get; } = new(IPAddress.Loopback, 0);
        public IPEndPoint EndPoint => (IPEndPoint)Listener.LocalEndpoint;
        public TcpListenerScope() => Listener.Start();
        public void Dispose() => Listener.Stop();
    }
}
