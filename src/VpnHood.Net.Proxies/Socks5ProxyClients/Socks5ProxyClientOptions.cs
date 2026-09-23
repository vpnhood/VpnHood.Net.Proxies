using System.Net;

namespace VpnHood.Net.Proxies.Socks5ProxyClients;

public class Socks5ProxyClientOptions
{
    public required IPEndPoint ProxyEndPoint { get; init; }
    public string? Username { get; set; }
    public string? Password { get; set; }
}