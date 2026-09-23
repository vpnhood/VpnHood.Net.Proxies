using System.Net;

namespace VpnHood.Net.Proxies.Socks5Proxy;

public readonly record struct Socks5Endpoint(string? Host, IPAddress? Address, int Port);
