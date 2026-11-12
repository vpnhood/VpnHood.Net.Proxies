using VpnHood.Net.Proxies.Socks5Proxy;

namespace VpnHood.Net.Proxies.Socks5ProxyServers;

internal sealed class RequestHeader
{
    public required Socks5Command Command { get; init; }

    // As the client gave it: a domain name is not looked up yet
    public required Socks5Endpoint Destination { get; init; }
}
