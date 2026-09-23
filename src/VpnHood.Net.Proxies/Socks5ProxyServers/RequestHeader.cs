using VpnHood.Net.Proxies.Socks5Proxy;

namespace VpnHood.Net.Proxies.Socks5ProxyServers;

public sealed class RequestHeader
{
    public required Socks5Command Command { get; init; }
    public required Socks5AddressType AddressType { get; init; }
}