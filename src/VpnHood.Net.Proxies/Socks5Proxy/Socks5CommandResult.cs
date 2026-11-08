namespace VpnHood.Net.Proxies.Socks5Proxy;

internal readonly record struct Socks5CommandResult(
    Socks5Command Command,
    Socks5CommandReply Reply,
    Socks5Endpoint BoundEndpoint);
