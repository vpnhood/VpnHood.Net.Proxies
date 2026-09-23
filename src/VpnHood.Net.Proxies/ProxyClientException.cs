using System.Net.Sockets;

namespace VpnHood.Net.Proxies;

public class ProxyClientException(SocketError socketError, string? message = null)
    : SocketException((int)socketError, message);
