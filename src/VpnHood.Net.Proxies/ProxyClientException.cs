using System.Net.Sockets;

namespace VpnHood.Net.Proxies;

/// <summary>
/// The exception that is thrown when a proxy refuses a request or answers in a way the client cannot use.
/// </summary>
/// <remarks>
/// <see cref="SocketException.SocketErrorCode"/> gives the reason in the terms of a direct connection: for
/// example <see cref="SocketError.AccessDenied"/> when the proxy refuses the request or its credentials,
/// <see cref="SocketError.ConnectionRefused"/> or <see cref="SocketError.HostUnreachable"/> when the proxy could
/// not reach the destination, and <see cref="SocketError.ProtocolNotSupported"/> when the server does not speak
/// the proxy protocol the client expects.
/// </remarks>
/// <param name="socketError">The reason, as a socket error code.</param>
/// <param name="message">A message that describes the error, or <see langword="null"/>.</param>
public class ProxyClientException(SocketError socketError, string? message = null)
    : SocketException((int)socketError, message);
