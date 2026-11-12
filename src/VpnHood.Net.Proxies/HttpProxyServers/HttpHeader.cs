namespace VpnHood.Net.Proxies.HttpProxyServers;

// One header line of a request. The lines are kept as a list, not a dictionary by name, so that the lines
// that repeat a name all survive, in the order they came in.
internal readonly record struct HttpHeader(string Name, string Value);
