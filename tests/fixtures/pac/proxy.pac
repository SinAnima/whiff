function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || dnsDomainIs(host, ".saltmere.example"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0"))
        return "DIRECT";
    if (shExpMatch(url, "https://tides.*"))
        return "PROXY tides-proxy.saltmere.example:3128; DIRECT";
    return "PROXY proxy.saltmere.example:8080; SOCKS5 socks.saltmere.example:1080";
}
