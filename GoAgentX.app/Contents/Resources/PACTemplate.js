function FindProxyForURL(url, host) {
    var DEFAULT_PROXY_PROFILE = "{DEFAULT_PROXY_PROFILE}";
    
    var FIRST_RUNNING_PROXY = "{FIRST_RUNNING_PROXY}";
    
    var FIRST_RUNNING_SOCKS_PROXY = "{FIRST_RUNNING_SOCKS_PROXY}";
    
	var HTTP_ONLY_PROXIES = {HTTP_ONLY_PROXIES};

	var GENERAL_PROXIES = {GENERAL_PROXIES};
    
    var GXAPIEnabled = {GX_API_ENABLED};
    var GXAPIProxy = "{GX_API_PROXY}";
    
    var getProxyIdentifier = arguments.length > 2 && arguments[2] == true;
	
	function GetProxy(identifier, url, rule) {
        if (getProxyIdentifier) {
            return rule ? {rule: rule, identifier: identifier} : null;
        }
        
		var isHTTP = (url.substr(0, 7) == "http://" || url.substr(0, 8) == "https://");
		var proxies = isHTTP ? HTTP_ONLY_PROXIES : GENERAL_PROXIES;
		var ret = proxies[identifier] || proxies["AutoDetect"];
		return ret;
	}
    
    url = url.toLowerCase();
    host = host.toLowerCase();
    
    if (GXAPIEnabled && host == "goagentx-api-server.local") {
        return getProxyIdentifier ? null : GXAPIProxy;
    }
    
    if (host == "127.0.0.1" ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return GetProxy("DirectConnection", url);
    }

	{PAC_RULES}
    
    return GetProxy(DEFAULT_PROXY_PROFILE, url);
}