var queryString = require("querystring");
var crypto = require("crypto");

function addCountries(url, a, b) {
	var tempUrl = url;
	if (a != null) {
		var tempUrlOne = new URL(tempUrl);
		tempUrl += ((tempUrlOne.search == "") ? "?" : "&") + "token_countries=" + a;
	}
	if (b != null) {
		var tempUrlTwo = new URL(tempUrl);
		tempUrl += ((tempUrlTwo.search == "") ? "?" : "&") + "token_countries_blocked=" + b;
	}
	return tempUrl;
}

function signUrl(url, securityKey, expirationTime = 3600, userIp, isDirectory = false, pathAllowed, countriesAllowed, countriesBlocked) {
	/*
		url: CDN URL w/o the trailing '/' - exp. http://test.b-cdn.net/file.png
		securityKey: Security token found in your pull zone
		expirationTime: Authentication validity (default. 86400 sec/24 hrs)
		userIp: Optional parameter if you have the User IP feature enabled
		isDirectory: Optional parameter - "true" returns a URL separated by forward slashes (exp. (domain)/bcdn_token=...)
		pathAllowed: Directory to authenticate (exp. /path/to/images)
		countriesAllowed: List of countries allowed (exp. CA, US, TH)
		countriesBlocked: List of countries blocked (exp. CA, US, TH)
	*/
	var parameterData = "", parameterDataUrl = "", signaturePath = "", hashableBase = "", token = "";
	var expires = Math.floor(new Date() / 1000) + expirationTime;
	var url = addCountries(url, countriesAllowed, countriesBlocked);
	var parsedUrl = new URL(url);
	var parameters = (new URL(url)).searchParams;
	if (pathAllowed != null) {
		signaturePath = pathAllowed;
		parameters.set("token_path", signaturePath);
	} else {
		signaturePath = decodeURIComponent(parsedUrl.pathname);
	}
	parameters.sort()
	if (Array.from(parameters).length > 0) {
		parameters.forEach(function(value, key) {
		  if (parameterData.length > 0) {
		  	parameterData += "&";
		  }
		  parameterData += key + "=" + value;
		  parameterDataUrl += "&" + key + "=" + queryString.escape(value);

		});
	}
	hashableBase = securityKey + signaturePath + expires + ((userIp != null) ? userIp : "") + parameterData;
	token = Buffer.from(crypto.createHash("sha256").update(hashableBase).digest()).toString("base64");
	token = token.replace(/\n/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	if (isDirectory) {
		return parsedUrl.protocol+ "//" + parsedUrl.host + "/bcdn_token=" + token + parameterDataUrl + "&expires=" + expires + parsedUrl.pathname;
	} else {
		return parsedUrl.protocol + "//" + parsedUrl.host + parsedUrl.pathname + "?token=" + token + parameterDataUrl + "&expires=" + expires;
	}
}
