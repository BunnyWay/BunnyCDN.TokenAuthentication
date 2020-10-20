package BunnyCDN;

import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.*;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URLEncodedUtils;
import org.apache.commons.codec.digest.*;
import org.apache.commons.codec.binary.Base64;

public class TokenSigner {

	private String addCountries(String url, String a, String b) throws Exception {
		String tempUrl = url;
		if (a.length() > 0) {
			URL temp = new URL(tempUrl);
			tempUrl += ((temp.getQuery() == null) ? "?" : "&") + "token_countries=" + a;
		}
		if (b.length() > 0) {
			URL tempTwo = new URL(tempUrl);
			tempUrl += ((tempTwo.getQuery() == null) ? "?" : "&") + "token_countries_blocked=" + b;
		}
		return tempUrl;
	}

	public <K extends Comparable, V> Map<K, V> sortByKeys(Map<K, V> map) {
		return new TreeMap<>(map);
	}

	private static String encodeValue(String value) throws Exception {
		return URLEncoder.encode(value, StandardCharsets.US_ASCII.toString());
	}

	public String signUrl(String urlIn, String securityKeyIn, String expirationTimeIn, String userIpIn,
			Boolean isDirectoryIn, String pathAllowedIn, String countriesAllowedIn, String countriesBlockedIn)
			throws Exception {
		String expires = "", parameterData = "", parameterDataUrl = "", expirationTime = "3600", signaturePath = "",
				countriesAllowed, countriesBlocked, hashableBase = "", userIp = "", token = "";
		boolean isDirectory = false;
		if (isDirectoryIn != null) {
			isDirectory = isDirectoryIn;
		}
		if (countriesAllowedIn == null) {
			countriesAllowed = "";
		} else {
			countriesAllowed = countriesAllowedIn;
		}
		if (countriesBlockedIn == null) {
			countriesBlocked = "";
		} else {
			countriesBlocked = countriesBlockedIn;
		}
		String url = addCountries(urlIn, countriesAllowed, countriesBlocked);
		URL temp = new URL(url);
		if (expirationTimeIn != null) {
			expirationTime = expirationTimeIn;
		}
		if (userIpIn != null) {
			userIp = userIpIn;
		}
		expires = System.currentTimeMillis() / 1000L + Long.parseLong(expirationTime) + "";
		List<NameValuePair> parametersList = URLEncodedUtils.parse(new URI(url), Charset.forName("ASCII"));
		Map<String, String> parametersMap = new HashMap<String, String>();
		for (NameValuePair param : parametersList)
			parametersMap.put(param.getName(), param.getValue());
		if (pathAllowedIn != null) {
			signaturePath = pathAllowedIn;
			parametersMap.put("token_path", signaturePath);
		} else {
			signaturePath = temp.getPath();
		}
		parametersMap = this.sortByKeys(parametersMap);
		if (parametersMap.size() > 0) {
			for (Map.Entry<String, String> param : parametersMap.entrySet()) {
				if (parameterData.length() > 0)
					parameterData += "&";
				parameterData += param.getKey() + "=" + param.getValue();
				parameterDataUrl += "&" + param.getKey() + "=" + encodeValue(param.getValue());

			}
		}
		hashableBase = securityKeyIn + signaturePath + expires + parameterData + ((userIp.length() > 0) ? userIp : "");
		token = new String(Base64.encodeBase64(new DigestUtils("SHA-256").digest(hashableBase.getBytes())));
		token = token.replace("\n", "").replace("+", "-").replace("/", "_").replace("=", "");
		if (isDirectory) {
			return temp.getProtocol() + "://" + temp.getHost() + "/bcdn_token=" + token + parameterDataUrl + "&expires="
					+ expires + temp.getPath();
		} else {
			return temp.getProtocol() + "://" + temp.getHost() + temp.getPath() + "?token=" + token + parameterDataUrl
					+ "&expires=" + expires;
		}
	}

	public TokenSigner() {
		// Nothing
	}
}
