import urllib.parse, time, hashlib, base64

VERSION = "2"

def add_countries(url, a, b):
	"""
		Helper to add the countries_allowed/countries_blocked
		parameters if necessary.

		a: List of countries allowed (exp. CA, US, TH)
		b: List of countries blocked (exp. CA, US, TH)
	"""
	allowed, blocked = "", ""
	if a:
		url += {1: "?", 0: "&"}[urllib.parse.urlparse(url).query == ""] + "token_countries=" + a
	if b:
		url += {1: "?", 0: "&"}[urllib.parse.urlparse(url).query == ""] + "token_countries_blocked=" + b
	return url;

def sign_url(url, security_key, expiration_time = 86400, user_ip = "", isDirectory = True, path_allowed = "", countries_allowed = "", countries_blocked = ""):
	"""
		Generates URL Authentication Beacon

		url: CDN URL w/o the trailing '/' - exp. http://test.b-cdn.net/file.png
		security_key: Security token found in your pull zone
		expiration_time: Authentication validity (default. 86400 sec/24 hrs)
		user_ip: Optional parameter if you have the User IP feature enabled
		countries_allowed: List of countries allowed (exp. CA, US, TH)
		countries_blocked: List of countries blocked (exp. CA, US, TH)

	"""
	parameter_data, parameter_data_url = "", ""
	expires = str(int(time.time() + expiration_time))
	url = add_countries(url, countries_allowed, countries_blocked)
	parsed_url = urllib.parse.urlparse(url)
	parameters = urllib.parse.parse_qs(parsed_url.query)
	if path_allowed: 
		signature_path = path_allowed
		parameters["token_path"] = signature_path
	else:
		signature_path = parsed_url.path
	parameters = dict((a, parameters[a]) for a in sorted(parameters))
	if parameters:
		for value in parameters:
			if len(parameter_data) > 0:
				parameter_data += "&"
			parameter_data_url += "&"
			parameter_data += value + "=" + "".join(parameters[value])
			parameter_data_url += value + "=" + urllib.parse.quote("".join(parameters[value]), safe="")

	hashable_base = security_key + signature_path + expires + parameter_data + {1: user_ip, 0: ""}[user_ip != None]
	token = base64.b64encode(hashlib.sha256(str.encode(hashable_base)).digest())
	token = token.decode().replace("\n", "").replace("+", "-").replace("/", "_").replace("=", "")
	if isDirectory:
		return parsed_url.scheme + "://" + parsed_url.netloc + "/bcdn_token=" + token + parameter_data_url + "&expires=" + str(expires) + parsed_url.path
	else:
		return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path + "?token=" + token + parameter_data_url + "&expires=" + str(expires)
