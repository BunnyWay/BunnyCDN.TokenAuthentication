require "uri"
require "base64"
require "digest"

def sign_url(url, sec_key:, expiration_time: nil, expires: nil, user_ip: "", path_url: false , path_allowed: nil, countries_allowed: nil, countries_blocked: nil, limit: nil)
  raise ArgumentError, "use EITHER expiration_time OR expires" if expiration_time && expires || !expiration_time && !expires

  uri = URI(url)
  expires = (expires || (Time.now.to_i + expiration_time.to_i)).to_s

  parameters = URI.decode_www_form(uri.query || "").to_h
  extra_parameters = {token_countries: countries_allowed, token_countries_blocked: countries_blocked, token_path: path_allowed, limit: limit}.compact
  parameters.merge!(extra_parameters) unless extra_parameters.empty?
  parameters = parameters.sort.to_h

  # The signature requires the non-encoded version of the query string
  parameter_data = parameters.map { |k, v| "#{k}=#{v}" }.join("&")
  signature_path = path_allowed || uri.path
  hashable_base = sec_key + signature_path + expires + parameter_data + user_ip.to_s

  token = Base64.urlsafe_encode64(Digest::SHA256.digest(hashable_base), padding: false)
  
  if path_url
    # Get our parameters into the order we want them, but manually add uri.path to the end. 

    parameter_data_url = URI.encode_www_form({bcdn_token: token, **parameters}).gsub("+", "%20") + "&expires=#{expires + uri.path}"
    "#{uri.scheme}://#{uri.host}/#{parameter_data_url}"
  else
    uri.query = URI.encode_www_form({token: token, **parameters, expires: expires}).gsub("+", "%20")
    uri.to_s
  end
end

