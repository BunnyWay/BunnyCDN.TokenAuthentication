require_relative 'token.rb'

# Tests Generated with the Python3 implementation, modified to allow directly setting the expired value for consistency.
#
def tests
  test_url = "https://token-tester.b-cdn.net/300kb.jpg"
  sec_key = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40"
  expires = 1727918622

  test_cases = [
    { user_ip: nil, path_allowed: nil, countries_allowed: nil, countries_blocked: nil, limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=fa_Vy6p0rbSWCf1CHNBdSiSku828n0HNDffUX0DFlnI&expires=1727918622/300kb.jpg"},

    { user_ip: nil, path_allowed: nil, countries_allowed: "AU", countries_blocked: nil, limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=8ryY2_NXJ8PauusW-GvF_GSstCq6IwkV1VmeZOrFKUQ&token_countries=AU&expires=1727918622/300kb.jpg"},

    { user_ip: "192.168.100.100", path_allowed: nil, countries_allowed: "AU", countries_blocked: nil, limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=wELdlcF6DFBiUI9daYEUf83xUdkiWiUnRs4WKjzxVXo&token_countries=AU&expires=1727918622/300kb.jpg"},

    { user_ip: "192.168.100.100", path_allowed: "/300kb", countries_allowed: "AU", countries_blocked: nil, limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=HQHBUOFnQCUl3Z53YsDUeihCYrP6wPWVCagPZhE0vKI&token_countries=AU&token_path=%2F300kb&expires=1727918622/300kb.jpg"},

    { user_ip: "192.168.100.100", path_allowed: "/300kb", countries_allowed: "AU", countries_blocked: "GB", limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=F0LkSqauEQ2vUfyB48WwGntGpIBQQdl0AxdX5XrTDow&token_countries=AU&token_countries_blocked=GB&token_path=%2F300kb&expires=1727918622/300kb.jpg"},

    { user_ip: "192.168.100.100", path_allowed: "/300kb", countries_allowed: "AU,NZ", countries_blocked: "GB", limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=DEOLD1efgKnm2FWBEwlg75NohDtydbKj4PU7oEpDoro&token_countries=AU%2CNZ&token_countries_blocked=GB&token_path=%2F300kb&expires=1727918622/300kb.jpg"},

    { user_ip: "192.168.100.100", path_allowed: "/300kb", countries_allowed: "AU, NZ", countries_blocked: "GB", limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=0XdwT0g9UACzUBh7AzyFwPhVZIsGwqj7yvHGHcY8qXo&token_countries=AU%2C%20NZ&token_countries_blocked=GB&token_path=%2F300kb&expires=1727918622/300kb.jpg"},

    { user_ip: "192.168.100.100", path_allowed: nil, countries_allowed: nil, countries_blocked: nil, limit: nil, path_url: true, expected: "https://token-tester.b-cdn.net/bcdn_token=SmnSkK1stGqOJge706jsf-02HaCbUaVv7507ZrLP43k&expires=1727918622/300kb.jpg"},

    { user_ip: nil, path_allowed: nil, countries_allowed: nil, countries_blocked: nil, limit: nil, expected: "https://token-tester.b-cdn.net/300kb.jpg?token=fa_Vy6p0rbSWCf1CHNBdSiSku828n0HNDffUX0DFlnI&expires=1727918622"},

    { user_ip: "192.168.100.100", path_allowed: nil, countries_allowed: nil, countries_blocked: nil, limit: nil, expected: "https://token-tester.b-cdn.net/300kb.jpg?token=SmnSkK1stGqOJge706jsf-02HaCbUaVv7507ZrLP43k&expires=1727918622"},

    { user_ip: "192.168.100.100", path_allowed: "/300kb", countries_allowed: nil, countries_blocked: nil, limit: nil, expected: "https://token-tester.b-cdn.net/300kb.jpg?token=jriwRWg1R2Ba_fCAFP7KnIKoBCYgBzkJg83mD8hJchA&token_path=%2F300kb&expires=1727918622"},

    { user_ip: "192.168.100.100", path_allowed: "/300kb", path_url: false, expected: "https://token-tester.b-cdn.net/300kb.jpg?token=jriwRWg1R2Ba_fCAFP7KnIKoBCYgBzkJg83mD8hJchA&token_path=%2F300kb&expires=1727918622"}
  ]
  test_cases.each_with_index do |test_case, index|
    expected = test_case.delete(:expected)
    generated = sign_url(test_url, sec_key: sec_key, expires: expires, **test_case)
    puts "Test #{index}: #{expected == generated ? "\e[32mPASSED\e[0m" : "\e[31mFAILED\e[0m"}"
    puts "   Expected : #{expected}"
    puts "   Generated: #{generated}"
  end
end

tests

