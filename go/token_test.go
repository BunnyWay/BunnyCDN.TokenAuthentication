package bunnycdn

import (
	"strings"
	"testing"
)

const securityKey = "SecurityKey"

var expiresAt int64 = 1598024587

func TestWithCountriesAllowed(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "", false, "/", "CA", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-JWU7jhpnBGI-O54AYDAtrlZT86Ied4RTO2-Y8mUj60A&token_countries=CA&token_path=%2F&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestWithCountriesBlocked(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "", false, "", "", "CA", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-zKGmNRBaHRmB4THCwmIQK5U21wH-S9KaJ6Ht7Kq9Zlw&token_countries_blocked=CA&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestWithIPAddress(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "1.2.3.4", false, "", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1-L2rISTLcujMY9UFf2tbZ41d5i-Bme1g1oTK_Z2QMLJk&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestWithIPv6Address(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false, "", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1-1avZgnR84EtR3eNPVtiOT8RtI9UqcvijgXVU88vxZ60&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestIPv6CompressedFormMatchesExpanded(t *testing.T) {
	expanded, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false, "", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "2001:db8:85a3::8a2e:370:7334", false, "", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if compressed != expanded {
		t.Errorf("compressed %s != expanded %s", compressed, expanded)
	}
}

func TestCombinedIPv6CountryDirectory(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/abc/",
		securityKey, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true, "", "CA,US", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/bcdn_token=HS256-1-TrSbI6dVaWEq8s7tuydKyhJSo9oKHA64KBhb2SgNv0E&token_countries=CA%2CUS&expires=1598024587/abc/"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestWithPathAllowed(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/abc/300kb.jpg",
		securityKey, 86400, "", false, "/abc", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/abc/300kb.jpg?token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestDirectoryAllowed(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/abc/",
		securityKey, 86400, "", true, "", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/bcdn_token=HS256-bTMv4RVOkjx2UXLfVDl-JIygaxfSIQP8UCnCy7CILuY&expires=1598024587/abc/"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestDirectoryAndPathAllowed(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/abc/",
		securityKey, 86400, "", true, "/abc", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/bcdn_token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587/abc/"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestWithIgnoreParams(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg?v=123",
		securityKey, 86400, "", false, "", "", "", true, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1lwWBD_c1IAGSj1UKPoxreu8ePDQ-Z9FoWLcRn_RRH0&token_ignore_params=true&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestWithExistingQueryParams(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg?v=123",
		securityKey, 86400, "", false, "", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-q6oRQr-5ccQ-piO1HSEQu1DVMy9UMppRxGlIQwoeM5Y&v=123&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestCombinedIPCountryDirectory(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/abc/",
		securityKey, 86400, "1.2.3.4", true, "", "CA,US", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/bcdn_token=HS256-1-eZuSzuE7KvWxa-lfmEG6eVOp4OmuPlFyzD6acZT8j_o&token_countries=CA%2CUS&expires=1598024587/abc/"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestWithSpeedLimit(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "", false, "", "", "", false, &expiresAt, 1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-DAVapqNNED3Z7JkjRTYX0UOIHNtbHEuuhRNEc4A7mMQ&limit=1000&expires=1598024587"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestCombinedSpeedLimitIPDirectory(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/abc/",
		securityKey, 86400, "1.2.3.4", true, "", "", "", false, &expiresAt, 5000,
	)
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://token-tester.b-cdn.net/bcdn_token=HS256-1-NasywRGZDPxXIxBgQ2iyxSP3EWxxok3bzpYhWgaU8BQ&limit=5000&expires=1598024587/abc/"
	if result != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestValidationEmptyKey(t *testing.T) {
	_, err := SignUrl("https://example.com/f.jpg", "", 86400, "", false, "", "", "", false, nil, 0)
	if err == nil {
		t.Error("expected error for empty security key")
	}
}

func TestValidationNegativeExpiry(t *testing.T) {
	_, err := SignUrl("https://example.com/f.jpg", "key", -1, "", false, "", "", "", false, nil, 0)
	if err == nil {
		t.Error("expected error for negative expiration time")
	}
}

func TestNoUserIpOmitsFlagPrefix(t *testing.T) {
	result, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "", false, "", "", "", false, &expiresAt, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "HS256-1-") {
		t.Errorf("expected no HS256-1- flag prefix when userIp is empty, got %s", result)
	}
}

func TestInvalidIpReturnsError(t *testing.T) {
	_, err := SignUrl(
		"https://token-tester.b-cdn.net/300kb.jpg",
		securityKey, 86400, "not-an-ip", false, "", "", "", false, &expiresAt, 0,
	)
	if err == nil {
		t.Error("expected error for invalid userIp")
	}
}
