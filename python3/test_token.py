"""Tests for BunnyCDN URL token authentication."""

import importlib.util
import os

import pytest

# "token" conflicts with the stdlib module of the same name,
# so we load it explicitly via importlib.
_spec = importlib.util.spec_from_file_location(
    "bunny_token",
    os.path.join(os.path.dirname(__file__), "token.py"),
)
bunny_token = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bunny_token)
sign_url = bunny_token.sign_url

SECURITY_KEY = "SecurityKey"
BASE_URL = "https://token-tester.b-cdn.net/300kb.jpg"
EXPIRES_AT = 1598024587


def test_with_countries_allowed():
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        countries_allowed="CA", path_allowed="/", is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-JWU7jhpnBGI-O54AYDAtrlZT86Ied4RTO2-Y8mUj60A"
        "&token_countries=CA&token_path=%2F&expires=1598024587"
    )


def test_with_countries_blocked():
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        countries_blocked="CA", is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-zKGmNRBaHRmB4THCwmIQK5U21wH-S9KaJ6Ht7Kq9Zlw"
        "&token_countries_blocked=CA&expires=1598024587"
    )


def test_with_ip_address():
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        user_ip="1.2.3.4", is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-1-L2rISTLcujMY9UFf2tbZ41d5i-Bme1g1oTK_Z2QMLJk"
        "&expires=1598024587"
    )


def test_with_ipv6_address():
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        user_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334", is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-1-1avZgnR84EtR3eNPVtiOT8RtI9UqcvijgXVU88vxZ60"
        "&expires=1598024587"
    )


def test_ipv6_compressed_form_matches_expanded():
    expanded = sign_url(
        BASE_URL, SECURITY_KEY,
        user_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334", is_directory=False,
        expires_at=EXPIRES_AT,
    )
    compressed = sign_url(
        BASE_URL, SECURITY_KEY,
        user_ip="2001:db8:85a3::8a2e:370:7334", is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert compressed == expanded


def test_combined_ipv6_country_directory():
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        user_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334", is_directory=True,
        countries_allowed="CA,US",
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-1-TrSbI6dVaWEq8s7tuydKyhJSo9oKHA64KBhb2SgNv0E"
        "&token_countries=CA%2CUS&expires=1598024587/abc/"
    )


def test_with_path_allowed():
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/300kb.jpg",
        SECURITY_KEY,
        path_allowed="/abc", is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/abc/300kb.jpg"
        "?token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ"
        "&token_path=%2Fabc&expires=1598024587"
    )


def test_directory_allowed():
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        is_directory=True,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-bTMv4RVOkjx2UXLfVDl-JIygaxfSIQP8UCnCy7CILuY"
        "&expires=1598024587/abc/"
    )


def test_directory_and_path_allowed():
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        is_directory=True, path_allowed="/abc",
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ"
        "&token_path=%2Fabc&expires=1598024587/abc/"
    )


def test_with_ignore_params():
    result = sign_url(
        "https://token-tester.b-cdn.net/300kb.jpg?v=123",
        SECURITY_KEY,
        ignore_params=True, is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-1lwWBD_c1IAGSj1UKPoxreu8ePDQ-Z9FoWLcRn_RRH0"
        "&token_ignore_params=true&expires=1598024587"
    )


def test_with_existing_query_params():
    result = sign_url(
        "https://token-tester.b-cdn.net/300kb.jpg?v=123",
        SECURITY_KEY,
        is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-q6oRQr-5ccQ-piO1HSEQu1DVMy9UMppRxGlIQwoeM5Y"
        "&v=123&expires=1598024587"
    )


def test_combined_ip_country_directory():
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        user_ip="1.2.3.4", is_directory=True, countries_allowed="CA,US",
        expires_at=EXPIRES_AT,
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-1-eZuSzuE7KvWxa-lfmEG6eVOp4OmuPlFyzD6acZT8j_o"
        "&token_countries=CA%2CUS&expires=1598024587/abc/"
    )


def test_with_speed_limit():
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        is_directory=False,
        expires_at=EXPIRES_AT,
        speed_limit=1000,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-DAVapqNNED3Z7JkjRTYX0UOIHNtbHEuuhRNEc4A7mMQ"
        "&limit=1000&expires=1598024587"
    )


def test_combined_speed_limit_ip_directory():
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        user_ip="1.2.3.4", is_directory=True,
        expires_at=EXPIRES_AT,
        speed_limit=5000,
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-1-NasywRGZDPxXIxBgQ2iyxSP3EWxxok3bzpYhWgaU8BQ"
        "&limit=5000&expires=1598024587/abc/"
    )


def test_validation_empty_key():
    with pytest.raises(ValueError, match="security_key"):
        sign_url(BASE_URL, "")


def test_validation_negative_expiry():
    with pytest.raises(ValueError, match="expiration_time"):
        sign_url(BASE_URL, SECURITY_KEY, expiration_time=-1)


def test_no_user_ip_omits_flag_prefix():
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        is_directory=False,
        expires_at=EXPIRES_AT,
    )
    assert "HS256-1-" not in result


def test_invalid_ip_raises():
    with pytest.raises(ValueError):
        sign_url(
            BASE_URL, SECURITY_KEY,
            user_ip="not-an-ip",
            is_directory=False,
            expires_at=EXPIRES_AT,
        )
