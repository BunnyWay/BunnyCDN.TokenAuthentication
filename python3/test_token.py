"""Tests for BunnyCDN URL token authentication."""

import importlib.util
import os
from unittest.mock import patch

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
# We want expires = 1598024587. With default expiration_time=86400,
# time.time() must return 1598024587 - 86400 = 1597938187.
MOCK_TIME = 1597938187


@patch("time.time", return_value=MOCK_TIME)
def test_with_countries_allowed(_mock):
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        countries_allowed="CA", path_allowed="/", is_directory=False,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-JWU7jhpnBGI-O54AYDAtrlZT86Ied4RTO2-Y8mUj60A"
        "&token_countries=CA&token_path=%2F&expires=1598024587"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_with_countries_blocked(_mock):
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        countries_blocked="CA", is_directory=False,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-zKGmNRBaHRmB4THCwmIQK5U21wH-S9KaJ6Ht7Kq9Zlw"
        "&token_countries_blocked=CA&expires=1598024587"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_with_ip_address(_mock):
    result = sign_url(
        BASE_URL, SECURITY_KEY,
        user_ip="1.2.3.4", is_directory=False,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-0A9FRzMI9ACT-5VKMPbJf7g8f7UHavqjBH1Z8HljoEk"
        "&expires=1598024587"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_with_path_allowed(_mock):
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/300kb.jpg",
        SECURITY_KEY,
        path_allowed="/abc", is_directory=False,
    )
    assert result == (
        "https://token-tester.b-cdn.net/abc/300kb.jpg"
        "?token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ"
        "&token_path=%2Fabc&expires=1598024587"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_directory_allowed(_mock):
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        is_directory=True,
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-bTMv4RVOkjx2UXLfVDl-JIygaxfSIQP8UCnCy7CILuY"
        "&expires=1598024587/abc/"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_directory_and_path_allowed(_mock):
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        is_directory=True, path_allowed="/abc",
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ"
        "&token_path=%2Fabc&expires=1598024587/abc/"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_with_ignore_params(_mock):
    result = sign_url(
        "https://token-tester.b-cdn.net/300kb.jpg?v=123",
        SECURITY_KEY,
        ignore_params=True, is_directory=False,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-1lwWBD_c1IAGSj1UKPoxreu8ePDQ-Z9FoWLcRn_RRH0"
        "&token_ignore_params=true&expires=1598024587"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_with_existing_query_params(_mock):
    result = sign_url(
        "https://token-tester.b-cdn.net/300kb.jpg?v=123",
        SECURITY_KEY,
        is_directory=False,
    )
    assert result == (
        "https://token-tester.b-cdn.net/300kb.jpg"
        "?token=HS256-q6oRQr-5ccQ-piO1HSEQu1DVMy9UMppRxGlIQwoeM5Y"
        "&v=123&expires=1598024587"
    )


@patch("time.time", return_value=MOCK_TIME)
def test_combined_ip_country_directory(_mock):
    result = sign_url(
        "https://token-tester.b-cdn.net/abc/",
        SECURITY_KEY,
        user_ip="1.2.3.4", is_directory=True, countries_allowed="CA,US",
    )
    assert result == (
        "https://token-tester.b-cdn.net/"
        "bcdn_token=HS256-pj8ytucbBWXT_M5cAqKGu4pshB2Q_s28G2uMfjhc3lA"
        "&token_countries=CA%2CUS&expires=1598024587/abc/"
    )


def test_validation_empty_key():
    with pytest.raises(ValueError, match="security_key"):
        sign_url(BASE_URL, "")


def test_validation_negative_expiry():
    with pytest.raises(ValueError, match="expiration_time"):
        sign_url(BASE_URL, SECURITY_KEY, expiration_time=-1)
