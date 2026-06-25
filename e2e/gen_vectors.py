#!/usr/bin/env python3
"""Generate e2e/vectors.json — reference tokens for cross-language consistency.

Every language SDK must produce the exact same token for the same inputs. This
writes the reference output of the Python signer for the shared inputs.json
cases; a CI freshness check re-runs it (fails if vectors.json is stale), and the
per-language emitters are compared against it. Purely signing output — inputs
and the resulting signed URL/token, both of which any caller can produce.

Run:   python e2e/gen_vectors.py          (writes e2e/vectors.json)
Check: python e2e/gen_vectors.py --check  (exit 1 if vectors.json is stale)
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(HERE, "vectors.json")
INPUTS = os.path.join(HERE, "inputs.json")

# Load the sibling python3/token.py by path (its module name `token` shadows a
# stdlib module, so we never import it by name).
_spec = importlib.util.spec_from_file_location(
    "bunny_signer", os.path.join(REPO, "python3", "token.py"))
signer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(signer)


def extract_token(signed_url):
    marker = "bcdn_token=" if "/bcdn_token=" in signed_url else "token="
    return signed_url.split(marker, 1)[1].split("&", 1)[0]


def build():
    with open(INPUTS, encoding="utf-8") as f:
        spec = json.load(f)
    key, expires, host = spec["key"], spec["expires"], spec["host"]

    vectors = []
    for c in spec["cases"]:
        signed = signer.sign_url(
            host + c["path"], key, 86400,
            user_ip=c["userIp"], is_directory=c["isDirectory"],
            path_allowed=c["pathAllowed"], countries_allowed=c["countriesAllowed"],
            countries_blocked=c["countriesBlocked"], ignore_params=c["ignoreParams"],
            expires_at=expires, speed_limit=c["speedLimit"])
        vectors.append({
            "name": c["name"],
            "signedUrl": signed,
            "token": extract_token(signed),
        })
    return {"generatedFrom": "python3/token.py", "vectors": vectors}


def main():
    text = json.dumps(build(), indent=2) + "\n"
    if "--check" in sys.argv:
        if not os.path.exists(OUT):
            print("vectors.json missing; run: python e2e/gen_vectors.py", file=sys.stderr)
            return 1
        if open(OUT, encoding="utf-8").read() != text:
            print("vectors.json is STALE — regenerate with: python e2e/gen_vectors.py", file=sys.stderr)
            return 1
        print("vectors.json is up to date.")
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
