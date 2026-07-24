// Command emit signs the e2e input cases with the Go signer and prints a
// JSON object mapping each case name to its extracted token. It is used by
// CI to prove the Go signer produces the canonical e2e tokens.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	bunnycdn "bunnycdn-token-authentication"
)

type inputs struct {
	Key     string `json:"key"`
	Expires int64  `json:"expires"`
	Host    string `json:"host"`
	Cases   []struct {
		Name             string `json:"name"`
		Path             string `json:"path"`
		UserIp           string `json:"userIp"`
		IsDirectory      bool   `json:"isDirectory"`
		PathAllowed      string `json:"pathAllowed"`
		CountriesAllowed string `json:"countriesAllowed"`
		CountriesBlocked string `json:"countriesBlocked"`
		IgnoreParams     bool   `json:"ignoreParams"`
		SpeedLimit       int64  `json:"speedLimit"`
		CountryCode      string `json:"countryCode"`
	} `json:"cases"`
}

// extractToken pulls the token value out of a signed URL: the substring after
// "bcdn_token=" if present, otherwise after "token=", up to the next "&".
func extractToken(signedUrl string) string {
	marker := "bcdn_token="
	idx := strings.Index(signedUrl, marker)
	if idx < 0 {
		marker = "token="
		idx = strings.Index(signedUrl, marker)
		if idx < 0 {
			return ""
		}
	}
	rest := signedUrl[idx+len(marker):]
	if amp := strings.IndexByte(rest, '&'); amp >= 0 {
		rest = rest[:amp]
	}
	return rest
}

func main() {
	path := "e2e/inputs.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}

	var in inputs
	if err := json.Unmarshal(data, &in); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
		os.Exit(1)
	}

	expires := in.Expires
	out := make(map[string]string, len(in.Cases))
	for _, c := range in.Cases {
		signedUrl, err := bunnycdn.SignUrl(
			in.Host+c.Path,
			in.Key,
			86400,
			c.UserIp,
			c.IsDirectory,
			c.PathAllowed,
			c.CountriesAllowed,
			c.CountriesBlocked,
			c.IgnoreParams,
			&expires,
			c.SpeedLimit,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sign case %q: %v\n", c.Name, err)
			os.Exit(1)
		}
		out[c.Name] = extractToken(signedUrl)
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		os.Exit(1)
	}
}
