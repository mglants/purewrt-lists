package build

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// userAgent identifies the builder so source operators can attribute traffic.
const userAgent = "nftset-builder/1 (+https://github.com/purewrt/nftset-builder)"

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// fetch loads a source by URL (http/https), file:// URL, or local path, and
// transparently gunzips a gzip-magic or .gz-suffixed body.
func fetch(src string) ([]byte, error) {
	var raw []byte
	switch {
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		req, err := http.NewRequest(http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("GET %s: %s", src, resp.Status)
		}
		raw, err = io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		if err != nil {
			return nil, err
		}
	default:
		path := strings.TrimPrefix(src, "file://")
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return maybeGunzip(raw, src), nil
}

func maybeGunzip(raw []byte, src string) []byte {
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		if zr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			defer func() { _ = zr.Close() }()
			if out, err := io.ReadAll(io.LimitReader(zr, 1<<30)); err == nil {
				return out
			}
		}
	}
	return raw
}
