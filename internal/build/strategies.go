package build

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// candidatesFile is the published strategy list filename (must match purewrt's
// config.ZapretCandidatesPath basename).
const candidatesFile = "zapret_candidates.json"

type candidateList struct {
	Candidates []Strategy `json:"candidates"`
}

// EmitStrategies writes <dir>/zapret_candidates.json and, for any blob that
// declares a source (its url, or blobs_base+file), fetches it into
// <dir>/blobs/<file> and fills in its sha256. Blobs without a source are left
// as {name,file} — the router resolves those from its zapret package. Returns
// the list of warnings (unresolvable/duplicate issues) for the caller to log.
func EmitStrategies(sc StrategyConfig, dir string) ([]string, error) {
	if len(sc.Candidates) == 0 {
		return nil, nil
	}
	var warns []string
	seenName := map[string]bool{}
	for _, c := range sc.Candidates {
		if c.Name == "" || c.Params == "" {
			return nil, fmt.Errorf("strategy candidate missing name/params: %+v", c)
		}
		if seenName[c.Name] {
			return nil, fmt.Errorf("duplicate strategy candidate name %q", c.Name)
		}
		seenName[c.Name] = true
		if strings.Contains(c.Params, "--dpi-desync") {
			warns = append(warns, fmt.Sprintf("candidate %q uses legacy --dpi-desync syntax", c.Name))
		}
	}

	// Fetch each unique sourced blob once; record its sha256.
	sums := map[string]string{} // file -> sha256
	blobDir := filepath.Join(dir, "blobs")
	for i := range sc.Candidates {
		for j := range sc.Candidates[i].Blobs {
			b := &sc.Candidates[i].Blobs[j]
			if b.Name == "" || b.File == "" {
				return nil, fmt.Errorf("candidate %q blob missing name/file", sc.Candidates[i].Name)
			}
			if sum, done := sums[b.File]; done {
				b.SHA256 = sum
				continue
			}
			// Resolve blob bytes: an in-repo file (BlobsDir) wins over a remote
			// source; a blob with neither is left as {name,file} for the router
			// to resolve from its shipped zapret package.
			data, err := localBlob(sc.BlobsDir, b.File)
			if err != nil {
				return nil, fmt.Errorf("candidate %q blob %s: %w", sc.Candidates[i].Name, b.File, err)
			}
			if data == nil {
				src := blobSource(sc.BlobsBase, *b)
				if src == "" {
					continue
				}
				data, err = fetchBlob(src)
				if err != nil {
					warns = append(warns, fmt.Sprintf("blob %s: %v (skipped bundling)", b.File, err))
					continue
				}
			}
			if err := os.MkdirAll(blobDir, 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(blobDir, b.File), data, 0o644); err != nil {
				return nil, err
			}
			sum := sha256hex(data)
			sums[b.File] = sum
			b.SHA256 = sum
		}
	}

	out, err := json.MarshalIndent(candidateList{Candidates: sc.Candidates}, "", "  ")
	if err != nil {
		return nil, err
	}
	return warns, os.WriteFile(filepath.Join(dir, candidatesFile), append(out, '\n'), 0o644)
}

// localBlob reads an in-repo blob from dir when dir is set and the file exists
// there. Returns (nil, nil) when there is no local copy, so the caller falls
// back to a remote source.
func localBlob(dir, file string) ([]byte, error) {
	if dir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.Base(file)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// blobSource resolves a blob's fetch URL: explicit url, else blobs_base+file.
func blobSource(base string, b Blob) string {
	if b.URL != "" {
		return b.URL
	}
	if base == "" {
		return ""
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + b.File
}

func fetchBlob(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func sha256hex(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}
