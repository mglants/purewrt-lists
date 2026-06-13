package build

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cidrMarker separates the domain section from the CIDR section in a
// .native file. Everything before it is bare domains, everything after is
// bare CIDRs (v4+v6). The router (purewrt parse_mode=native_import) reads
// it with a single cheap line scan — no per-line parsing or validation.
const cidrMarker = "@cidr"

// CatalogEntry is one row of catalog.json — the wizard's list picker.
type CatalogEntry struct {
	Name            string `json:"name"`
	File            string `json:"file"`
	SuggestedSection string `json:"suggested_section"`
	Domains         int    `json:"domains"`
	Subnets         int    `json:"subnets"`
}

// Emit writes the bundle to dir: one <category>.native per category, a
// catalog.json index for the wizard, and manifest.json (the audit record).
func (r *Result) Emit(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var catalog []CatalogEntry
	for _, s := range r.Sections {
		file := s + ".native"
		if err := os.WriteFile(filepath.Join(dir, file), []byte(r.renderNative(s)), 0o644); err != nil {
			return err
		}
		catalog = append(catalog, CatalogEntry{
			Name: s, File: file, SuggestedSection: s,
			Domains: len(r.Domains[s]), Subnets: len(r.Subnets[s]),
		})
	}
	if err := writeJSON(filepath.Join(dir, "catalog.json"), catalog); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "manifest.json"), r.Manifest)
}

// renderNative emits the marker-split bare format: header, bare domains,
// then `@cidr` + bare CIDRs (only when the category has subnets). The data
// is already normalized, deduped, subdomain-collapsed, host-route-dropped,
// CDN-carved and supernet-collapsed by the build pipeline, so the consumer
// imports it verbatim.
func (r *Result) renderNative(s string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# purewrt-native v1\t%s\tbuild=%d\n", s, r.Manifest.BuildStamp)
	for _, d := range r.Domains[s] {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	if len(r.Subnets[s]) > 0 {
		b.WriteString(cidrMarker)
		b.WriteByte('\n')
		for _, p := range r.Subnets[s] {
			b.WriteString(p.String())
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
