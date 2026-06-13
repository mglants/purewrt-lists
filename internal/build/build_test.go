package build

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// splitNative parses a .native file into (domains, cidrs) the same way the
// router's native_import path does: lines before the @cidr marker are
// domains, after are CIDRs; `#` comments skipped.
func splitNative(s string) (domains, cidrs []string) {
	inCIDR := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == cidrMarker {
			inCIDR = true
			continue
		}
		if inCIDR {
			cidrs = append(cidrs, line)
		} else {
			domains = append(domains, line)
		}
	}
	return domains, cidrs
}

// --- minimal geosite.dat fixture builder (mirrors geosite_test) ---
func uvarint(v uint64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	return b[:binary.PutUvarint(b, v)]
}
func lenF(field int, p []byte) []byte {
	out := append(uvarint(uint64(field)<<3|2), uvarint(uint64(len(p)))...)
	return append(out, p...)
}
func varF(field int, v uint64) []byte { return append(uvarint(uint64(field)<<3|0), uvarint(v)...) }
func dom(t int, v string) []byte      { return append(varF(1, uint64(t)), lenF(2, []byte(v))...) }
func site(code string, ds ...[]byte) []byte {
	b := lenF(1, []byte(code))
	for _, d := range ds {
		b = append(b, lenF(2, d)...)
	}
	return b
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return "file://" + p
}

func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()

	// geosite with a media category (youtube) and ai (openai).
	geo := append(
		lenF(1, site("YOUTUBE", dom(2, "youtube.com"))),
		lenF(1, site("OPENAI", dom(2, "openai.com")))...,
	)
	geoPath := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(geoPath, geo, 0o644); err != nil {
		t.Fatal(err)
	}

	// common domains include a youtube subdomain (must be subtracted) + a
	// same-parent pair (must collapse) + a unique blocked domain.
	domSrc := writeFile(t, dir, "domains.lst",
		"kids.youtube.com\nevil.example\nads.evil.example\nblocked.ru\n")
	// subnets: a /16 with a CDN /24 inside, a host route, a fully-CDN /24.
	subSrc := writeFile(t, dir, "subnet.lst", "10.0.0.0/16\n1.2.3.4/32\n45.45.45.0/24\n")
	cdnSrc := writeFile(t, dir, "cdn.sum", "10.0.5.0/24\n45.45.0.0/16\n")

	cfg := Config{
		Table: "inet blocklist", IPv6: true,
		Geosite: Geosite{URL: "file://" + geoPath},
		IPF:     IPFilter{DropHostRoutes: true, CDNExclude: []string{cdnSrc}},
		Categories: Categories{
			{Name: "media", Geosite: []string{"youtube"}},
			{Name: "ai", Geosite: []string{"openai"}},
			{Name: "common", Domains: []string{domSrc}, Subnets: []string{subSrc}},
		},
	}
	res, err := Run(cfg, 1700000000)
	if err != nil {
		t.Fatal(err)
	}

	// media has youtube.com, ai has openai.com.
	if !contains(res.Domains["media"], "youtube.com") || !contains(res.Domains["ai"], "openai.com") {
		t.Fatalf("media=%v ai=%v", res.Domains["media"], res.Domains["ai"])
	}
	// common: kids.youtube.com subtracted (under media), ads.evil.example
	// collapsed under evil.example.
	if contains(res.Domains["common"], "kids.youtube.com") {
		t.Fatalf("common still has youtube subdomain: %v", res.Domains["common"])
	}
	if contains(res.Domains["common"], "ads.evil.example") {
		t.Fatalf("subdomain not collapsed: %v", res.Domains["common"])
	}
	if !contains(res.Domains["common"], "evil.example") || !contains(res.Domains["common"], "blocked.ru") {
		t.Fatalf("common missing expected domains: %v", res.Domains["common"])
	}
	// subnets: host route gone, 45.45.45.0/24 fully inside CDN gone, /16 carved.
	cidrs := prefixStrings(res.Subnets["common"])
	if contains(cidrs, "1.2.3.4/32") || contains(cidrs, "45.45.45.0/24") || contains(cidrs, "10.0.5.0/24") {
		t.Fatalf("filter leaked: %v", cidrs)
	}
	if len(cidrs) == 0 {
		t.Fatalf("expected carved /16 remainder, got none")
	}

	// emit + sanity-check the per-category .native files: the marker-split
	// bare format (domains, then `@cidr`, then CIDRs) plus catalog.json.
	outDir := filepath.Join(dir, "out")
	if err := res.Emit(outDir); err != nil {
		t.Fatal(err)
	}
	nat, err := os.ReadFile(filepath.Join(outDir, "common.native"))
	if err != nil {
		t.Fatalf("common.native not emitted: %v", err)
	}
	doms, cidrs := splitNative(string(nat))
	if !contains(doms, "blocked.ru") || !contains(doms, "evil.example") {
		t.Fatalf("common domains = %v", doms)
	}
	if contains(doms, "kids.youtube.com") {
		t.Fatalf("common.native leaked subtracted subdomain")
	}
	for _, c := range cidrs {
		if _, err := netip.ParsePrefix(c); err != nil {
			t.Fatalf("common.native cidr %q invalid: %v", c, err)
		}
	}
	if len(cidrs) != len(res.Subnets["common"]) {
		t.Fatalf("common.native cidrs: got %d want %d", len(cidrs), len(res.Subnets["common"]))
	}
	mediaNat, err := os.ReadFile(filepath.Join(outDir, "media.native"))
	if err != nil {
		t.Fatalf("media.native not emitted: %v", err)
	}
	if strings.Contains(string(mediaNat), cidrMarker) {
		t.Fatalf("media.native has @cidr marker despite no subnets:\n%s", mediaNat)
	}
	mdoms, _ := splitNative(string(mediaNat))
	if !contains(mdoms, "youtube.com") {
		t.Fatalf("media.native missing domain:\n%s", mediaNat)
	}
	if _, err := os.Stat(filepath.Join(outDir, "ai.native")); err != nil {
		t.Fatalf("ai.native not emitted: %v", err)
	}
	cat, err := os.ReadFile(filepath.Join(outDir, "catalog.json"))
	if err != nil {
		t.Fatalf("catalog.json not emitted: %v", err)
	}
	for _, want := range []string{`"name": "common"`, `"file": "common.native"`, `"suggested_section": "common"`} {
		if !strings.Contains(string(cat), want) {
			t.Fatalf("catalog.json missing %q:\n%s", want, cat)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "manifest.json")); err != nil {
		t.Fatalf("manifest.json not emitted: %v", err)
	}
}

func TestLoadConfigCategoryOrder(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yaml")
	yaml := `
table: inet blocklist
geosite:
  url: file:///tmp/geosite.dat
categories:
  ai:
    geosite: [openai]
  media:
    geosite: [youtube]
  common:
    domains: [file:///tmp/d.lst]
    subnets: [file:///tmp/s.lst]
`
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(cfg.Categories))
	for i, c := range cfg.Categories {
		got[i] = c.Name
	}
	if strings.Join(got, ",") != "ai,media,common" {
		t.Fatalf("category order not preserved: %v", got)
	}
	if len(cfg.Categories[2].Domains) != 1 || len(cfg.Categories[2].Subnets) != 1 {
		t.Fatalf("common inputs not parsed: %+v", cfg.Categories[2])
	}

	// geosite entries without a geosite.url must be rejected.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("categories:\n  ai:\n    geosite: [openai]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil {
		t.Fatal("expected error for geosite entries without geosite.url")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
