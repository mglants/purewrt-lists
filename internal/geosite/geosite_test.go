package geosite

import (
	"encoding/binary"
	"slices"
	"testing"
)

// --- minimal protobuf encoders for building test fixtures ---

func uvarint(v uint64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(b, v)
	return b[:n]
}

func tag(field, wire int) []byte { return uvarint(uint64(field)<<3 | uint64(wire)) }

func lenField(field int, payload []byte) []byte {
	out := tag(field, wireLen)
	out = append(out, uvarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func varintField(field int, v uint64) []byte {
	return append(tag(field, wireVarint), uvarint(v)...)
}

// domain builds a Domain message: type + value.
func domain(dtype int, value string) []byte {
	b := varintField(1, uint64(dtype))
	b = append(b, lenField(2, []byte(value))...)
	return b
}

// geoSite builds a GeoSite message: country_code + domains.
func geoSite(code string, domains ...[]byte) []byte {
	b := lenField(1, []byte(code))
	for _, d := range domains {
		b = append(b, lenField(2, d)...)
	}
	return b
}

// geoSiteList wraps entries as GeoSiteList.entry (field 1).
func geoSiteList(entries ...[]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = append(b, lenField(1, e)...)
	}
	return b
}

func TestDomainsForCategory(t *testing.T) {
	const (
		typePlain  = 0
		typeRegex  = 1
		typeDomain = 2
		typeFull   = 3
	)
	blob := geoSiteList(
		geoSite("YOUTUBE",
			domain(typeDomain, "youtube.com"),
			domain(typeFull, "youtu.be"),
			domain(typePlain, "ytkeyword"), // skipped
			domain(typeRegex, ".*\\.ggpht\\.com"), // skipped
		),
		geoSite("OPENAI",
			domain(typeDomain, "openai.com"),
		),
	)

	got, skipped, err := DomainsForCategory(blob, "youtube")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{"youtu.be", "youtube.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("youtube domains = %v, want %v", got, want)
	}
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2 (keyword+regex)", skipped)
	}

	// Case-insensitive category match.
	ai, _, err := DomainsForCategory(blob, "OpenAI")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ai, []string{"openai.com"}) {
		t.Fatalf("openai = %v", ai)
	}

	// Unknown category → empty, no error.
	none, _, err := DomainsForCategory(blob, "nope")
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown category: got %v err %v", none, err)
	}
}

func TestCategories(t *testing.T) {
	blob := geoSiteList(geoSite("A"), geoSite("B"))
	cats, err := Categories(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cats, []string{"A", "B"}) {
		t.Fatalf("categories = %v", cats)
	}
}

func TestTruncatedNeverPanics(t *testing.T) {
	full := geoSiteList(geoSite("X", domain(2, "x.com")))
	for i := 0; i <= len(full); i++ {
		_, _, _ = DomainsForCategory(full[:i], "x") // must not panic
	}
}
