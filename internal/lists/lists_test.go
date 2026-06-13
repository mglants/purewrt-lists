package lists

import (
	"math/big"
	"net/netip"
	"slices"
	"testing"
)

func TestParseDomains(t *testing.T) {
	in := []byte(`
# comment
nftset=/ruantiblock.example/4#inet#x#s
server=/srv.example/1.2.3.4
DOMAIN-SUFFIX,suffix.example,proxy
DOMAIN,exact.example
plain.example
*.wild.example
DOMAIN-KEYWORD,kw
not a domain
`)
	got := DedupSort(ParseDomains(in))
	want := []string{"exact.example", "plain.example", "ruantiblock.example", "srv.example", "suffix.example", "wild.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestSubtractSuffix(t *testing.T) {
	common := []string{"kids.youtube.com", "evil.com", "youtube.com", "a.evil.com"}
	excl := []string{"youtube.com"}
	got := SubtractSuffix(common, excl)
	slices.Sort(got)
	// youtube.com (exact) and kids.youtube.com (descendant) removed.
	want := []string{"a.evil.com", "evil.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCollapseSubdomains(t *testing.T) {
	got, dropped := CollapseSubdomains([]string{"a.com", "x.a.com", "y.x.a.com", "b.com"})
	slices.Sort(got)
	if !slices.Equal(got, []string{"a.com", "b.com"}) {
		t.Fatalf("got %v", got)
	}
	if dropped != 2 {
		t.Fatalf("dropped = %d want 2", dropped)
	}
}

func mustP(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func TestFilterSubnets_CDNCarveOut(t *testing.T) {
	// blocked /16 with a CDN /24 inside → keep /16 minus /24.
	cands := []netip.Prefix{mustP("10.0.0.0/16")}
	cdn := []netip.Prefix{mustP("10.0.5.0/24")}
	got, counts := FilterSubnets(cands, cdn, SubnetOpts{DropHostRoutes: true})
	// reconstruct coverage: union of got must equal 10.0.0.0/16 minus 10.0.5.0/24
	if slices.Contains(strs(got), "10.0.5.0/24") {
		t.Fatalf("CDN /24 must be carved out, got %v", strs(got))
	}
	if !coversExactly(got, "10.0.0.0/16", "10.0.5.0/24") {
		t.Fatalf("carve-out coverage wrong: %v", strs(got))
	}
	if counts.CDNCarved != 1 {
		t.Fatalf("CDNCarved = %d want 1", counts.CDNCarved)
	}
}

func TestFilterSubnets_FullyInsideCDN(t *testing.T) {
	got, _ := FilterSubnets([]netip.Prefix{mustP("10.0.5.0/24")}, []netip.Prefix{mustP("10.0.0.0/16")}, SubnetOpts{})
	if len(got) != 0 {
		t.Fatalf("blocked subnet fully inside CDN must vanish, got %v", strs(got))
	}
}

func TestFilterSubnets_HostRoutesAndPassthrough(t *testing.T) {
	cands := []netip.Prefix{mustP("1.2.3.4/32"), mustP("203.0.113.0/24"), mustP("2001:db8::1/128")}
	got, counts := FilterSubnets(cands, nil, SubnetOpts{DropHostRoutes: true})
	if !slices.Equal(strs(got), []string{"203.0.113.0/24"}) {
		t.Fatalf("got %v want [203.0.113.0/24]", strs(got))
	}
	if counts.HostRoutesDropped != 2 {
		t.Fatalf("HostRoutesDropped = %d want 2", counts.HostRoutesDropped)
	}
}

func TestFilterSubnets_SupernetCollapse(t *testing.T) {
	got, counts := FilterSubnets([]netip.Prefix{mustP("10.0.0.0/22"), mustP("10.0.1.0/24")}, nil, SubnetOpts{})
	if !slices.Equal(strs(got), []string{"10.0.0.0/22"}) {
		t.Fatalf("got %v", strs(got))
	}
	if counts.ChildrenCollapsed != 1 {
		t.Fatalf("ChildrenCollapsed = %d want 1", counts.ChildrenCollapsed)
	}
}

func TestRangeToCIDRs_Unaligned(t *testing.T) {
	lo := addrToInt(netip.MustParseAddr("10.0.0.5"))
	hi := addrToInt(netip.MustParseAddr("10.0.0.10"))
	got := strs(rangeToCIDRs(lo, hi, true))
	want := []string{"10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/31", "10.0.0.10/32"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseCIDRs(t *testing.T) {
	in := []byte("10.0.0.0/24\n1.2.3.4\nIP-CIDR,192.168.0.0/16,no-resolve\n2001:db8::/32\n# x\njunk\n")
	got := strs(ParseCIDRs(in))
	slices.Sort(got)
	want := []string{"1.2.3.4/32", "10.0.0.0/24", "192.168.0.0/16", "2001:db8::/32"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// coversExactly checks that the union of got equals base minus hole.
func coversExactly(got []netip.Prefix, base, hole string) bool {
	bp, hp := mustP(base), mustP(hole)
	inGot := func(a netip.Addr) bool {
		for _, p := range got {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	// sample: every address in base must be covered iff it's not in hole.
	// exhaustive over a /16 is 65k — fine for a test.
	lo, hi := prefixRange(bp)
	cur := new(big.Int).Set(lo)
	one := big.NewInt(1)
	for cur.Cmp(hi) <= 0 {
		a := intToAddr(cur, bp.Addr().Is4())
		want := !hp.Contains(a)
		if inGot(a) != want {
			return false
		}
		cur.Add(cur, one)
	}
	return true
}
