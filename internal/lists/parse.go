// Package lists parses blocklist source files (plain domains, dnsmasq
// nftset=/server= lines, classical DOMAIN-SUFFIX/IP-CIDR rules, bare CIDRs)
// into normalized domain and prefix sets, and provides the suffix/subnet
// reductions the dnsmasq nftset emission relies on.
package lists

import (
	"bufio"
	"bytes"
	"net/netip"
	"slices"
	"strings"
)

// ParseDomains extracts normalized domains from a source file. It accepts
// plain one-per-line domains, dnsmasq `nftset=/d/...` and `server=/d/...`
// directives, and classical `DOMAIN,d` / `DOMAIN-SUFFIX,d` lines. Comments
// (`#`, `//`) and unparseable lines are skipped.
func ParseDomains(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if d, ok := dnsmasqDomain(line); ok {
			if d := NormalizeDomain(d); IsValidDomain(d) {
				out = append(out, d)
			}
			continue
		}
		// classical "TYPE,value[,...]"
		if i := strings.IndexByte(line, ','); i > 0 {
			switch strings.ToUpper(strings.TrimSpace(line[:i])) {
			case "DOMAIN", "DOMAIN-SUFFIX":
				rest := line[i+1:]
				if j := strings.IndexByte(rest, ','); j >= 0 {
					rest = rest[:j]
				}
				if d := NormalizeDomain(rest); IsValidDomain(d) {
					out = append(out, d)
				}
				continue
			case "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOSITE", "GEOIP":
				continue // not representable as a dnsmasq suffix entry
			}
		}
		if d := NormalizeDomain(line); IsValidDomain(d) {
			out = append(out, d)
		}
	}
	return out
}

// ParseCIDRs extracts IPv4/IPv6 prefixes from a source file: bare CIDRs,
// bare IPs (→ /32 or /128), and classical `IP-CIDR,cidr` / `IP-CIDR6,cidr`
// lines. Invalid tokens are skipped.
func ParseCIDRs(data []byte) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		tok := line
		if i := strings.IndexByte(line, ','); i > 0 {
			switch strings.ToUpper(strings.TrimSpace(line[:i])) {
			case "IP-CIDR", "IP-CIDR6":
				tok = line[i+1:]
				if j := strings.IndexByte(tok, ','); j >= 0 {
					tok = tok[:j]
				}
			default:
				continue
			}
		}
		if p, ok := parsePrefix(strings.TrimSpace(tok)); ok {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefix(tok string) (netip.Prefix, bool) {
	if strings.ContainsRune(tok, '/') {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(tok)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// dnsmasqDomain extracts the domain from `nftset=/d/...` or `server=/d/...`.
func dnsmasqDomain(line string) (string, bool) {
	for _, pfx := range []string{"nftset=/", "server=/", "ipset=/", "address=/"} {
		if strings.HasPrefix(line, pfx) {
			rest := line[len(pfx):]
			if i := strings.IndexByte(rest, '/'); i > 0 {
				return rest[:i], true
			}
			return "", false
		}
	}
	return "", false
}

// NormalizeDomain lowercases and strips a leading "*."/"." and trailing dot.
func NormalizeDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "*.")
	v = strings.TrimPrefix(v, ".")
	return strings.TrimSuffix(v, ".")
}

// IsValidDomain rejects empties, wildcards, over-long names, and labels with
// illegal characters — enough to keep junk out of the dnsmasq conf.
func IsValidDomain(v string) bool {
	if v == "" || len(v) > 253 || !strings.Contains(v, ".") {
		return false
	}
	if strings.ContainsAny(v, "*/ \t#") || strings.Contains(v, "..") {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// SubtractSuffix returns the domains in base that are neither equal to nor a
// subdomain of any domain in exclude. This is what keeps `common` free of
// everything under a media/ai domain: dnsmasq uses longest-match, so a
// leftover `kids.youtube.com` in common would override media's `youtube.com`.
func SubtractSuffix(base, exclude []string) []string {
	ex := make(map[string]struct{}, len(exclude))
	for _, d := range exclude {
		ex[d] = struct{}{}
	}
	out := base[:0:0]
	for _, d := range base {
		if !hasAncestor(d, ex, true) {
			out = append(out, d)
		}
	}
	return out
}

// CollapseSubdomains drops any domain whose suffix-ancestor is also present
// in the same set — lossless under dnsmasq's suffix match. Returns the kept
// domains and the count removed.
func CollapseSubdomains(domains []string) (kept []string, dropped int) {
	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		set[d] = struct{}{}
	}
	for _, d := range domains {
		if hasAncestor(d, set, false) {
			dropped++
			continue
		}
		kept = append(kept, d)
	}
	return kept, dropped
}

// hasAncestor reports whether a proper ancestor of d (or d itself when
// includeSelf) is present in set. Walks labels upward: a.b.c → b.c → c.
func hasAncestor(d string, set map[string]struct{}, includeSelf bool) bool {
	if includeSelf {
		if _, ok := set[d]; ok {
			return true
		}
	}
	for {
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
		if !strings.Contains(d, ".") {
			return false // a TLD like "com" is never a blocking ancestor
		}
		if _, ok := set[d]; ok {
			return true
		}
	}
}

// Dedup sorts and removes duplicate strings in place semantics (returns new).
func DedupSort(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}
