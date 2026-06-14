package build

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/purewrt/nftset-builder/internal/geosite"
	"github.com/purewrt/nftset-builder/internal/lists"
)

// Result is the in-memory bundle plus the manifest, ready to emit.
type Result struct {
	Family   string
	Table    string
	IPv6     bool
	Sections   []string                  // category names in declaration/emit order
	Priorities map[string]int            // category → catalog routing priority
	Domains    map[string][]string       // category → sorted domains
	Subnets    map[string][]netip.Prefix // category → sorted prefixes
	Manifest   Manifest
}

type Manifest struct {
	BuildStamp        int64               `json:"build_stamp"`
	Table             string              `json:"table"`
	Sources           map[string][]string `json:"sources"`
	DomainCounts      map[string]int      `json:"domain_counts"`
	SubnetCounts      map[string]int      `json:"subnet_counts"`
	GeositeSkipped    int                 `json:"geosite_skipped"`
	SubdomainsDropped int                 `json:"subdomains_collapsed"`
	SuffixSubtracted  int                 `json:"suffix_subtracted"`
	SubnetFilter      lists.SubnetCounts  `json:"subnet_filter"`
	Warnings          []string            `json:"warnings,omitempty"`
}

// Run executes the full pipeline. stamp is the reproducible build timestamp.
func Run(cfg Config, stamp int64) (*Result, error) {
	family, table, err := cfg.familyTable()
	if err != nil {
		return nil, err
	}
	res := &Result{
		Family: family, Table: table, IPv6: cfg.IPv6,
		Priorities: map[string]int{},
		Domains:    map[string][]string{}, Subnets: map[string][]netip.Prefix{},
		Manifest: Manifest{
			BuildStamp: stamp, Table: cfg.Table,
			Sources:      map[string][]string{},
			DomainCounts: map[string]int{}, SubnetCounts: map[string]int{},
		},
	}
	for _, cat := range cfg.Categories {
		res.Sections = append(res.Sections, cat.Name)
		res.Priorities[cat.Name] = cat.EffectivePriority()
	}
	warn := func(format string, a ...any) {
		res.Manifest.Warnings = append(res.Manifest.Warnings, fmt.Sprintf(format, a...))
	}

	// geosite.dat fetched once, shared by every category's geosite entries.
	var geoData []byte
	for _, cat := range cfg.Categories {
		if len(cat.Geosite) > 0 {
			geoData, err = fetch(cfg.Geosite.URL)
			if err != nil {
				return nil, fmt.Errorf("geosite fetch: %w", err)
			}
			res.Manifest.Sources["geosite"] = []string{cfg.Geosite.URL}
			break
		}
	}

	// CDN carve-out list fetched once, applied to every category's subnets.
	var cdn []netip.Prefix
	for _, src := range cfg.IPF.CDNExclude {
		data, err := fetch(src)
		if err != nil {
			// A CDN list that fails to load would silently under-exclude — fatal.
			return nil, fmt.Errorf("cdn_exclude source failed (would under-exclude CDN): %s: %w", src, err)
		}
		cdn = append(cdn, lists.ParseCIDRs(data)...)
		res.Manifest.Sources["cdn_exclude"] = append(res.Manifest.Sources["cdn_exclude"], src)
	}
	opts := lists.SubnetOpts{
		DropHostRoutes: cfg.IPF.DropHostRoutes,
		MinPrefixV4:    cfg.IPF.MinPrefixV4,
		MinPrefixV6:    cfg.IPF.MinPrefixV6,
	}

	// 1. per-category inputs: geosite categories + domain lists + subnet lists.
	catDomains := map[string][]string{}
	for _, cat := range cfg.Categories {
		var doms []string
		for _, gc := range cat.Geosite {
			d, skipped, err := geosite.DomainsForCategory(geoData, gc)
			if err != nil {
				return nil, fmt.Errorf("geosite category %s: %w", gc, err)
			}
			if len(d) == 0 {
				warn("geosite category %q (category %s) produced no domains", gc, cat.Name)
			}
			doms = append(doms, d...)
			res.Manifest.GeositeSkipped += skipped
		}
		for _, src := range cat.Domains {
			data, err := fetch(src)
			if err != nil {
				warn("%s domains source failed: %s: %v", cat.Name, src, err)
				continue
			}
			doms = append(doms, lists.ParseDomains(data)...)
			res.Manifest.Sources[cat.Name+"_domains"] = append(res.Manifest.Sources[cat.Name+"_domains"], src)
		}
		catDomains[cat.Name] = lists.DedupSort(doms)

		// subnets → filter (host-route + CDN carve-out + collapse).
		var candidates []netip.Prefix
		for _, src := range cat.Subnets {
			data, err := fetch(src)
			if err != nil {
				warn("%s subnets source failed: %s: %v", cat.Name, src, err)
				continue
			}
			candidates = append(candidates, lists.ParseCIDRs(data)...)
			res.Manifest.Sources[cat.Name+"_subnets"] = append(res.Manifest.Sources[cat.Name+"_subnets"], src)
		}
		var subnets []netip.Prefix
		if len(candidates) > 0 {
			var counts lists.SubnetCounts
			subnets, counts = lists.FilterSubnets(candidates, cdn, opts)
			addSubnetCounts(&res.Manifest.SubnetFilter, counts)
			if !cfg.IPv6 {
				subnets = dropV6(subnets)
			}
		}
		res.Subnets[cat.Name] = subnets
		res.Manifest.SubnetCounts[cat.Name] = len(subnets)
	}

	// 2. suffix-aware subtract: a category loses anything equal-to/under a
	//    domain of an earlier-declared category (declaration order = priority).
	var higher []string
	for _, cat := range cfg.Categories {
		doms := catDomains[cat.Name]
		if len(higher) > 0 && len(doms) > 0 {
			before := len(doms)
			doms = lists.SubtractSuffix(doms, higher)
			res.Manifest.SuffixSubtracted += before - len(doms)
			catDomains[cat.Name] = doms
		}
		higher = append(higher, doms...)
	}

	// 3. within-set subdomain collapse.
	total := 0
	for _, cat := range cfg.Categories {
		kept, dropped := lists.CollapseSubdomains(catDomains[cat.Name])
		res.Manifest.SubdomainsDropped += dropped
		sort.Strings(kept)
		res.Domains[cat.Name] = kept
		res.Manifest.DomainCounts[cat.Name] = len(kept)
		total += len(kept) + len(res.Subnets[cat.Name])
	}

	if total == 0 {
		return nil, fmt.Errorf("build produced zero entries — all sources failed?")
	}
	return res, nil
}

func addSubnetCounts(dst *lists.SubnetCounts, c lists.SubnetCounts) {
	dst.HostRoutesDropped += c.HostRoutesDropped
	dst.TooBroadDropped += c.TooBroadDropped
	dst.CDNCarved += c.CDNCarved
	dst.ChildrenCollapsed += c.ChildrenCollapsed
	dst.Kept += c.Kept
}

func dropV6(in []netip.Prefix) []netip.Prefix {
	out := in[:0:0]
	for _, p := range in {
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}
