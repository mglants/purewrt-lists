// Command nftset-builder compiles per-category native blocklists
// (<category>.native: nftset= directives + an elements block) for purewrt
// rule providers, from geosite categories + Russia-blocked domain/subnet
// lists, carving out CDN ranges so the subnets hold only fully-blocked
// networks. See README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/purewrt/nftset-builder/internal/build"
)

func main() {
	cfgPath := flag.String("config", "blocklist.yaml", "path to the build config")
	out := flag.String("out", "dist", "output directory for the bundle")
	stamp := flag.Int64("build-stamp", 0, "reproducible build timestamp (unix); 0 = now")
	flag.Parse()

	cfg, err := build.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	ts := *stamp
	if ts == 0 {
		ts = time.Now().Unix()
	}
	res, err := build.Run(cfg, ts)
	if err != nil {
		fatal(err)
	}
	if err := res.Emit(*out); err != nil {
		fatal(err)
	}
	stratWarns, err := build.EmitStrategies(cfg.Strategies, *out)
	if err != nil {
		fatal(err)
	}
	if n := len(cfg.Strategies.Candidates); n > 0 {
		fmt.Printf("emitted %d zapret strategy candidate(s) → %s/%s\n", n, *out, "zapret_candidates.json")
	}
	m := res.Manifest
	parts := make([]string, 0, len(res.Sections))
	for _, s := range res.Sections {
		p := fmt.Sprintf("%s=%d", s, m.DomainCounts[s])
		if n := m.SubnetCounts[s]; n > 0 {
			p += fmt.Sprintf("+%dnet", n)
		}
		parts = append(parts, p)
	}
	fmt.Printf("built %s: %s (host-routes dropped=%d, CDN carved=%d, subdomains collapsed=%d, children collapsed=%d) → %s\n",
		cfg.Table, strings.Join(parts, " "), m.SubnetFilter.HostRoutesDropped, m.SubnetFilter.CDNCarved,
		m.SubdomainsDropped, m.SubnetFilter.ChildrenCollapsed, *out)
	for _, w := range append(append([]string{}, m.Warnings...), stratWarns...) {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
