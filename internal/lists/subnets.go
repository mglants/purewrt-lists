package lists

import (
	"math/big"
	"net/netip"
	"slices"
	"sort"
)

// SubnetOpts controls FilterSubnets.
type SubnetOpts struct {
	DropHostRoutes bool // drop /32 and /128
	MinPrefixV4    int  // drop v4 prefixes shorter (broader) than this; 0 = no limit
	MinPrefixV6    int
}

// SubnetCounts reports what FilterSubnets removed, for the manifest.
type SubnetCounts struct {
	HostRoutesDropped int `json:"host_routes_dropped"`
	TooBroadDropped   int `json:"too_broad_dropped"`
	CDNCarved         int `json:"cdn_ranges_carved"`   // candidate prefixes that lost space to CDN
	ChildrenCollapsed int `json:"children_collapsed"`
	Kept              int `json:"kept"`
}

// FilterSubnets produces the final blocked-subnet set: it drops host routes
// and over-broad prefixes, CIDR-subtracts the CDN ranges (carving CDN space
// out of larger blocked subnets rather than dropping them whole), then
// collapses any prefix contained in a larger surviving one. v4 and v6 are
// processed independently. Output is sorted and deterministic.
func FilterSubnets(candidates, cdn []netip.Prefix, opts SubnetOpts) ([]netip.Prefix, SubnetCounts) {
	var counts SubnetCounts

	keep := func(p netip.Prefix, minPrefix int) bool {
		if opts.DropHostRoutes && p.Bits() == p.Addr().BitLen() {
			counts.HostRoutesDropped++
			return false
		}
		if minPrefix > 0 && p.Bits() < minPrefix {
			counts.TooBroadDropped++
			return false
		}
		return true
	}

	splitFamily := func(ps []netip.Prefix, want4 bool) []netip.Prefix {
		var out []netip.Prefix
		for _, p := range ps {
			if p.Addr().Is4() == want4 {
				out = append(out, p.Masked())
			}
		}
		return out
	}

	process := func(cands, cdnFam []netip.Prefix, minPrefix int) []netip.Prefix {
		// pre-filter host/broad
		var filtered []netip.Prefix
		for _, p := range cands {
			if keep(p, minPrefix) {
				filtered = append(filtered, p)
			}
		}
		cuts := mergeIntervals(prefixesToIntervals(cdnFam))
		var survivors []netip.Prefix
		for _, p := range filtered {
			lo, hi := prefixRange(p)
			rem := subtractInterval(lo, hi, cuts)
			if len(rem) == 0 {
				counts.CDNCarved++ // fully removed by CDN
				continue
			}
			if len(rem) != 1 || rem[0].lo.Cmp(lo) != 0 || rem[0].hi.Cmp(hi) != 0 {
				counts.CDNCarved++ // partially carved
			}
			is4 := p.Addr().Is4()
			for _, iv := range rem {
				survivors = append(survivors, rangeToCIDRs(iv.lo, iv.hi, is4)...)
			}
		}
		collapsed, dropped := collapseSupernets(survivors)
		counts.ChildrenCollapsed += dropped
		return collapsed
	}

	out := process(splitFamily(candidates, true), splitFamily(cdn, true), opts.MinPrefixV4)
	out = append(out, process(splitFamily(candidates, false), splitFamily(cdn, false), opts.MinPrefixV6)...)
	slices.SortFunc(out, comparePrefix)
	counts.Kept = len(out)
	return out, counts
}

// --- interval math over big.Int (uniform for v4/v6) ---

type interval struct{ lo, hi *big.Int }

func addrToInt(a netip.Addr) *big.Int {
	b := a.As16()
	if a.Is4() {
		v4 := a.As4()
		return new(big.Int).SetBytes(v4[:])
	}
	return new(big.Int).SetBytes(b[:])
}

func intToAddr(n *big.Int, is4 bool) netip.Addr {
	if is4 {
		var b [4]byte
		n.FillBytes(b[:])
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	n.FillBytes(b[:])
	return netip.AddrFrom16(b)
}

func prefixRange(p netip.Prefix) (lo, hi *big.Int) {
	a := p.Masked().Addr()
	lo = addrToInt(a)
	host := a.BitLen() - p.Bits()
	size := new(big.Int).Lsh(big.NewInt(1), uint(host)) // 2^host
	hi = new(big.Int).Add(lo, size)
	hi.Sub(hi, big.NewInt(1))
	return lo, hi
}

func prefixesToIntervals(ps []netip.Prefix) []interval {
	out := make([]interval, 0, len(ps))
	for _, p := range ps {
		lo, hi := prefixRange(p)
		out = append(out, interval{lo, hi})
	}
	return out
}

// mergeIntervals sorts and unions overlapping/adjacent intervals.
func mergeIntervals(in []interval) []interval {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].lo.Cmp(in[j].lo) < 0 })
	out := []interval{{new(big.Int).Set(in[0].lo), new(big.Int).Set(in[0].hi)}}
	for _, iv := range in[1:] {
		last := out[len(out)-1]
		// adjacent if iv.lo <= last.hi+1
		hiPlus1 := new(big.Int).Add(last.hi, big.NewInt(1))
		if iv.lo.Cmp(hiPlus1) <= 0 {
			if iv.hi.Cmp(last.hi) > 0 {
				last.hi.Set(iv.hi)
			}
			continue
		}
		out = append(out, interval{new(big.Int).Set(iv.lo), new(big.Int).Set(iv.hi)})
	}
	return out
}

// subtractInterval removes the merged cut intervals from [lo,hi], returning
// the remaining sub-intervals (possibly empty).
func subtractInterval(lo, hi *big.Int, cuts []interval) []interval {
	var out []interval
	cur := new(big.Int).Set(lo)
	// binary-search to the first cut that could overlap (cut.hi >= lo)
	start := sort.Search(len(cuts), func(i int) bool { return cuts[i].hi.Cmp(lo) >= 0 })
	for i := start; i < len(cuts) && cuts[i].lo.Cmp(hi) <= 0; i++ {
		c := cuts[i]
		if c.lo.Cmp(cur) > 0 {
			out = append(out, interval{new(big.Int).Set(cur), new(big.Int).Sub(c.lo, big.NewInt(1))})
		}
		next := new(big.Int).Add(c.hi, big.NewInt(1))
		if next.Cmp(cur) > 0 {
			cur.Set(next)
		}
		if cur.Cmp(hi) > 0 {
			return out
		}
	}
	if cur.Cmp(hi) <= 0 {
		out = append(out, interval{new(big.Int).Set(cur), new(big.Int).Set(hi)})
	}
	return out
}

// rangeToCIDRs decomposes an inclusive [lo,hi] range into the minimal set of
// aligned CIDR prefixes (largest-aligned-block algorithm).
func rangeToCIDRs(lo, hi *big.Int, is4 bool) []netip.Prefix {
	bits := 128
	if is4 {
		bits = 32
	}
	var out []netip.Prefix
	cur := new(big.Int).Set(lo)
	one := big.NewInt(1)
	for cur.Cmp(hi) <= 0 {
		// largest block size aligned at cur: min(trailing zeros, fit in range)
		maxByAlign := bits
		if cur.Sign() != 0 {
			maxByAlign = trailingZeros(cur)
		}
		// fit: 2^size-1 <= hi-cur  →  size <= bitlen(hi-cur+1)-1
		span := new(big.Int).Sub(hi, cur)
		span.Add(span, one)
		maxByFit := span.BitLen() - 1
		size := maxByAlign
		if maxByFit < size {
			size = maxByFit
		}
		out = append(out, netip.PrefixFrom(intToAddr(cur, is4), bits-size))
		step := new(big.Int).Lsh(one, uint(size))
		cur = new(big.Int).Add(cur, step)
	}
	return out
}

func trailingZeros(n *big.Int) int {
	if n.Sign() == 0 {
		return 0
	}
	tz := 0
	for n.Bit(tz) == 0 {
		tz++
	}
	return tz
}

// collapseSupernets drops any prefix fully contained in a larger one.
func collapseSupernets(ps []netip.Prefix) (kept []netip.Prefix, dropped int) {
	// sort by Bits ascending (largest networks first); a prefix is dropped if
	// an earlier, broader prefix contains it.
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return a.Bits() - b.Bits()
		}
		return comparePrefix(a, b)
	})
	for _, p := range ps {
		covered := false
		for _, k := range kept {
			if k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if covered {
			dropped++
			continue
		}
		kept = append(kept, p)
	}
	return kept, dropped
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}
