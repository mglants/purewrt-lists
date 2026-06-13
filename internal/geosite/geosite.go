// Package geosite is a minimal, dependency-free reader for the v2ray/Xray
// geosite.dat format. It extracts the domains of a named category for use
// in dnsmasq nftset directives.
//
// geosite.dat is a protobuf-serialized GeoSiteList:
//
//	message GeoSiteList { repeated GeoSite entry = 1; }
//	message GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//	message Domain {
//	  enum Type { Plain = 0; Regex = 1; Domain = 2; Full = 3; }
//	  Type type = 1; string value = 2; repeated Attribute attribute = 3;
//	}
//
// We only need the domain strings of one category, so the parser walks the
// wire format directly with encoding/binary varints rather than pulling in
// google.golang.org/protobuf. Type mapping for the dnsmasq nftset path
// (which is itself a suffix match):
//
//	Full   (3) → exact domain   → emitted
//	Domain (2) → domain suffix   → emitted
//	Plain  (0) → keyword         → skipped (dnsmasq can't keyword-match)
//	Regex  (1) → regex           → skipped
package geosite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// protobuf wire types
const (
	wireVarint = 0
	wireLen    = 2
)

// DomainsForCategory returns the emittable domains (Full + Domain types)
// for the named category, plus a count of skipped keyword/regex entries.
// The category is matched against GeoSite.country_code case-insensitively.
// Returns an error only on a malformed file; an unknown category yields an
// empty result with no error so callers can warn-and-continue.
func DomainsForCategory(data []byte, category string) (domains []string, skipped int, err error) {
	want := strings.ToUpper(strings.TrimSpace(category))
	r := &reader{buf: data}
	for r.more() {
		field, wt, e := r.tag()
		if e != nil {
			return nil, 0, e
		}
		if field != 1 || wt != wireLen { // GeoSiteList.entry
			if e := r.skip(wt); e != nil {
				return nil, 0, e
			}
			continue
		}
		entry, e := r.bytes()
		if e != nil {
			return nil, 0, e
		}
		code, doms, skip, e := parseGeoSite(entry)
		if e != nil {
			return nil, 0, e
		}
		if strings.ToUpper(code) == want {
			domains = append(domains, doms...)
			skipped += skip
		}
	}
	return domains, skipped, nil
}

// Categories lists every country_code present in the file — handy for a
// --list-categories diagnostic.
func Categories(data []byte) ([]string, error) {
	var out []string
	r := &reader{buf: data}
	for r.more() {
		field, wt, err := r.tag()
		if err != nil {
			return nil, err
		}
		if field != 1 || wt != wireLen {
			if err := r.skip(wt); err != nil {
				return nil, err
			}
			continue
		}
		entry, err := r.bytes()
		if err != nil {
			return nil, err
		}
		code, _, _, err := parseGeoSite(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, code)
	}
	return out, nil
}

func parseGeoSite(b []byte) (code string, domains []string, skipped int, err error) {
	r := &reader{buf: b}
	for r.more() {
		field, wt, e := r.tag()
		if e != nil {
			return "", nil, 0, e
		}
		switch {
		case field == 1 && wt == wireLen: // country_code
			s, e := r.bytes()
			if e != nil {
				return "", nil, 0, e
			}
			code = string(s)
		case field == 2 && wt == wireLen: // domain
			d, e := r.bytes()
			if e != nil {
				return "", nil, 0, e
			}
			val, emit, e := parseDomain(d)
			if e != nil {
				return "", nil, 0, e
			}
			if emit {
				domains = append(domains, val)
			} else {
				skipped++
			}
		default:
			if e := r.skip(wt); e != nil {
				return "", nil, 0, e
			}
		}
	}
	return code, domains, skipped, nil
}

// parseDomain returns the normalized domain value and whether it should be
// emitted (Full/Domain) vs skipped (Plain keyword / Regex).
func parseDomain(b []byte) (value string, emit bool, err error) {
	r := &reader{buf: b}
	var dtype uint64
	var val string
	for r.more() {
		field, wt, e := r.tag()
		if e != nil {
			return "", false, e
		}
		switch {
		case field == 1 && wt == wireVarint: // type
			v, e := r.varint()
			if e != nil {
				return "", false, e
			}
			dtype = v
		case field == 2 && wt == wireLen: // value
			s, e := r.bytes()
			if e != nil {
				return "", false, e
			}
			val = string(s)
		default:
			if e := r.skip(wt); e != nil {
				return "", false, e
			}
		}
	}
	switch dtype {
	case 2, 3: // Domain (suffix), Full (exact)
		v := strings.Trim(strings.ToLower(strings.TrimSpace(val)), ".")
		if v == "" {
			return "", false, nil
		}
		return v, true, nil
	default: // Plain (0) keyword, Regex (1)
		return "", false, nil
	}
}

// reader is a tiny protobuf wire walker over a byte slice.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) more() bool { return r.pos < len(r.buf) }

func (r *reader) tag() (field int, wireType int, err error) {
	v, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	return int(v >> 3), int(v & 0x7), nil
}

func (r *reader) varint() (uint64, error) {
	v, n := binary.Uvarint(r.buf[r.pos:])
	if n <= 0 {
		return 0, errors.New("geosite: bad varint")
	}
	r.pos += n
	return v, nil
}

func (r *reader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.buf)-r.pos) {
		return nil, fmt.Errorf("geosite: length %d exceeds remaining %d", n, len(r.buf)-r.pos)
	}
	b := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return b, nil
}

func (r *reader) skip(wireType int) error {
	switch wireType {
	case wireVarint:
		_, err := r.varint()
		return err
	case wireLen:
		_, err := r.bytes()
		return err
	case 1: // 64-bit
		if len(r.buf)-r.pos < 8 {
			return errors.New("geosite: truncated 64-bit field")
		}
		r.pos += 8
		return nil
	case 5: // 32-bit
		if len(r.buf)-r.pos < 4 {
			return errors.New("geosite: truncated 32-bit field")
		}
		r.pos += 4
		return nil
	default:
		return fmt.Errorf("geosite: unsupported wire type %d", wireType)
	}
}
