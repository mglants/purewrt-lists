# nftset-builder

Compiles **per-category native blocklists** for purewrt's
`parse_mode: native_only` rule providers. It splits Russia-blocked lists into
**media / ai / common** categories, where `common` is kept free of anything
that belongs to `media` or `ai`, and the static subnets contain **only
fully-blocked networks** (CDN ranges and pre-resolved host IPs removed).

It's a build-time tool: run it centrally (CI / a dev box), publish the
artifacts, and have routers fetch them.

## How it works

Each category in the config declares any mix of three inputs:

```yaml
categories:
  ai:
    geosite: [CATEGORY-AI-!CN]          # geosite.dat category names
  media:
    geosite: [youtube, netflix]
  common:
    domains: [https://…/domains.lst]    # domain-list sources
    subnets: [https://…/subnet.lst]     # CIDR-list sources
```

- **geosite / domains** become dnsmasq `nftset=` directives; dnsmasq resolves
  them into the category's sets at query time. Categories are declared in
  priority order: a later category loses any domain equal to or **under** an
  earlier category's domain — required because dnsmasq nftset uses
  longest-match, so a leftover `kids.youtube.com` in common would otherwise
  override media's `youtube.com`.
- Within each set, a domain whose parent is already present is dropped
  (lossless — `nftset=/parent/…` is a suffix match).
- **subnets** are the category's "fully blocked" lists, filtered: `/32` &
  `/128` host routes dropped, and **CDN ranges CIDR-subtracted** — a blocked
  `/16` that contains a CDN `/24` keeps everything except that `/24` (it is
  *not* dropped wholesale); a subnet fully inside CDN space is removed. CDN
  ranges come from [PentiumB/CDN-RuleSet](https://github.com/PentiumB/CDN-RuleSet)
  `merged.sum` (Cloudflare, Amazon, Fastly, Akamai, CDN77/DataCamp, Oracle).
  CDN-hosted blocked domains are still reached via the domain→nftset DNS path.

## Output bundle

| file | purpose |
|------|---------|
| `<category>.native` | the category's data in the marker-split bare format (below) |
| `catalog.json` | index of categories (`name`, `file`, `suggested_section`, counts) for the purewrt wizard's list picker |
| `manifest.json` | counts + sources + every reduction (auditable) |

### `.native` format (marker-split, bare)

```
# purewrt-native v1   <category>   build=<unix>
example.com
ad.example.net
@cidr
1.2.3.0/24
2001:db8::/32
```

Lines before `@cidr` are bare domains (normalized, deduped, subdomain-collapsed);
lines after are bare CIDRs (v4+v6, host-routes dropped, CDN-carved, supernet-collapsed).
No table/set names — the file is neutral, so the consumer targets whatever set it
likes with a single zero-parse line scan. The `@cidr` marker is omitted when a
category has no subnets.

## Build

```sh
task test          # go test ./... && go vet ./...
task lists:build   # → dist/  (uses examples/blocklist.yaml)
# or:
go run . --config examples/blocklist.yaml --out dist [--build-stamp <unix>]
```

Sources may be `http(s)://`, `file://`, or a local path. See
`examples/blocklist.yaml` for the full config (table name, shared geosite.dat
URL, IP filter, per-category inputs).

## Router side (purewrt)

purewrt imports a `.native` list with `parse_mode: native_import` — a zero-parse
path that wraps the bare domains into its own dnsmasq `nftset=` directives and the
CIDRs into nft set elements for the chosen section, with no validation/dedup (the
builder already did all of that). The wizard's "Default lists" source reads
`catalog.json` and lets the user map each list to a section in one click; or by hand:

```uci
config rule_provider 'blocked_common'
    option enabled '1'
    option parse_mode 'native_import'
    option url 'https://github.com/<you>/nftset-builder/releases/latest/download/common.native'
    option section '<your section>'
    option interval '86400'
```

The lists only provide the data; the routing/mark/reject policy is yours. A
`build-lists` GitHub Actions workflow rebuilds and publishes the lists +
`catalog.json` as release assets daily.
