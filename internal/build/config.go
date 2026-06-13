package build

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config is the build.yaml schema.
type Config struct {
	Table      string     `yaml:"table"` // nft family + table, e.g. "inet blocklist"
	IPv6       bool       `yaml:"ipv6"`  // emit v6 sets/elements
	Geosite    Geosite    `yaml:"geosite"`
	IPF        IPFilter   `yaml:"ip_filter"`
	Categories Categories `yaml:"categories"`
}

type Geosite struct {
	URL string `yaml:"url"` // shared geosite.dat for all category geosite entries
}

// Category is one named nft set; each input kind is optional.
type Category struct {
	Name    string   `yaml:"-"`
	Subnets []string `yaml:"subnets"` // CIDR-list sources → static elements
	Domains []string `yaml:"domains"` // domain-list sources → dnsmasq directives
	Geosite []string `yaml:"geosite"` // geosite.dat category names
}

// Categories preserves YAML declaration order: earlier categories win domain
// overlaps and define the emit order.
type Categories []Category

func (cs *Categories) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("categories must be a mapping of name → {subnets, domains, geosite}")
	}
	for i := 0; i < len(node.Content); i += 2 {
		var c Category
		if err := node.Content[i+1].Decode(&c); err != nil {
			return fmt.Errorf("category %s: %w", node.Content[i].Value, err)
		}
		c.Name = node.Content[i].Value
		*cs = append(*cs, c)
	}
	return nil
}

type IPFilter struct {
	DropHostRoutes bool     `yaml:"drop_host_routes"`
	MinPrefixV4    int      `yaml:"min_prefix_v4"`
	MinPrefixV6    int      `yaml:"min_prefix_v6"`
	CDNExclude     []string `yaml:"cdn_exclude"` // plain-CIDR sources
}

// Family + table name split out of Config.Table ("inet blocklist").
func (c Config) familyTable() (family, table string, err error) {
	var f, t string
	if _, e := fmt.Sscan(c.Table, &f, &t); e != nil || f == "" || t == "" {
		return "", "", fmt.Errorf("table must be \"<family> <name>\", e.g. \"inet blocklist\"; got %q", c.Table)
	}
	return f, t, nil
}

// category names become nft set names (with a 4/6 suffix appended).
var validCategoryName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Table == "" {
		c.Table = "inet blocklist"
	}
	if _, _, err := c.familyTable(); err != nil {
		return Config{}, err
	}
	if len(c.Categories) == 0 {
		return Config{}, fmt.Errorf("config has no categories")
	}
	seen := map[string]bool{}
	for _, cat := range c.Categories {
		if !validCategoryName.MatchString(cat.Name) {
			return Config{}, fmt.Errorf("category name %q is not a valid nft set name", cat.Name)
		}
		if seen[cat.Name] {
			return Config{}, fmt.Errorf("duplicate category %q", cat.Name)
		}
		seen[cat.Name] = true
		if len(cat.Geosite) > 0 && c.Geosite.URL == "" {
			return Config{}, fmt.Errorf("category %q uses geosite entries but geosite.url is not set", cat.Name)
		}
	}
	return c, nil
}
