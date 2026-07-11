package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEmitStrategies(t *testing.T) {
	dir := t.TempDir()
	sc := StrategyConfig{Candidates: []Strategy{
		{Name: "youtube_tcp", ISP: "common", Protocols: []string{"tcp"}, TCPPorts: "443",
			Params: "--filter-tcp=443 --payload=tls_client_hello --lua-desync=multisplit:pos=midsld"},
		{Name: "yt_seqovl", ISP: "common", Protocols: []string{"tcp"}, TCPPorts: "443",
			Params: "--filter-tcp=443 --lua-desync=multisplit:seqovl=679:seqovl_pattern=tls_google",
			Blobs:  []Blob{{Name: "tls_google", File: "tls_clienthello_www_google_com.bin"}}}, // no source → not bundled
	}}
	warns, err := EmitStrategies(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	data, err := os.ReadFile(filepath.Join(dir, "zapret_candidates.json"))
	if err != nil {
		t.Fatalf("candidates not emitted: %v", err)
	}
	var l candidateList
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("emitted json invalid: %v", err)
	}
	if len(l.Candidates) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(l.Candidates))
	}
	// The sourceless blob is still declared (router resolves it locally), no sha256.
	if len(l.Candidates[1].Blobs) != 1 || l.Candidates[1].Blobs[0].File != "tls_clienthello_www_google_com.bin" {
		t.Fatalf("blob ref not preserved: %+v", l.Candidates[1].Blobs)
	}
	if l.Candidates[1].Blobs[0].SHA256 != "" {
		t.Fatal("sourceless blob should have no sha256")
	}
}

func TestEmitStrategiesLocalBlob(t *testing.T) {
	dir := t.TempDir()
	blobsSrc := t.TempDir()
	payload := []byte("\x01\x02\x03fake-quic")
	if err := os.WriteFile(filepath.Join(blobsSrc, "quic_custom.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sc := StrategyConfig{
		BlobsDir: blobsSrc,
		Candidates: []Strategy{{
			Name: "games_udp", ISP: "common", Protocols: []string{"udp"}, UDPPorts: "443",
			Params: "--filter-udp=443 --lua-desync=fake:blob=quic_custom",
			Blobs:  []Blob{{Name: "quic_custom", File: "quic_custom.bin"}},
		}},
	}
	warns, err := EmitStrategies(sc, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	// The local .bin is bundled into dist/blobs/ verbatim.
	got, err := os.ReadFile(filepath.Join(dir, "blobs", "quic_custom.bin"))
	if err != nil {
		t.Fatalf("local blob not bundled: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("bundled blob mismatch: %q", got)
	}
	// Its sha256 is published so the router can verify the fetched copy.
	data, err := os.ReadFile(filepath.Join(dir, "zapret_candidates.json"))
	if err != nil {
		t.Fatal(err)
	}
	var l candidateList
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatal(err)
	}
	if l.Candidates[0].Blobs[0].SHA256 != sha256hex(payload) {
		t.Fatalf("want sha256 %s, got %q", sha256hex(payload), l.Candidates[0].Blobs[0].SHA256)
	}
}

func TestEmitStrategiesRejectsDup(t *testing.T) {
	_, err := EmitStrategies(StrategyConfig{Candidates: []Strategy{
		{Name: "x", Params: "--lua-desync=multisplit:pos=2"},
		{Name: "x", Params: "--lua-desync=multisplit:pos=1"},
	}}, t.TempDir())
	if err == nil {
		t.Fatal("expected duplicate-name error")
	}
}
