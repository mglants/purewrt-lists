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
		{Name: "youtube_tcp", Group: "recommended", Protocols: []string{"tcp"}, TCPPorts: "443",
			Params: "--filter-tcp=443 --payload=tls_client_hello --lua-desync=multisplit:pos=midsld"},
		{Name: "yt_seqovl", Group: "recommended", Protocols: []string{"tcp"}, TCPPorts: "443",
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

func TestEmitStrategiesRejectsDup(t *testing.T) {
	_, err := EmitStrategies(StrategyConfig{Candidates: []Strategy{
		{Name: "x", Params: "--lua-desync=multisplit:pos=2"},
		{Name: "x", Params: "--lua-desync=multisplit:pos=1"},
	}}, t.TempDir())
	if err == nil {
		t.Fatal("expected duplicate-name error")
	}
}
