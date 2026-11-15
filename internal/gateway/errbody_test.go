package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errBodyTestDir points the evidence log at a folder of its own, so one test
// never reads another's records.
func errBodyTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	os.Remove(ErrBodyPath())
	os.Remove(filepath.Join(dir, "magpie", ErrBodyOld))
	return dir
}

// errBodyLines reads the evidence log back as records.
func errBodyLines(t *testing.T) []ErrBodyRecord {
	t.Helper()
	b, err := os.ReadFile(ErrBodyPath())
	if err != nil {
		t.Fatalf("read evidence log: %v", err)
	}
	var out []ErrBodyRecord
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var rec ErrBodyRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line is not JSON: %v (%q)", err, line)
		}
		out = append(out, rec)
	}
	return out
}

// A vendor's refusal is kept with its status, content type, its own request
// id and the body, so "Codex: Bad Request" can be taken back to the vendor.
func TestErrBodyKeepsRefusal(t *testing.T) {
	errBodyTestDir(t)

	path := KeepErrBody(ErrBodyRecord{
		Provider:    "codex",
		Model:       "gpt-6.1-sol",
		RouteID:     "1794439898674",
		CallerKey:   "mini-codex",
		CallerKeyID: "abc123",
		Status:      400,
		ContentType: "application/json",
		UpstreamID:  "x-request-id=req_9f8e7d",
		Body:        `{"error":{"message":"Unsupported parameter: 'reasoning.effort'","type":"invalid_request_error","code":"unsupported_parameter"}}`,
	})
	if path == "" {
		t.Fatal("no path written")
	}
	recs := errBodyLines(t)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	got := recs[0]
	if got.Status != 400 {
		t.Errorf("status = %d, want 400", got.Status)
	}
	if got.Provider != "codex" || got.Model != "gpt-6.1-sol" || got.RouteID != "1794439898674" {
		t.Errorf("identity lost: %+v", got)
	}
	if got.CallerKey != "mini-codex" {
		t.Errorf("callerKeyName = %q, want mini-codex", got.CallerKey)
	}
	if got.UpstreamID != "x-request-id=req_9f8e7d" {
		t.Errorf("upstreamRequestId = %q", got.UpstreamID)
	}
	if !strings.Contains(got.Body, "unsupported_parameter") {
		t.Errorf("body lost the vendor's words: %q", got.Body)
	}
	if got.Time == "" {
		t.Error("no timestamp")
	}
}

// A success is not kept: only refusals are.
func TestErrBodySkipsSuccess(t *testing.T) {
	errBodyTestDir(t)

	if p := KeepErrBody(ErrBodyRecord{Provider: "codex", Status: 200, Body: "fine"}); p != "" {
		t.Fatalf("a 200 was kept at %s", p)
	}
	if _, err := os.Stat(ErrBodyPath()); !os.IsNotExist(err) {
		t.Fatalf("a file was made for a success: %v", err)
	}
}

// Only the first 4 KiB of the body is kept, so one huge reply can't fill the
// disk; what is kept is still a prefix of what the vendor said.
func TestErrBodyCutsLongBody(t *testing.T) {
	errBodyTestDir(t)

	long := strings.Repeat("x", errBodyMost*3)
	KeepErrBody(ErrBodyRecord{Provider: "codex", Status: 400, Body: long})
	recs := errBodyLines(t)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if len(recs[0].Body) > errBodyMost {
		t.Fatalf("kept %d bytes, want at most %d", len(recs[0].Body), errBodyMost)
	}
	if recs[0].BodyLen != len(recs[0].Body) {
		t.Errorf("bodyLen = %d, body is %d", recs[0].BodyLen, len(recs[0].Body))
	}
}

// A secret in the body never reaches the file, and the vendor's own words
// still do.
func TestErrBodyScrubsSecrets(t *testing.T) {
	errBodyTestDir(t)

	const key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	KeepErrBody(ErrBodyRecord{
		Provider: "codex",
		Status:   401,
		Body:     `{"error":{"message":"Incorrect API key provided: ` + key + `"}}`,
	})
	recs := errBodyLines(t)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if strings.Contains(recs[0].Body, key) {
		t.Fatalf("the key is in the file: %q", recs[0].Body)
	}
	if !strings.Contains(recs[0].Body, "Incorrect API key provided") {
		t.Errorf("scrubbing lost the vendor's words: %q", recs[0].Body)
	}
}

// At the limit the log becomes the old one, over the one before: two files,
// never more.
func TestErrBodyRotates(t *testing.T) {
	dir := errBodyTestDir(t)

	big := strings.Repeat("y", errBodyMost)
	for i := 0; i < (errBodyLimit/errBodyMost)+2; i++ {
		KeepErrBody(ErrBodyRecord{Provider: "codex", Status: 400, Body: big})
	}
	if _, err := os.Stat(filepath.Join(dir, "magpie", ErrBodyOld)); err != nil {
		t.Fatalf("no rotated file: %v", err)
	}
	fi, err := os.Stat(ErrBodyPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > errBodyLimit {
		t.Errorf("current log is %d bytes, over %d", fi.Size(), errBodyLimit)
	}
	if n := len(errBodyLines(t)); n == 0 {
		t.Error("no records after rotation")
	}
}

// The vendor's request id is picked from whichever header it came in.
func TestUpstreamRequestID(t *testing.T) {
	h := mapHeader{"cf-ray": "a59ba827395adf0a-SJC"}
	if got := upstreamRequestID(h); got != "cf-ray=a59ba827395adf0a-SJC" {
		t.Errorf("got %q", got)
	}
	h2 := mapHeader{"openai-request-id": "req_123", "cf-ray": "x"}
	if got := upstreamRequestID(h2); got != "openai-request-id=req_123" {
		t.Errorf("header order: got %q", got)
	}
	if got := upstreamRequestID(mapHeader{}); got != "" {
		t.Errorf("empty headers answered %q", got)
	}
}

// mapHeader is an http.Header for the test without the deps.
type mapHeader map[string]string

func (m mapHeader) Get(k string) string { return m[k] }
