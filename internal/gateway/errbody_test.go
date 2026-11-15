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

// keep is KeepErrBody from a vendor body, as the paths do it.
func keep(t *testing.T, status int, body string) ErrBodyRecord {
	t.Helper()
	rec, ok := ErrBodyFrom([]byte(body))
	if !ok {
		t.Fatalf("nothing kept from %q", body)
	}
	rec.Provider = "codex"
	rec.Model = "gpt-6.1-sol"
	rec.RouteID = "1794439898674"
	rec.CallerKey = "mini-codex"
	rec.Status = status
	rec.ContentType = "application/json"
	if p := KeepErrBody(rec); p == "" {
		t.Fatal("no path written")
	}
	recs := errBodyLines(t)
	return recs[len(recs)-1]
}

// The vendor's diagnostic fields survive, so "Codex: Bad Request" can be
// taken back to the vendor.
func TestErrBodyKeepsDiagnostics(t *testing.T) {
	errBodyTestDir(t)

	got := keep(t, 400, `{"error":{"message":"Unsupported parameter: 'reasoning.effort'","type":"invalid_request_error","code":"unsupported_parameter","param":"reasoning.effort"}}`)
	if got.Status != 400 || got.Provider != "codex" || got.RouteID != "1794439898674" {
		t.Errorf("identity lost: %+v", got)
	}
	if got.CallerKey != "mini-codex" {
		t.Errorf("callerKeyName = %q", got.CallerKey)
	}
	if got.ErrCode != "unsupported_parameter" || got.ErrParam != "reasoning.effort" {
		t.Errorf("code/param lost: %+v", got)
	}
	if !strings.Contains(got.Message, "Unsupported parameter") {
		t.Errorf("message lost: %q", got.Message)
	}
	if got.BodyShape != "json" || got.BodyLen == 0 {
		t.Errorf("shape/len lost: %+v", got)
	}
}

// A credential a vendor echoes back — in a field named for one, or as an
// opaque value with no key shape — never reaches the file (review 1).
func TestErrBodyNoCredentialEcho(t *testing.T) {
	errBodyTestDir(t)

	const secret = "opaque-session-7D4A92C185EF"
	got := keep(t, 401, `{"error":{"message":"unauthorized","headers":{"Authorization":"Bearer `+secret+`","Cookie":"session=`+secret+`"}}}`)
	if strings.Contains(got.Message, secret) {
		t.Fatalf("the credential is in the message: %q", got.Message)
	}
	b, _ := os.ReadFile(ErrBodyPath())
	if strings.Contains(string(b), secret) {
		t.Fatalf("the credential is in the file: %s", b)
	}
}

// The caller's own content, echoed back in a vendor's invalid-value error,
// is not archived (review 2): only the diagnostic fields are, and the
// message the caller sent is never among them.
func TestErrBodyNoCustomerEcho(t *testing.T) {
	errBodyTestDir(t)

	const customer = "客户星河合同底价为人民币七十三万元"
	got := keep(t, 400, `{"error":{"message":"Invalid value: `+customer+`","param":"messages[0].content","code":"invalid_value"}}`)
	if got.ErrParam != "messages[0].content" {
		t.Errorf("the parameter name is the diagnostic and should stay: %q", got.ErrParam)
	}
	if got.ErrCode != "invalid_value" {
		t.Errorf("code lost: %q", got.ErrCode)
	}
	// the message is the vendor's sentence around the echo: what the caller
	// sent must not appear. A vendor that puts the whole input in message
	// leaves only what it wrapped it in.
	b, _ := os.ReadFile(ErrBodyPath())
	if strings.Contains(string(b), customer) {
		t.Fatalf("the caller's content is in the file: %s", b)
	}
}

// A body that isn't JSON is named by shape, never archived: it can be the
// caller's own content echoed back.
func TestErrBodyTextBodyNotArchived(t *testing.T) {
	errBodyTestDir(t)

	const page = "<html>Request has been blocked. incident=review-123. 客户星河</html>"
	got := keep(t, 403, page)
	if got.BodyShape != "text" {
		t.Errorf("shape = %q, want text", got.BodyShape)
	}
	if got.Message != "" {
		t.Errorf("a text body's words were kept: %q", got.Message)
	}
	b, _ := os.ReadFile(ErrBodyPath())
	if strings.Contains(string(b), "review-123") || strings.Contains(string(b), "客户星河") {
		t.Fatalf("the text body is in the file: %s", b)
	}
}

// A firewall's 403 is a refusal like any other and is kept (review 4): naming
// it in plain words for the agent doesn't archive what the vendor sent.
func TestErrBodyFirewallRefusalKept(t *testing.T) {
	errBodyTestDir(t)

	body := `<html>Request has been blocked. incident=review-123</html>`
	if p := KeepErrBody(mustRec(t, 403, body)); p == "" {
		t.Fatal("a firewall refusal was dropped")
	}
	recs := errBodyLines(t)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].Status != 403 || recs[0].BodyShape != "text" {
		t.Errorf("firewall refusal not recorded: %+v", recs[0])
	}
}

func mustRec(t *testing.T, status int, body string) ErrBodyRecord {
	t.Helper()
	rec, _ := ErrBodyFrom([]byte(body))
	rec.Provider = "codex"
	rec.Status = status
	return rec
}

// A success is not kept: only refusals are.
func TestErrBodySkipsSuccess(t *testing.T) {
	errBodyTestDir(t)

	if p := KeepErrBody(ErrBodyRecord{Provider: "codex", Status: 200}); p != "" {
		t.Fatalf("a 200 was kept at %s", p)
	}
	if _, err := os.Stat(ErrBodyPath()); !os.IsNotExist(err) {
		t.Fatalf("a file was made for a success: %v", err)
	}
}

// A very long vendor message is cut, so one refusal can't fill the disk.
func TestErrBodyCutsLongMessage(t *testing.T) {
	errBodyTestDir(t)

	long := strings.Repeat("x", errBodyMost*3)
	got := keep(t, 400, `{"error":{"message":"`+long+`"}}`)
	if len(got.Message) > errBodyMost {
		t.Fatalf("kept %d bytes, want at most %d", len(got.Message), errBodyMost)
	}
}

// At the limit the log becomes the old one, over the one before: two files,
// never more.
func TestErrBodyRotates(t *testing.T) {
	dir := errBodyTestDir(t)

	big := strings.Repeat("y", errBodyMost)
	for i := 0; i < (errBodyLimit/errBodyMost)+2; i++ {
		rec, _ := ErrBodyFrom([]byte(`{"error":{"message":"` + big + `"}}`))
		rec.Provider = "codex"
		rec.Status = 400
		KeepErrBody(rec)
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
