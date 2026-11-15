package gateway

// Vendor refusal evidence.
//
// Why this exists: a vendor's 4xx reaches the agent as a short line —
// APIError keeps only the human message out of the body — so when the
// refusal is not one magpie can name itself (not an overflow, not a quota,
// not a safety filter) the original body is gone by the time anyone asks
// what the vendor actually said. On 2026-11-13 three Codex 400s could not
// be diagnosed for exactly this reason (routes 1794439898674 / …738 /
// …9161), and a pi/3ai/group/auto 400 the next day had the same shape.
//
// What is kept, one JSON object per line, for a vendor reply that came back
// 4xx or 5xx:
//
//	time, provider, model, route id, callerKeyName, callerKeyId, status,
//	content-type, the vendor's own request id when it sent one, the body's
//	first 4 KiB (scrubbed), and how long the body was.
//
// What is never kept: the request body, a successful reply's content, and
// any key or token. The body goes through redact.Scrub, so anything that
// looks like a secret goes for good; it is cut to 4 KiB before that. The
// client's reply is untouched: this only records.
//
// The file is upstream-errors.log in the settings folder, rotated at 8 MiB
// to upstream-errors.old.log, two files at most — the same shape and limits
// as the app's own log.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/redact"
	"github.com/yetone/magpie/internal/settings"
)

const (
	// ErrBodyLog is the evidence log's file name.
	ErrBodyLog = "upstream-errors.log"
	// ErrBodyOld is the log before the last rotation.
	ErrBodyOld = "upstream-errors.old.log"
	// errBodyLimit is the size at which the log is rotated.
	errBodyLimit = 8 << 20
	// errBodyMost is how much of a vendor's body is kept.
	errBodyMost = 4 << 10
)

// ErrBodyPath is where the evidence log lives, beside caller-keys.json.
func ErrBodyPath() string {
	return filepath.Join(settings.Dir(), ErrBodyLog)
}

// errBodyMu guards the file: one write at a time, so a rotation happens
// between lines and never inside one.
var errBodyMu sync.Mutex

// ErrBodyRecord is one kept refusal.
type ErrBodyRecord struct {
	Time        string `json:"t"`
	Provider    string `json:"provider"`
	Model       string `json:"model,omitempty"`
	RouteID     string `json:"routeId,omitempty"`
	CallerKey   string `json:"callerKeyName,omitempty"`
	CallerKeyID string `json:"callerKeyId,omitempty"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
	UpstreamID  string `json:"upstreamRequestId,omitempty"`
	BodyLen     int    `json:"bodyLen"`
	Body        string `json:"body"`
}

// KeepErrBody writes one refusal to the evidence log, and answers the path
// written to. It never fails a request: an unwritable log is a quiet no-op.
func KeepErrBody(rec ErrBodyRecord) string {
	if rec.Status < 400 {
		return ""
	}
	body := rec.Body
	if len(body) > errBodyMost {
		body = body[:errBodyMost]
	}
	rec.Body = redact.Scrub(body)
	rec.BodyLen = len(rec.Body)
	if rec.Time == "" {
		rec.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return ""
	}
	line = append(line, '\n')

	path := ErrBodyPath()
	errBodyMu.Lock()
	defer errBodyMu.Unlock()
	// the folder may not be there yet (a fresh install, a test): make it
	// rather than lose the evidence
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return ""
	}
	if fi, err := os.Stat(path); err == nil && fi.Size()+int64(len(line)) > errBodyLimit {
		// rotate: the log becomes the old one, over the one before
		_ = os.Rename(path, filepath.Join(filepath.Dir(path), ErrBodyOld))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return ""
	}
	return path
}

// upstreamRequestID picks the vendor's own id out of a reply's headers, so a
// refusal can be quoted back to the vendor. Vendors name it differently:
// Anthropic and most others x-request-id, OpenAI openai-request-id, AWS
// x-amzn-requestid, Cloudflare cf-ray, Google x-goog-request-id.
func upstreamRequestID(h interface{ Get(string) string }) string {
	for _, name := range []string{
		"x-request-id",
		"openai-request-id",
		"request-id",
		"x-amzn-requestid",
		"cf-ray",
		"x-goog-request-id",
	} {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			return name + "=" + v
		}
	}
	return ""
}

// routeIDOf is the routing id the request in flight was given, as a string,
// so the evidence line joins the Routing view's row for it.
func routeIDOf(ctx context.Context) string {
	if f := inflightOf(ctx); f != nil {
		if rt := f.route.Load(); rt != nil && rt.ID != 0 {
			return strconv.FormatInt(rt.ID, 10)
		}
	}
	return ""
}

// namedRefusal says magpie already put this refusal in its own words, so
// keeping the body would only add noise: an overflow it recognised, a
// quota, or a vendor's safety filter.
func namedRefusal(p provider.Provider, status int, body []byte) bool {
	// a firewall's block page, put in plain words by APIError
	return provider.EdgeBlocked(body)
}
