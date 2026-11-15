package gateway

// Upstream 4xx/5xx refusal evidence.
//
// Why this exists: a vendor's refusal reaches the client as a short line —
// "Codex: Bad Request" — because APIError keeps only the human message out
// of the body. When the refusal is not one magpie itself can explain (not
// an overflow, not a quota, not a safety refusal), the original body is
// gone by the time anyone asks what the vendor actually said. On 2026-11-13
// three Codex 400s could not be diagnosed for exactly this reason (#yueran,
// route 1794439898674/…738/…9161), and a pi/3ai/group/auto 400 the next day
// had the same shape.
//
// What is written, one JSON object per line, for a provider attempt that
// failed with 4xx or 5xx and whose refusal magpie could not name:
//
//	time, provider, model, effort, route id, callerKeyName, callerKeyId,
//	status, content-type, upstream request id (when the vendor sent one),
//	the body's first 4 KiB (scrubbed), the body's length, and why it was
//	kept (refused/overflow/other).
//
// What is never written: the request body, the response's success content,
// any key or token. The body goes through redact.Scrub, so anything that
// looks like a secret goes for good, and it is cut to 4 KiB before that.
// The client's reply is untouched: this only records.
//
// The file is upstream-errors.log beside routing/, rotated at 8 MiB to
// upstream-errors.old.log, two files at most — the same shape and limits as
// the app's own log.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/redact"
)

const (
	// ErrBodyLog is the evidence log's file name, beside routing/.
	ErrBodyLog = "upstream-errors.log"
	// ErrBodyOld is the log before the last rotation.
	ErrBodyOld = "upstream-errors.old.log"
	// errBodyLimit is the size at which the log is rotated.
	errBodyLimit = 8 << 20
	// errBodyMost is how much of a vendor's body is kept.
	errBodyMost = 4 << 10
)

// ErrBodyPath is where the evidence log lives.
func ErrBodyPath() string {
	return filepath.Join(appdir.Config(), ErrBodyLog)
}

// errBodyMu guards the file: one write at a time, so a rotation happens
// between lines and never inside one.
var errBodyMu sync.Mutex

// ErrBodyRecord is one kept refusal.
type ErrBodyRecord struct {
	Time        string `json:"t"`
	Provider    string `json:"provider"`
	Model       string `json:"model,omitempty"`
	Effort      string `json:"effort,omitempty"`
	RouteID     string `json:"routeId,omitempty"`
	CallerKey   string `json:"callerKeyName,omitempty"`
	CallerKeyID string `json:"callerKeyId,omitempty"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
	UpstreamID  string `json:"upstreamRequestId,omitempty"`
	Why         string `json:"why,omitempty"`
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
// refusal can be quoted back to the vendor. Name is whatever the vendor
// uses: x-request-id, openai-request-id, cf-ray, x-amzn-requestid…
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
