package gateway

// Vendor refusal evidence.
//
// Why this exists: a vendor's 4xx reaches the agent as a short line —
// APIError keeps only the human message out of the body — so when the
// refusal is not one magpie can name itself, the original body is gone by
// the time anyone asks what the vendor actually said. On 2026-11-13 three
// Codex 400s could not be diagnosed for exactly this reason (routes
// 1794439898674 / …738 / …9161), and a pi/3ai/group/auto 400 the next day
// had the same shape.
//
// What is kept, one JSON object per line, for a vendor reply that came back
// 4xx or 5xx:
//
//	time, provider, model, route id, callerKeyName, callerKeyId, status,
//	content-type, the vendor's own request id when it sent one, the error
//	type and code the vendor gave, which parameter it named, and the
//	vendor's own message with every echo of what the caller sent taken out.
//
// What is never kept: a credential, the caller's own content, the request
// body, or a successful reply. The body is parsed as JSON and rebuilt from a
// fixed set of diagnostic fields — not copied and scrubbed — so a vendor
// that echoes the input (a parameter's invalid value, a rejected message)
// can't put the caller's words in this file. A credential in any field goes
// for good: a field named for one (Authorization, Cookie, api_key…) is
// dropped whole by redact's own rule, and every other string goes through
// redact.Scrub. A body that isn't JSON is not kept at all; its type and
// length are, which is enough to name a firewall page without archiving it.
//
// The file is upstream-errors.log in the settings folder, rotated at 8 MiB
// to upstream-errors.old.log, two files at most — the same shape and limits
// as the app's own log.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/access"
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
	// errBodyMost is the longest vendor message kept, in bytes.
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
//
// The body itself is not a field: what a vendor said is taken apart into
// these, so nothing the caller sent can reach the file by being echoed.
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
	// what the vendor said, taken apart
	ErrType   string   `json:"errType,omitempty"`
	ErrCode   string   `json:"errCode,omitempty"`
	ErrParam  string   `json:"errParam,omitempty"`
	Message   string   `json:"message,omitempty"`
	BodyLen   int      `json:"bodyLen"`
	BodyShape string   `json:"bodyShape,omitempty"` // json / text / empty
	Matched   []string `json:"matched,omitempty"`   // vendor fields the message came from
}

// KeepErrBody writes one refusal to the evidence log, and answers the path
// written to. It never fails a request: an unwritable log is a quiet no-op.
func KeepErrBody(rec ErrBodyRecord) string {
	if rec.Status < 400 {
		return ""
	}
	if rec.Time == "" {
		rec.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return ""
	}
	line = append(line, '\n')
	return appendErrBody(line)
}

// appendErrBody writes one already-built line, rotating first when the file
// would pass its limit.
func appendErrBody(line []byte) string {
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

// ErrBodyFrom reads a vendor's refusal body into the diagnostics kept, and
// says whether there is anything worth a line. A body that isn't JSON is
// named by shape alone: its words are not kept, because a plain text body
// can be the caller's own content echoed back.
func ErrBodyFrom(body []byte) (rec ErrBodyRecord, keep bool) {
	rec.BodyLen = len(body)
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		rec.BodyShape = "empty"
		return rec, true // an empty refusal is itself the finding
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		rec.BodyShape = "text"
		return rec, true
	}
	rec.BodyShape = "json"
	// the diagnostic fields a vendor uses, most specific first; the first
	// one that answers wins for each
	obj, ok := v.(map[string]any)
	if !ok {
		return rec, true
	}
	if e, ok := obj["error"].(map[string]any); ok {
		rec.Matched = append(rec.Matched, "error")
		rec.ErrType = erecStr(e["type"])
		rec.ErrCode = erecStr(e["code"])
		rec.ErrParam = erecStr(e["param"])
		rec.Message = cut(redact.Scrub(withoutEcho(erecStr(e["message"]))), errBodyMost)
		if rec.Message == "" {
			// some vendors put the words in details
			rec.Message = cut(redact.Scrub(withoutEcho(erecStr(e["detail"]))), errBodyMost)
		}
	}
	if rec.Message == "" {
		for _, k := range []string{"message", "msg", "detail", "error_description", "description"} {
			if s := erecStr(obj[k]); s != "" {
				rec.Matched = append(rec.Matched, k)
				rec.Message = cut(redact.Scrub(withoutEcho(s)), errBodyMost)
				break
			}
		}
	}
	if rec.ErrType == "" {
		rec.ErrType = erecStr(obj["type"])
	}
	if rec.ErrCode == "" {
		rec.ErrCode = erecStr(obj["code"])
	}
	return rec, true
}

// str is a JSON value as text, or "" for anything that isn't a string or a
// number: a nested object is never put into the message.
func erecStr(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// echoAfter is the punctuation a vendor puts a caller's own value behind
// when it echoes the value back: "Invalid value: <the value>",
// "Unsupported parameter: '<the value>'", "messages[0].content is not…".
var echoAfter = regexp.MustCompile(`(?is)^(.*?(?:invalid value|unsupported (?:value|parameter)|invalid (?:parameter|argument|request)|not valid|must be|is not|unexpected (?:value|token)|unknown (?:value|field)))\s*[:=]?\s*(.+)$`)

// withoutEcho drops a caller's own value a vendor echoed into its message,
// keeping the vendor's own sentence around it: the message is the diagnostic,
// the value is the caller's content and is not archived.
//
// A vendor that only says the value, with nothing around it, leaves a message
// that is the value itself; there is no way to tell it from the vendor's own
// words, so a message that is not one of the known shapes is kept as it is —
// this is a limit, not a guarantee (see the file's header).
func withoutEcho(s string) string {
	if s == "" {
		return s
	}
	if m := echoAfter.FindStringSubmatch(s); m != nil {
		if tail := strings.TrimSpace(m[2]); tail != "" {
			// the vendor's own lead-in alone: the value after it goes,
			// and what came before it stays
			return strings.TrimSpace(m[1])
		}
	}
	return s
}

// cut keeps the first n bytes of s.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
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

// keepRefusal records one vendor refusal, from every path that forwards one:
// the two protocol paths in gateway.go and the streamed translation.
func keepRefusal(ctx context.Context, p provider.Provider, model string, status int, h interface{ Get(string) string }, body []byte) {
	rec, ok := ErrBodyFrom(body)
	if !ok {
		return
	}
	who := access.Caller(ctx)
	rec.Provider = p.ID
	rec.Model = model
	rec.RouteID = routeIDOf(ctx)
	rec.CallerKey = who.KeyName
	rec.CallerKeyID = who.KeyID
	rec.Status = status
	rec.ContentType = h.Get("Content-Type")
	rec.UpstreamID = upstreamRequestID(h)
	KeepErrBody(rec)
}
