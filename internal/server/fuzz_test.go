package server

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// FuzzDecodePeerRequest feeds arbitrary bodies to the strict decoder used by
// the peer endpoints. A body it accepts must survive a re-encode/decode round
// trip unchanged, so nothing is silently dropped on the way in.
func FuzzDecodePeerRequest(f *testing.F) {
	seeds := []string{
		`{"peerId":"550e8400-e29b-41d4-a716-446655440000"}`,
		`{"peerId":"550e8400-e29b-41d4-a716-446655440000","expiresAt":"2030-01-01T00:00:00Z"}`,
		`{"peerId":"x","addressFamilies":["IPv4","IPv6"]}`,
		`{"peerId":"x","expires_at":"2030-01-01T00:00:00Z"}`,
		`{"peerId":"x"} {"peerId":"y"}`,
		`{"peerId":"x"}   `,
		`{"peerId":null,"addressFamilies":null}`,
		`[]`,
		`{`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		var req peerRequest
		if err := decodeStrictJSON(bytes.NewReader(body), &req); err != nil {
			return
		}
		encoded, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal accepted request: %v", err)
		}
		var again peerRequest
		if err := decodeStrictJSON(bytes.NewReader(encoded), &again); err != nil {
			t.Fatalf("re-decode %s: %v", encoded, err)
		}
		if !reflect.DeepEqual(normalizePeerRequest(req), normalizePeerRequest(again)) {
			t.Fatalf("round trip changed request: %+v -> %+v", req, again)
		}
	})
}

// normalizePeerRequest treats an empty addressFamilies list like an absent
// one: omitempty drops it on encode, and the handler reads both the same way.
func normalizePeerRequest(r peerRequest) peerRequest {
	if len(r.AddressFamilies) == 0 {
		r.AddressFamilies = nil
	}
	return r
}

func FuzzParseExpiresAt(f *testing.F) {
	for _, s := range []string{
		"",
		"2099-01-01T00:00:00Z",
		"2099-01-01T00:00:00+03:00",
		"2000-01-01T00:00:00Z",
		"2099-01-01",
		"9999-12-31T23:59:59.999999999Z",
		"2099-01-01T24:00:00Z",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		before := time.Now()
		got, err := parseExpiresAt(&s)
		if s == "" {
			if got != nil || err != nil {
				t.Fatalf("empty input: got (%v, %v), want (nil, nil)", got, err)
			}
			return
		}
		if err != nil {
			if got != nil {
				t.Fatalf("%q: got both %v and error %v", s, got, err)
			}
			return
		}
		if got == nil {
			t.Fatalf("%q: got (nil, nil) for non-empty input", s)
		}
		if got.Location() != time.UTC {
			t.Fatalf("%q: result not in UTC: %v", s, got)
		}
		if !got.After(before) {
			t.Fatalf("%q: accepted a time that is not in the future: %v", s, got)
		}
	})
}

// FuzzPaginationParams checks that anything validatePaginationParams accepts
// parses into a usable window, and that parsing agrees with the raw values.
func FuzzPaginationParams(f *testing.F) {
	f.Add("", "")
	f.Add("0", "100")
	f.Add("10", "1000")
	f.Add("-1", "0")
	f.Add("+5", "1001")
	f.Add("9223372036854775807", "1")
	f.Add("1e3", " 5")

	f.Fuzz(func(t *testing.T, offsetStr, limitStr string) {
		if validatePaginationParams(offsetStr, limitStr) != nil {
			return
		}
		offset, limit := parsePaginationParams(offsetStr, limitStr)
		if offset < 0 {
			t.Fatalf("offset=%q: negative offset %d", offsetStr, offset)
		}
		if limit < 1 || limit > maxPaginationLimit {
			t.Fatalf("limit=%q: limit %d outside [1, %d]", limitStr, limit, maxPaginationLimit)
		}
		if offsetStr != "" {
			if n, _ := strconv.Atoi(offsetStr); n != offset {
				t.Fatalf("offset=%q parsed as %d", offsetStr, offset)
			}
		}
		if limitStr == "" && limit != defaultPaginationLimit {
			t.Fatalf("absent limit parsed as %d, want %d", limit, defaultPaginationLimit)
		}
	})
}

func FuzzIsUUIDv4(f *testing.F) {
	for _, s := range []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"550e8400e29b41d4a716446655440000",
		"urn:uuid:550e8400-e29b-41d4-a716-446655440000",
		"{550e8400-e29b-41d4-a716-446655440000}",
		"550e8400-e29b-11d4-a716-446655440000",
		"550e8400-e29b-41d4-0716-446655440000",
		"",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if !IsUUIDv4(s) {
			return
		}
		u, err := uuid.Parse(s)
		if err != nil {
			t.Fatalf("%q accepted but does not parse: %v", s, err)
		}
		if u.Version() != 4 || u.Variant() != uuid.RFC4122 {
			t.Fatalf("%q accepted with version %d, variant %v", s, u.Version(), u.Variant())
		}
		// The canonical form of an accepted ID must be accepted too, so
		// clients can store whichever form the API echoes back.
		if !IsUUIDv4(strings.ToUpper(u.String())) {
			t.Fatalf("%q accepted but its canonical form %q is not", s, u.String())
		}
	})
}
