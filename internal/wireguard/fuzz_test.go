package wireguard

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// FuzzIPPool drives the pool with a random sequence of allocate, release and
// markUsed calls on a small subnet and checks it against a plain set of used
// addresses: no address is handed out twice, the server address is never
// handed out, and allocation fails only when every host address is taken.
//
// Input: data[0] picks the prefix, data[1] the server address, and each
// following pair of bytes is one operation (kind, address offset).
func FuzzIPPool(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 0, 1, 2, 0, 0})
	f.Add([]byte{2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 3, 0, 0, 0, 0})
	f.Add([]byte{5, 200, 0, 0, 2, 4, 2, 5, 0, 0, 0, 0, 1, 4, 0, 0})
	f.Add([]byte{3, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0})

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/30"),
		netip.MustParsePrefix("10.0.0.0/29"),
		netip.MustParsePrefix("10.0.0.0/28"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("fd00::/126"),
		netip.MustParsePrefix("fd00::/124"),
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		prefix := prefixes[int(data[0])%len(prefixes)]
		hosts := hostCount(prefix)
		hostAt := func(b byte) netip.Addr {
			a := prefix.Addr()
			for range 1 + int(b)%hosts {
				a = a.Next()
			}
			return a
		}

		// data[1] == 0 means no server address; anything else picks a host.
		var server netip.Addr
		if data[1] != 0 {
			server = hostAt(data[1])
		}
		p, err := newIPPool(prefix, server)
		if err != nil {
			t.Fatalf("newIPPool(%s): %v", prefix, err)
		}

		used := make(map[netip.Addr]bool)
		if server.IsValid() {
			used[server] = true
		}

		ops := data[2:]
		for i := 0; i+1 < len(ops); i += 2 {
			addr := hostAt(ops[i+1])
			switch ops[i] % 3 {
			case 0:
				got, err := p.allocate()
				if len(used) == hosts {
					if !errors.Is(err, ErrNoAvailableIP) {
						t.Fatalf("op %d: pool is full but allocate returned (%v, %v)", i/2, got, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("op %d: %d of %d hosts used but allocate failed: %v", i/2, len(used), hosts, err)
				}
				if !p.inRange(got) || !prefix.Contains(got) {
					t.Fatalf("op %d: allocated %v outside %s", i/2, got, prefix)
				}
				if got == server {
					t.Fatalf("op %d: allocated the server address %v", i/2, got)
				}
				if used[got] {
					t.Fatalf("op %d: allocated %v twice", i/2, got)
				}
				used[got] = true
			case 1:
				if addr == server {
					continue // the service never releases the server address
				}
				p.release(addr)
				delete(used, addr)
			case 2:
				if addr == server {
					continue
				}
				p.markUsed(addr)
				used[addr] = true
			}
			for a := range used {
				if !p.isUsed(a) {
					t.Fatalf("op %d: %v should be used but the pool has it free", i/2, a)
				}
			}
		}
	})
}

// FuzzStoredToRecord feeds arbitrary JSON through the path that loads peers
// from the store file at startup. A record it accepts must convert back to
// the same stored form and load again unchanged.
func FuzzStoredToRecord(f *testing.F) {
	key := "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	psk := "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	f.Add([]byte(`{"peer_id":"p1","public_key":"` + key + `","preshared_key":"` + psk + `","allowed_ips":["10.0.0.2/32"],"created_at":"2026-01-01T00:00:00Z"}`))
	f.Add([]byte(`{"peer_id":"p1","public_key":"` + key + `","preshared_key":"` + psk + `","allowed_ips":["10.0.0.2/32","fd00::2/128"],"created_at":"2026-01-01T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}`))
	f.Add([]byte(`{"peer_id":"p1","public_key":"` + key + `","preshared_key":"` + psk + `","allowed_ips":["10.0.0.2/24",""]}`))
	f.Add([]byte(`{"peer_id":" ","public_key":"` + key + `","preshared_key":"` + psk + `","allowed_ips":["10.0.0.2/32"]}`))
	f.Add([]byte(`{"peer_id":"p1","public_key":"short","preshared_key":"","allowed_ips":["not-a-cidr"]}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var stored peerRecordStored
		if json.Unmarshal(data, &stored) != nil {
			return
		}
		rec, err := storedToRecord(stored)
		if err != nil {
			return
		}
		if len(rec.AllowedIPs) == 0 {
			t.Fatalf("accepted a record without allowed IPs: %s", data)
		}
		again, err := storedToRecord(recordToStored(rec))
		if err != nil {
			t.Fatalf("re-load of %+v: %v", recordToStored(rec), err)
		}
		if !reflect.DeepEqual(rec, again) {
			t.Fatalf("round trip changed record:\n%+v\n%+v", rec, again)
		}
	})
}
