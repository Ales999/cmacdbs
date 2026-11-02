package main

import (
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"10.23.1.1":     "10.23.1.1",
		" 192.168.0.5 ": "192.168.0.5",
		"10.0.0.01":     "10.0.0.1", // ведущий ноль отбрасывается
		"10.0.0.255":    "10.0.0.255",
	}
	for in, want := range cases {
		if got, ok := normalizeIP(in); ok != (want != "") || got != want {
			t.Errorf("normalizeIP(%q) = (%q, %v), want (%q, %v)", in, got, ok, want, want != "")
		}
	}

	invalid := []string{
		"",
		"10.23.1",          //太少 октетов
		"10.23.1.1.1",      // слишком октетов
		"10.23.1.256",      // октет > 255
		"10.23.1.x",        // не число
		"10.23.1.-1",       // отрицательный
		"abc.def.ghi.jkl",  // не десятичные
		"4cbd8f73d94d",     // это MAC, а не IP
	}
	for _, in := range invalid {
		if got, ok := normalizeIP(in); ok || got != "" {
			t.Errorf("normalizeIP(%q) = (%q, %v), want invalid", in, got, ok)
		}
	}
}

func TestMacToCisco(t *testing.T) {
	cases := map[string]string{
		"aabbcc001030": "aabb.cc00.1030",
		"4cbd8f73d94d": "4cbd.8f73.d94d",
		"fffffffffffe": "ffff.ffff.fffe",
	}
	for in, want := range cases {
		if got := macToCisco(in); got != want {
			t.Errorf("macToCisco(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveArpIP(t *testing.T) {
	arp := []string{
		"Protocol  Address          Age (min)  Hardware Addr   Type   Interface",
		"Internet  10.23.1.1             172   aabb.cc00.1030  ARPA   Ethernet0/3",
		"Internet  10.23.1.2               -   aabb.cc00.2030  ARPA   Ethernet0/3",
		"Internet  192.168.9.9             12   dd.ee.ff.00.11  ARPA   VLAN5",
		"Internet  10.99.99.99             5   Incomplete  ARPA   Ethernet0/9",
	}

	arpIdx := buildArpIpIndex(arp)

	t.Run("found", func(t *testing.T) {
		if got := resolveArpIP(arpIdx, "aabbcc001030"); got != "10.23.1.1" {
			t.Errorf("resolveArpIP = %q, want 10.23.1.1", got)
		}
		if got := resolveArpIP(arpIdx, "aabbcc002030"); got != "10.23.1.2" {
			t.Errorf("resolveArpIP = %q, want 10.23.1.2", got)
		}
	})

	t.Run("not found", func(t *testing.T) {
		if got := resolveArpIP(arpIdx, "001122334455"); got != "" {
			t.Errorf("resolveArpIP = %q, want empty", got)
		}
	})

	t.Run("empty lines", func(t *testing.T) {
		if got := resolveArpIP(nil, "aabbcc001030"); got != "" {
			t.Errorf("resolveArpIP(nil) = %q, want empty", got)
		}
	})
}

func TestSearchByIP(t *testing.T) {
	newTestDB(t)
	rec := MacRecord{
		MacAddress: "4cbd8f73d94d",
		IP:         "10.23.1.1",
		Current:    Visit{SwitchID: "swA", Port: "Gi0/1", Timestamp: time.Unix(1_700_000_000, 0)},
		History:    []Visit{{SwitchID: "swB", Port: "Gi0/2", Timestamp: time.Unix(1_699_000_000, 0)}},
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucket(bucketName)
		if err != nil {
			return err
		}
		return b.Put([]byte(macToKey(rec.MacAddress)), mustJSON(t, rec))
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("by ip direct", func(t *testing.T) {
		out := searchByIP("10.23.1.1")
		for _, want := range []string{
			"MAC 4C:BD:8F:73:D9:4D",
			"IP:",
			"10.23.1.1",
			"Сейчас:     swA / Gi0/1",
			"История 1:  swB / Gi0/2",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("searchByIP output missing %q;\ngot:\n%s", want, out)
			}
		}
	})

	t.Run("dispatcher picks ip", func(t *testing.T) {
		out := search("10.23.1.1")
		if !strings.Contains(out, "MAC 4C:BD:8F:73:D9:4D") {
			t.Errorf("search(ip) did not resolve to the record;\ngot:\n%s", out)
		}
		if !strings.Contains(out, "10.23.1.1") {
			t.Errorf("search(ip) should show the IP;\ngot:\n%s", out)
		}
	})

	t.Run("ip not found", func(t *testing.T) {
		out := searchByIP("172.16.0.1")
		if !strings.Contains(out, "не найден в базе") {
			t.Errorf("expected not-found, got:\n%s", out)
		}
	})
}

func TestSearchAutoDetect(t *testing.T) {
	newTestDB(t)

	t.Run("invalid input", func(t *testing.T) {
		out := search("nope")
		if !strings.Contains(out, "не похоже ни на MAC-адрес, ни на IP-адрес") {
			t.Errorf("expected ambiguous error, got:\n%s", out)
		}
	})

	t.Run("mac input goes to mac path", func(t *testing.T) {
		// Ни MAC, ни IP в базе нет — но ошибка должна быть про MAC-путь, а не
		// про неоднозначность (вход похож на MAC).
		out := search("4cbd8f73d94d")
		if strings.Contains(out, "не похоже ни на") {
			t.Errorf("mac-like input should not report ambiguous error:\n%s", out)
		}
		if !strings.Contains(out, "не найден в базе") {
			t.Errorf("expected MAC not-found, got:\n%s", out)
		}
	})
}
