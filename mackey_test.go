package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// captureStdout перенаправляет os.Stdout и возвращает собранную строку.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestMacToKeyCanonical(t *testing.T) {
	// Разные форматы одного и того же MAC дают один канонический ключ.
	forms := []string{
		"4CBD.8F73.D94D",
		"4cbd:8f73:d94d",
		"4cbd-8f73-d94d",
		"4cbd.8f73.d94d",
		"4cbd8f73d94d",
		"  4CBD:8F73:D94D  ",
	}
	want := "4cbd8f73d94d"
	for _, f := range forms {
		if got := macToKey(f); got != want {
			t.Errorf("macToKey(%q) = %q, want %q", f, got, want)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"4cbd.8f73.d94d":       "4cbd8f73d94d",
		"4CBD:8F73:D94D":       "4cbd8f73d94d",
		"4cbd-8f73-d94d":       "4cbd8f73d94d",
		"  4cbd 8f73 d94d  ":   "4cbd8f73d94d",
		"4cbd8f73d94d":         "4cbd8f73d94d",
		"4cbd.8f73.d94":        "",
		"4cbd8f73d94g":         "",
		"4cbd8f73d94":          "",
		"not-a-mac":            "",
		"4cbd:8f73:d94d:aa:bb": "",
	}
	for in, want := range cases {
		if got, ok := normalizeMAC(in); ok != (want != "") || got != want {
			t.Errorf("normalizeMAC(%q) = (%q, %v), want (%q, %v)", in, got, ok, want, want != "")
		}
	}
}

func TestFormatMAC(t *testing.T) {
	cases := map[string]string{
		"4cbd8f73d94d": "4C:BD:8F:73:D9:4D",
		"0e556c89a819": "0E:55:6C:89:A8:19",
	}
	for in, want := range cases {
		if got := formatMAC(in); got != want {
			t.Errorf("formatMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMacCandidateKeys(t *testing.T) {
	keys := macCandidateKeys("4cbd8f73d94d")
	want := []string{"4cbd8f73d94d", "4cbd.8f73.d94d", "4cbd-8f73-d94d"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("macCandidateKeys = %v, want %v", keys, want)
	}
}

func TestSearchMacHistory(t *testing.T) {
	newTestDB(t)
	rec := MacRecord{
		MacAddress: "4cbd8f73d94d",
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

	out := captureStdout(t, func() { searchMac("4CBD.8F73.D94D") })
	for _, want := range []string{
		"MAC 4C:BD:8F:73:D9:4D",
		"Сейчас:     swA / Gi0/1",
		"История 1:  swB / Gi0/2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("searchMac output missing %q;\ngot:\n%s", want, out)
		}
	}
}

func TestSearchMacUnfound(t *testing.T) {
	newTestDB(t)
	rec := UnfoundRecord{
		MacAddress: "f4339234d502",
		LastSwitch: "swA",
		LastPort:   "Po14",
		Reason:     "external",
		FirstSeen:  time.Unix(1_699_000_000, 0),
		LastSeen:   time.Unix(1_700_000_000, 0),
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(unfoundBucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(macToKey(rec.MacAddress)), mustJSON(t, rec))
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { searchMac("f433-9234-d502") })
	for _, want := range []string{
		"MAC F4:33:92:34:D5:02",
		"не резолвится в конечную точку (reason=external)",
		"Последний раз: swA / Po14",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("searchMac output missing %q;\ngot:\n%s", want, out)
		}
	}
}

func TestSearchMacNotFoundAndInvalid(t *testing.T) {
	newTestDB(t)

	out := captureStdout(t, func() { searchMac("001122334455") })
	if !strings.Contains(out, "не найден в базе") {
		t.Errorf("expected not-found message, got:\n%s", out)
	}

	out = captureStdout(t, func() { searchMac("nope") })
	if !strings.Contains(out, "не похоже на MAC") {
		t.Errorf("expected invalid-MAC message, got:\n%s", out)
	}
}

func TestSaveUnfoundMACInsertOnceAndUpdateReason(t *testing.T) {
	newTestDB(t)

	base := func(reason string, ts int64) UnfoundRecord {
		return UnfoundRecord{
			MacAddress: "aabbccddeeff",
			LastSwitch: "swA",
			LastPort:   "Po14",
			Neighbor:   "r1",
			Reason:     reason,
			LastSeen:   time.Unix(ts, 0),
		}
	}
	if err := saveUnfoundMAC("aabbccddeeff", base("external", 1_700_000_000)); err != nil {
		t.Fatal(err)
	}
	first := mustLoadUnfound(t, "aabbccddeeff")
	if first.Reason != "external" {
		t.Fatalf("first Reason = %q, want external", first.Reason)
	}
	firstSeen := first.FirstSeen

	// Повторное появление с другой классификацией — Reason должен обновиться,
	// FirstSeen — сохраниться, LastSeen — продвинуться.
	if err := saveUnfoundMAC("aabbccddeeff", base("internal", 1_700_100_000)); err != nil {
		t.Fatal(err)
	}
	second := mustLoadUnfound(t, "aabbccddeeff")
	if second.Reason != "internal" {
		t.Errorf("Reason = %q, want internal (updated on repeat)", second.Reason)
	}
	if second.Neighbor != "r1" {
		t.Errorf("Neighbor = %q, want r1", second.Neighbor)
	}
	if !second.FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen changed: %v -> %v", firstSeen, second.FirstSeen)
	}
	if !second.LastSeen.After(firstSeen) {
		t.Errorf("LastSeen not advanced: %v", second.LastSeen)
	}
}

func TestApplySVISeenUpdates(t *testing.T) {
	newTestDB(t)
	now := time.Unix(1_700_000_000, 0)
	updates := []sviSeenUpdate{
		{switchID: "sw1", vlanID: 100, hasMac: false, now: now},
		{switchID: "sw1", vlanID: 100, hasMac: true, now: now.Add(time.Hour)},
	}
	if err := applySVISeenUpdates(updates); err != nil {
		t.Fatal(err)
	}
	rec, err := loadSVIVlanSeen("sw1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if rec.FirstObserved.IsZero() {
		t.Errorf("FirstObserved not set")
	}
	if !rec.LastMacSeen.Equal(now.Add(time.Hour)) {
		t.Errorf("LastMacSeen = %v, want %v", rec.LastMacSeen, now.Add(time.Hour))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func mustLoadUnfound(t *testing.T, mac string) *UnfoundRecord {
	t.Helper()
	rec, err := loadUnfoundMAC(mac)
	if err != nil {
		t.Fatalf("loadUnfoundMAC(%q): %v", mac, err)
	}
	return rec
}
