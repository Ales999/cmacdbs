package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func withTempDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	d, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { d.Close(); os.Remove(path) })
	db = d
}

func TestSearchByMACUnfoundShowsIP(t *testing.T) {
	withTempDB(t)

	key := "005056885711"
	if err := saveUnfoundMAC(key, UnfoundRecord{
		MacAddress: key,
		LastSwitch: "dcx4500x",
		LastPort:   "Port-channel14",
		Reason:     "external",
		IP:         "172.24.16.42",
		LastSeen:   time.Now(),
	}); err != nil {
		t.Fatalf("saveUnfoundMAC: %v", err)
	}

	out := searchByMAC("00:50:56:88:57:11")
	if !strings.Contains(out, "172.24.16.42") {
		t.Errorf("expected IP in output, got:\n%s", out)
	}
	if !strings.Contains(out, "reason=external") {
		t.Errorf("expected status line, got:\n%s", out)
	}
}

func TestSearchByIPUnfoundShowsIP(t *testing.T) {
	withTempDB(t)

	// IP есть только у «не найденного» MAC (линк за пределами области, но
	// ARP-привязка на коммутаторе есть) — searchByIP должен его найти.
	key := "005056885711"
	if err := saveUnfoundMAC(key, UnfoundRecord{
		MacAddress: key,
		LastSwitch: "dcx4500x",
		LastPort:   "Port-channel14",
		Reason:     "external",
		IP:         "172.24.16.42",
		LastSeen:   time.Now(),
	}); err != nil {
		t.Fatalf("saveUnfoundMAC: %v", err)
	}

	out := searchByIP("172.24.16.42")
	for _, want := range []string{
		"MAC 00:50:56:88:57:11",
		"172.24.16.42",
		"reason=external",
		"dcx4500x / Port-channel14",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("searchByIP output missing %q;\ngot:\n%s", want, out)
		}
	}

	// Приоритет — MacHistory: если IP есть и там, и там, выводим запись с историей.
	newTestDB(t)
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		return b.Put([]byte(macToKey("f4339234d502")), mustJSON(t, MacRecord{
			MacAddress: "f4339234d502",
			IP:         "172.24.16.42",
			Current:    Visit{SwitchID: "swA", Port: "Gi0/1", Timestamp: time.Unix(1_700_000_000, 0)},
		}))
	}); err != nil {
		t.Fatalf("put mac record: %v", err)
	}
	if err := saveUnfoundMAC("f4339234d502", UnfoundRecord{
		MacAddress: "f4339234d502", LastSwitch: "dcx4500x", LastPort: "Po1",
		Reason: "external", IP: "172.24.16.42", LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("saveUnfoundMAC: %v", err)
	}
	out = searchByIP("172.24.16.42")
	if !strings.Contains(out, "Сейчас:") {
		t.Errorf("expected MacHistory record to take priority, got:\n%s", out)
	}
}

func TestSaveUnfoundMACUpdatesIPOnSecondSave(t *testing.T) {
	withTempDB(t)

	key := "005056885711"
	if err := saveUnfoundMAC(key, UnfoundRecord{
		MacAddress: key, LastSwitch: "swA", LastPort: "Po1",
		Reason: "external", LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// Второй запуск без IP — прежний IP не должен потеряться.
	if err := saveUnfoundMAC(key, UnfoundRecord{
		MacAddress: key, LastSwitch: "swB", LastPort: "Po2",
		Reason: "external", LastSeen: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("second save: %v", err)
	}
	rec, err := loadUnfoundMAC(key)
	if err != nil || rec == nil {
		t.Fatalf("loadUnfoundMAC: %v rec=%v", err, rec)
	}
	if rec.IP != "" {
		t.Errorf("expected empty IP preserved from first save to remain, got %q", rec.IP)
	}
	if rec.LastSwitch != "swB" || rec.LastPort != "Po2" {
		t.Errorf("expected updated location, got %s/%s", rec.LastSwitch, rec.LastPort)
	}

	// Третий запуск с IP — должен сохраниться и обновиться.
	if err := saveUnfoundMAC(key, UnfoundRecord{
		MacAddress: key, LastSwitch: "swB", LastPort: "Po2",
		Reason: "external", IP: "10.0.0.1", LastSeen: time.Now().Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("third save: %v", err)
	}
	rec, _ = loadUnfoundMAC(key)
	if rec.IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %q", rec.IP)
	}
}
