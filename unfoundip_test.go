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
