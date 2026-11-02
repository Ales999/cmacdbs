package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// newTestDB открывает временный bbolt-файл и подставляет его в глобальный db.
func newTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	d, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("bbolt open: %v", err)
	}
	t.Cleanup(func() { d.Close(); os.Remove(path) })
	db = d
}

func TestSVIEmptyConfirmed(t *testing.T) {
	newTestDB(t)
	now := time.Now()
	month := time.Duration(emptySVIDays) * 24 * time.Hour

	cases := []struct {
		name     string
		observed time.Time
		lastMac  time.Time
		want     bool
	}{
		{"never seen, observed long ago", now.Add(-2 * month), time.Time{}, true},
		{"recently seen, observed long ago", now.Add(-2 * month), now.Add(-48 * time.Hour), false},
		{"new SVI, never seen", now.Add(-24 * time.Hour), time.Time{}, false},
		{"new SVI, seen recently", now.Add(-24 * time.Hour), now, false},
		{"old mac, long observed", now.Add(-month), now.Add(-2 * month), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := SVIVlanSeen{SwitchID: "sw1", VlanID: 100, LastMacSeen: c.lastMac, FirstObserved: c.observed}
			if err := saveSVIVlanSeen(rec); err != nil {
				t.Fatalf("saveSVIVlanSeen: %v", err)
			}
			got := sviIsEmptyConfirmed("sw1", 100, now)
			if got != c.want {
				t.Errorf("sviIsEmptyConfirmed = %v, want %v", got, c.want)
			}
		})
	}
}

func TestReconcileTopology(t *testing.T) {
	newTestDB(t)

	mk := func(host string, runs int) TopologySwitch {
		return TopologySwitch{Hostname: host, ScanTime: time.Now(), Neighbors: []TopoNeighbor{}, MissRuns: runs}
	}
	if err := saveTopologySwitch(mk("alpha", 0)); err != nil {
		t.Fatal(err)
	}
	if err := saveTopologySwitch(mk("beta", 0)); err != nil {
		t.Fatal(err)
	}

	// Запуск 1: только alpha доступен -> beta получает MissRuns=1.
	if err := reconcileTopology(map[string]bool{"alpha": true}); err != nil {
		t.Fatal(err)
	}
	if got := countKeys(t); got != 2 {
		t.Fatalf("expected 2 topology keys after run1, got %d", got)
	}

	// Запуск 2: никто не доступен -> alpha=1, beta=2 (beta ещё жив).
	if err := reconcileTopology(nil); err != nil {
		t.Fatal(err)
	}

	// Запуск 3: никто не доступен -> alpha=2, beta=3 -> beta удалён.
	if err := reconcileTopology(nil); err != nil {
		t.Fatal(err)
	}
	if got := countKeys(t); got != 1 {
		t.Fatalf("expected 1 topology key after run3 (beta removed), got %d", got)
	}

	rec := loadTopology(t, "alpha")
	if rec.MissRuns != 2 {
		t.Errorf("alpha MissRuns = %d, want 2", rec.MissRuns)
	}
}

func TestReconcileTopologyResets(t *testing.T) {
	newTestDB(t)
	if err := saveTopologySwitch(TopologySwitch{Hostname: "sw1", MissRuns: 5}); err != nil {
		t.Fatal(err)
	}
	// Доступен -> MissRuns сбрасывается в 0, запись не удаляется.
	if err := reconcileTopology(map[string]bool{"sw1": true}); err != nil {
		t.Fatal(err)
	}
	rec := loadTopology(t, "sw1")
	if rec == nil {
		t.Fatal("sw1 should still exist after being known")
	}
	if rec.MissRuns != 0 {
		t.Errorf("MissRuns = %d, want 0", rec.MissRuns)
	}
}

func TestBuildTopology(t *testing.T) {
	managed := map[string]bool{"myswcm36": true, "server1": false}
	sw := SwitchMACData{
		SwitchName: "swA",
		CDPNeighbors: map[string]CDPNeighbor{
			"TenGigabitEthernet1/1/1": {NeighborHostname: "myswcm36", NeighborDeviceID: "myswcm36", LocalInterface: "TenGigabitEthernet1/1/1", RemoteInterface: "TenGigabitEthernet2/1/4"},
			"TenGigabitEthernet1/1/2": {NeighborHostname: "server1", NeighborDeviceID: "server1", LocalInterface: "TenGigabitEthernet1/1/2", RemoteInterface: "Ethernet1/33"},
		},
	}
	tw := buildTopology(sw, managed)
	if tw.Hostname != "swA" {
		t.Fatalf("Hostname = %q, want swA", tw.Hostname)
	}
	if len(tw.Neighbors) != 2 {
		t.Fatalf("expected 2 neighbors, got %d", len(tw.Neighbors))
	}
	// Порядок map не детерминирован, поэтому ищем по RemoteHostname.
	byHost := map[string]TopoNeighbor{}
	for _, n := range tw.Neighbors {
		byHost[n.RemoteHostname] = n
	}
	if n := byHost["myswcm36"]; n.LocalInterface != "TenGigabitEthernet1/1/1" || n.RemoteInterface != "TenGigabitEthernet2/1/4" || !n.Managed {
		t.Errorf("myswcm36 edge wrong: %+v", n)
	}
	if n := byHost["server1"]; n.RemoteInterface != "Ethernet1/33" || n.Managed {
		t.Errorf("server1 edge wrong (should be unmanaged): %+v", n)
	}
}

// TestBuildTopologyDeterministic проверяет, что рёбра топологии отсортированы по
// локальному порту, несмотря на недетерминированный range по map (п.6 REVIEW).
func TestBuildTopologyDeterministic(t *testing.T) {
	managed := map[string]bool{}
	sw := SwitchMACData{
		SwitchName: "swA",
		CDPNeighbors: map[string]CDPNeighbor{
			"TenGigabitEthernet1/1/9":  {NeighborHostname: "h9", LocalInterface: "TenGigabitEthernet1/1/9"},
			"TenGigabitEthernet1/1/1":  {NeighborHostname: "h1", LocalInterface: "TenGigabitEthernet1/1/1"},
			"TenGigabitEthernet1/1/5":  {NeighborHostname: "h5", LocalInterface: "TenGigabitEthernet1/1/5"},
			"TenGigabitEthernet1/1/23": {NeighborHostname: "h23", LocalInterface: "TenGigabitEthernet1/1/23"},
		},
	}
	// Собираем все ключи и перемешиваем порядок вставки в новую карту несколько
	// раз — если сортировка на месте, результат всё равно стабилен.
	for iter := 0; iter < 5; iter++ {
		keys := []string{"TenGigabitEthernet1/1/9", "TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/5", "TenGigabitEthernet1/1/23"}
		// простой reverse для разнообразия порядка итерации
		for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
			keys[i], keys[j] = keys[j], keys[i]
		}
		shuffled := make(map[string]CDPNeighbor, len(keys))
		for _, k := range keys {
			shuffled[k] = sw.CDPNeighbors[k]
		}
		tw := buildTopology(SwitchMACData{SwitchName: "swA", CDPNeighbors: shuffled}, managed)
		var gotIfaces []string
		for _, n := range tw.Neighbors {
			gotIfaces = append(gotIfaces, n.LocalInterface)
		}
		want := []string{"TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/23", "TenGigabitEthernet1/1/5", "TenGigabitEthernet1/1/9"}
		if !reflect.DeepEqual(gotIfaces, want) {
			t.Errorf("iter %d: neighbors not sorted by LocalInterface;\ngot:  %v\nwant: %v", iter, gotIfaces, want)
		}
	}
}

func countKeys(t *testing.T) int {
	t.Helper()
	n := 0
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(topologyBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_k, _v []byte) error { n++; return nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func loadTopology(t *testing.T, host string) *TopologySwitch {
	t.Helper()
	var rec *TopologySwitch
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(topologyBucket)
		if b == nil {
			rec = nil
			return nil
		}
		data := b.Get([]byte(host))
		if data == nil {
			rec = nil
			return nil
		}
		rec = &TopologySwitch{}
		return json.Unmarshal(data, rec)
	})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
