package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

var topologyBucket = []byte("Topology")

// topologyStaleRuns — сколько запусков подряд коммутатор должен отсутствовать
// в управляемой области (не сканироваться и не объявляться соседом в CDP),
// чтобы быть удалённым из топологии. Позволяет переживать кратковременные
// недоступности, но убивает коммутаторы, выведенные из работы.
const topologyStaleRuns = 3

// TopoNeighbor — одно ребро топологии: локальный порт коммутатора, до которого
// подключён сосед, и (если известен) порт соседа.
type TopoNeighbor struct {
	LocalInterface  string `json:"local_interface"`
	RemoteHostname  string `json:"remote_hostname"`
	RemoteInterface string `json:"remote_interface,omitempty"`
	Managed         bool   `json:"managed"`
}

// TopologySwitch — снимок CDP-топологии одного коммутатора на момент скана.
// Ключ бакета — hostname. Перезаписывается каждый запуск, поэтому
// добавление/вывод коммутаторов обрабатывается через MissRuns (reconcileTopology).
type TopologySwitch struct {
	Hostname  string         `json:"hostname"`
	ScanTime  time.Time      `json:"scan_time"`
	Neighbors []TopoNeighbor `json:"neighbors"`
	MissRuns  int            `json:"miss_runs"`
}

// buildTopology собирает запись топологии для коммутатора из его CDP-данных.
// Managed показывает, относится ли сосед к управляемой области (hosts.yaml).
func buildTopology(sw SwitchMACData, managed map[string]bool) TopologySwitch {
	t := TopologySwitch{
		Hostname:  sw.SwitchName,
		ScanTime:  time.Now(),
		Neighbors: []TopoNeighbor{},
	}
	for iface, nb := range sw.CDPNeighbors {
		t.Neighbors = append(t.Neighbors, TopoNeighbor{
			LocalInterface:  iface,
			RemoteHostname:  nb.NeighborHostname,
			RemoteInterface: nb.RemoteInterface,
			Managed:         managed[strings.ToLower(nb.NeighborHostname)],
		})
	}
	return t
}

// saveTopologySwitch сохраняет (перезаписывает) снимок топологии коммутатора.
func saveTopologySwitch(t TopologySwitch) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(topologyBucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(strings.ToLower(t.Hostname)), data)
	})
}

// reconcileTopology обновляет MissRuns у коммутаторов в топологии:
//   - доступные в текущем запуске — MissRuns=0;
//   - отсутствующие увеличивают MissRuns и удаляются после topologyStaleRuns.
func reconcileTopology(knownNow map[string]bool) error {
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(topologyBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var t TopologySwitch
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}
			if knownNow[strings.ToLower(string(k))] {
				t.MissRuns = 0
			} else {
				t.MissRuns++
			}
			if t.MissRuns >= topologyStaleRuns {
				return b.Delete(k)
			}
			data, err := json.Marshal(t)
			if err != nil {
				return err
			}
			return b.Put(k, data)
		})
	})
}

// applySVISeenUpdates применяет пачкой изменения видимости MAC по VLAN:
// устанавлирует FirstObserved при первом наблюдении SVI и LastMacSeen, когда
// VLAN был занят динамическим MAC.
func applySVISeenUpdates(updates []sviSeenUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(sviSeenBucket)
		if err != nil {
			return err
		}
		for _, u := range updates {
			key := []byte(sviSeenKey(u.switchID, u.vlanID))
			var rec SVIVlanSeen
			if data := b.Get(key); data != nil {
				if err := json.Unmarshal(data, &rec); err != nil {
					return err
				}
			}
			if rec.FirstObserved.IsZero() {
				rec.FirstObserved = u.now
			}
			if u.hasMac {
				rec.LastMacSeen = u.now
			}
			data, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if err := b.Put(key, data); err != nil {
				return err
			}
		}
		return nil
	})
}

// sviIsEmptyConfirmed возвращает, действительно ли SVI пуст уже больше месяца:
// VLAN наблюдали дольше месяца и динамический MAC не видели больше месяца
// (или не видели никогда).
func sviIsEmptyConfirmed(switchID string, vlanID int, now time.Time) bool {
	rec, err := loadSVIVlanSeen(switchID, vlanID)
	if err != nil {
		log.Printf("Error loading SVIVlanSeen %s/%d: %v", switchID, vlanID, err)
		return false
	}
	if rec.FirstObserved.IsZero() {
		return false
	}
	stable := time.Duration(emptySVIDays) * 24 * time.Hour
	if now.Sub(rec.FirstObserved) < stable {
		return false
	}
	if rec.LastMacSeen.IsZero() {
		return true
	}
	return now.Sub(rec.LastMacSeen) >= stable
}
