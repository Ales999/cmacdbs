package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"

	"github.com/ales999/cisaccs/v2"
	"go.etcd.io/bbolt"
)

var cli struct {
	// Режим поиска одного MAC вместо заполнения базы данных. MAC передаётся после -s.
	SearchMAC string `short:"s" name:"search" help:"Поиск переданного MAC вместо заполнения базы данных"`
	// Отладочный вывод записей [debug].
	Debug bool `short:"d" name:"debug" help:"Выводить записи [debug]"`
}

var rootSwitches = []string{
	"switch1",
	"switch2",
}

type Visit struct {
	SwitchID  string    `json:"switch_id"`
	Port      string    `json:"port"`
	Timestamp time.Time `json:"timestamp"`
}

type MacRecord struct {
	MacAddress string  `json:"mac_address"`
	Current    Visit   `json:"current"`
	History    []Visit `json:"history"`
}

type SVIRecord struct {
	SwitchID    string `json:"switch_id"`
	VlanID      int    `json:"vlan_id"`
	Description string `json:"description,omitempty"`
}

// SVIVlanSeen отслеживает, когда последний раз на VLAN этого коммутатора
// замечен динамический MAC, и когда VLAN впервые был замечен как SVI.
// Нужен, чтобы помечать SVI пустыми только после долгого отсутствия MAC.
type SVIVlanSeen struct {
	SwitchID      string    `json:"switch_id"`
	VlanID        int       `json:"vlan_id"`
	LastMacSeen   time.Time `json:"last_mac_seen,omitempty"`
	FirstObserved time.Time `json:"first_observed,omitempty"`
}

// UnfoundRecord — MAC, который не резолвится в конкретную конечную точку
// (порт-линк ведёт за пределы управляемой области: сервер, неуправляемое
// устройство или мультичассис). Хранится как множество уникальных MAC (insert-once).
type UnfoundRecord struct {
	MacAddress string    `json:"mac_address"`
	LastSwitch string    `json:"last_switch"`
	LastPort   string    `json:"last_port"`
	Neighbor   string    `json:"neighbor,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type SwitchMACData struct {
	SwitchName   string
	MACs         []cisaccs.MacLineData
	SVIs         []cisaccs.IntDescSVI
	CDPNeighbors map[string]CDPNeighbor
	// CDPLines — суммарный вывод `sh etherchannel detail | i Group:|Port:` и
	// `sh cdp entry * | i Device|Interface`. Нужен для резолвинга линк-портов
	// (в т.ч. Port-Channel) до соседнего хоста через nxthst.FindNextPortbyMac.
	CDPLines []string
}

type CDPNeighbor struct {
	NeighborHostname  string
	NeighborDeviceID  string
	LocalInterface    string
	// RemoteInterface — исходящий порт соседа («Port ID (outgoing port)»).
	// Нужен для постройки топологии: вместе с LocalInterface даёт полное
	// описание ребра «наш-порт -> чужой-порт» без обращения к записи соседа.
	RemoteInterface string
}

var (
	db              *bbolt.DB
	bucketName      = []byte("MacHistory")
	unfoundBucket   = []byte("UnfoundMAC")
	emptyBucketName = []byte("EmptySVIs")
	sviSeenBucket   = []byte("SVIVlanSeen")
	isScanning      bool
	scanMu          sync.Mutex
	// debugEnabled управляет выводом записей [debug] (флаг -d).
	debugEnabled bool
)

// emptySVIDays — сколько дней SVI должен оставаться без динамических MAC-адресов,
// прежде чем считаться действительно пустым (защита от кратковременных
// «пропажений» MAC из-за L2/транков).
const emptySVIDays = 30

func main() {

	kong.Parse(&cli,
		kong.Name("cmacdbs"),
		kong.Description("Сбор MAC-адресов с Cisco-коммутаторов с отслеживанием истории перемещений"),
		kong.UsageOnError(),
	)

	// Включает/выключает вывод записей [debug].
	debugEnabled = cli.Debug

	var err error
	db, err = bbolt.Open("macs.db", 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Ошибка открытия БД: %v", err)
	}
	defer db.Close()

	// Если указан -s, ищем переданный MAC вместо заполнения базы.
	if strings.TrimSpace(cli.SearchMAC) != "" {
		searchMac(cli.SearchMAC)
		return
	}

	collectDataAndSave()
}

// debugf выводит отладочную запись только когда включена отладка (флаг -d).
func debugf(format string, args ...any) {
	if debugEnabled {
		log.Printf("[debug] "+format, args...)
	}
}

// searchMac — режим поиска одного MAC вместо заполнения базы данных.
// Тело будет дописано позже.
func searchMac(mac string) {
	debugf("searchMac для MAC %s", mac)
}

func getHostsFile() string {
	if v := os.Getenv("CIS2FILE"); v != "" {
		return v
	}
	return "hosts.yaml"
}

func getPasswdFile() string {
	if v := os.Getenv("CIS2PWDS"); v != "" {
		return v
	}
	return "groups.yaml"
}

func macToKey(mac string) string {
	return strings.ReplaceAll(strings.ToLower(mac), ":", "")
}

// portIsLink определяет, является ли порт линком (агрегацией/транком) к другому
// устройству, а не конечным access-портом. Для таких портов MAC может «переползать»
// между физическими портами одного bundle, поэтому в качестве точки фиксируем bundle.
func portIsLink(iface string) bool {
	li := strings.ToLower(strings.TrimSpace(iface))
	for _, p := range []string{"port-channel", "portchannel", "eth-trunk", "bundle-ether"} {
		if strings.HasPrefix(li, p) {
			return true
		}
	}
	// Короткая форма Cisco для Port-Channel — «Po» (ни один тип physical-порта
	// не начинается на «po»).
	return strings.HasPrefix(li, "po")
}

func vlanSet(macs []cisaccs.MacLineData) map[int]bool {
	s := make(map[int]bool)
	for _, m := range macs {
		v, err := strconv.Atoi(m.GetVlan())
		if err == nil {
			s[v] = true
		}
	}
	return s
}

func saveMacRecord(macAddr string, rec MacRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			_, err = tx.CreateBucket(bucketName)
			if err != nil {
				return err
			}
			b = tx.Bucket(bucketName)
		}
		return b.Put([]byte(macToKey(macAddr)), data)
	})
}

func loadMacRecord(macAddr string) (*MacRecord, error) {
	var rec *MacRecord
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			rec = &MacRecord{}
			return nil
		}
		data := b.Get([]byte(macToKey(macAddr)))
		if data == nil {
			rec = &MacRecord{}
			return nil
		}
		rec = &MacRecord{}
		return json.Unmarshal(data, rec)
	})
	return rec, err
}

// saveUnfoundMAC заносит MAC в таблицу «не найденных» только если его там ещё нет
// (insert-once). При повторном появлении обновляется только LastSeen.
func saveUnfoundMAC(macAddr string, rec UnfoundRecord) error {
	key := []byte(macToKey(macAddr))
	return db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(unfoundBucket)
		if err != nil {
			return err
		}
		existing := b.Get(key)
		if existing == nil {
			rec.FirstSeen = rec.LastSeen
			data, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			return b.Put(key, data)
		}
		// MAC уже есть — обновляем только LastSeen, остальное не трогаем.
		var cur UnfoundRecord
		if err := json.Unmarshal(existing, &cur); err != nil {
			return err
		}
		cur.LastSeen = rec.LastSeen
		if rec.LastSwitch != "" {
			cur.LastSwitch = rec.LastSwitch
		}
		if rec.LastPort != "" {
			cur.LastPort = rec.LastPort
		}
		data, err := json.Marshal(cur)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

func saveEmptySVI(switchID string, vlanID int, svis []cisaccs.IntDescSVI) error {
	for _, sv := range svis {
		if sv.Status != "up" || sv.Protocol != "up" {
			continue
		}
		key := fmt.Sprintf("%s_%04d", switchID, vlanID)
		rec := SVIRecord{SwitchID: switchID, VlanID: sv.VlanID, Description: sv.Description}
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		err = db.Update(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists(emptyBucketName)
			if err != nil {
				return err
			}
			return b.Put([]byte(key), data)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteEmptySVI убирает SVI из списка пустых (например, VLAN снова занялся MAC).
func deleteEmptySVI(switchID string, vlanID int) error {
	key := fmt.Sprintf("%s_%04d", switchID, vlanID)
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(emptyBucketName)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

// sviSeenKey — ключ записи «когда MAC видели на VLAN коммутатора».
func sviSeenKey(switchID string, vlanID int) string {
	return fmt.Sprintf("%s_%04d", switchID, vlanID)
}

// saveSVIVlanSeen сохраняет когда последний раз видели динамический MAC на
// VLAN коммутатора и когда VLAN впервые наблюдали.
func saveSVIVlanSeen(rec SVIVlanSeen) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(sviSeenBucket)
		if err != nil {
			return err
		}
		return b.Put([]byte(sviSeenKey(rec.SwitchID, rec.VlanID)), data)
	})
}

// loadSVIVlanSeen возвращает запись о видимости MAC на VLAN (ноль, если её нет).
func loadSVIVlanSeen(switchID string, vlanID int) (*SVIVlanSeen, error) {
	var rec *SVIVlanSeen
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(sviSeenBucket)
		if b == nil {
			rec = &SVIVlanSeen{}
			return nil
		}
		data := b.Get([]byte(sviSeenKey(switchID, vlanID)))
		if data == nil {
			rec = &SVIVlanSeen{}
			return nil
		}
		rec = &SVIVlanSeen{}
		return json.Unmarshal(data, rec)
	})
	return rec, err
}

// parseCDPNeighbors парсит вывод «sh cdp neighbors detail» в карту «локальный
// порт -> сосед». Ключ карты — порт на текущем коммутаторе, значение — ID и
// hostname обнаруженного соседнего устройства. Строка «Device ID» всегда
// предваряет строку «Interface» внутри одной записи CDP, поэтому hostname
// запоминается и привязывается к следующей строке интерфейса.
func parseCDPNeighbors(lines []string) map[string]CDPNeighbor {
	result := make(map[string]CDPNeighbor)
	var deviceID string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		idx := strings.Index(line, ":")
		if idx <= 0 || idx >= len(line)-1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		switch {
		case strings.Contains(key, "Device ID"):
			deviceID = strings.TrimSpace(val)
			if dotIdx := strings.Index(deviceID, "."); dotIdx > 0 {
				deviceID = deviceID[:dotIdx]
			}
		case strings.Contains(key, "Interface") && deviceID != "":
			localIface := val
			remoteIface := ""
			if p := strings.Index(localIface, "Port ID (outgoing port):"); p > 0 {
				remoteIface = strings.TrimSpace(localIface[p+len("Port ID (outgoing port):"):])
				localIface = localIface[:p]
			}
			localIface = strings.TrimSuffix(strings.TrimSpace(localIface), ",")
			localIface = strings.TrimSpace(localIface)
			if localIface == "" {
				continue
			}
			result[localIface] = CDPNeighbor{
				NeighborHostname:  strings.ToLower(deviceID),
				NeighborDeviceID:  deviceID,
				LocalInterface:    localIface,
				RemoteInterface:   remoteIface,
			}
			deviceID = ""
		}
	}
	return result
}
