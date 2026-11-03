package main

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
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
	// Порт подключения к коммутаторам по SSH
	PortSsh int `help:"SSH порт для доступа к cisco" short:"p" default:"22"`
	// Путь к файлу конфигурации имя_cisco/группа/ip
	CisFileName string `help:"Путь к файлу конфигурации имя_cisco/группа/ip" default:"/etc/cisco/hosts.yaml" env:"CIS2FILE"`
	// Путь к файлу конфигурации имя_группы/логин/пароль
	PwdFileName string `help:"Путь к файлу конфигурации имя_группы/логин/пароль" default:"/etc/cisco/groups.yaml" env:"CIS2PWDS"`
	// Пусть к файлу конфигурации программы со списком коммутаторов от которых будем сканировать сеть.
	CmacDbConfig string `help:"Пусть к файлу конфигурации программы со списком коммутаторов от которых будем сканировать сеть" default:"/etc/cisco/cmacdb.yaml"`
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
	IP         string  `json:"ip,omitempty"`
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
	IP         string    `json:"ip,omitempty"`
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
	// ARP — вывод `sh arp` на коммутаторе. Нужен, чтобы привязать IP-адрес к
	// MAC-адресу конечной точки через cisaccs.CisFindArp (MAC из таблицы MAC
	// напрямую IP не содержит, привязка хранится в ARP-таблице).
	ARP []string
}

type CDPNeighbor struct {
	NeighborHostname string
	NeighborDeviceID string
	LocalInterface   string
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

	// Если указан -s, ищем переданный MAC (или IP) вместо заполнения базы.
	if strings.TrimSpace(cli.SearchMAC) != "" {
		fmt.Println(search(strings.TrimSpace(cli.SearchMAC)))
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

// search определяет тип переданного адраса (IPv4 или MAC) и вызывает
// соответствующий режим поиска. Строки взаимно исключающие: IPv4 содержит
// точки и десятичные октеты, MAC — 12 hex-символов, поэтому путаницы нет.
func search(raw string) string {
	if ip, ok := normalizeIP(raw); ok {
		return searchByIP(ip)
	}
	if _, ok := normalizeMAC(raw); ok {
		return searchByMAC(raw)
	}
	return fmt.Sprintf("Ошибка: %q не похоже ни на MAC-адрес, ни на IP-адрес", raw)
}

// searchByMAC ищет переданный MAC в базе данных и формирует текст отчёта:
// текущее место нахождения из MacHistory (или запись из UnfoundMAC, если MAC
// не резолвится в конечную точку). Формат ввода гибкий: принимает разделители
// «:», «-» и «.» (в т.ч. cisco-вид 0011.2233.4455).
func searchByMAC(raw string) string {
	key, ok := normalizeMAC(raw)
	if !ok {
		return fmt.Sprintf("Ошибка: %q не похоже на MAC-адрес", raw)
	}

	// После миграции все ключи в БД канонические (macToKey убирает «:», «-», «»
	// и приводит к нижнему регистру), поэтому совпадает первая форма. macCandidateKeys
	// оставлены как defensive-мера на случай немиграрованных данных.
	keys := macCandidateKeys(key)
	debugf("candidate keys for %q: %v", raw, keys)

	// Первоочередной вариант — полноценная запись с историей перемещений.
	for _, k := range keys {
		if rec, err := loadMacRecord(k); err != nil {
			debugf("error reading MacHistory via key %q: %v", k, err)
			continue
		} else if rec.Current.SwitchID != "" || len(rec.History) > 0 {
			debugf("matched MacHistory via key %q", k)
			return formatMacResult(key, rec)
		}
	}

	// MAC нет в MacHistory — проверим «не найденных» (линк за пределами области).
	for _, k := range keys {
		if unf, err := loadUnfoundMAC(k); err != nil {
			debugf("error reading UnfoundMAC via key %q: %v", k, err)
			continue
		} else if unf != nil && (unf.LastSwitch != "" || unf.Reason != "") {
			debugf("matched UnfoundMAC via key %q", k)
			var b strings.Builder
			fmt.Fprintf(&b, "MAC %s\n", formatMAC(key))
			fmt.Fprintf(&b, "  Статус:     не резолвится в конечную точку (reason=%s)\n", unf.Reason)
			if unf.IP != "" {
				fmt.Fprintf(&b, "  IP:         %s\n", unf.IP)
			}
			if unf.LastSwitch != "" {
				fmt.Fprintf(&b, "  Последний раз: %s / %s (%s)\n", unf.LastSwitch, unf.LastPort, ts(unf.LastSeen))
			}
			return b.String()
		}
	}

	return fmt.Sprintf("MAC %s не найден в базе", formatMAC(key))
}

// searchByIP ищет MAC по привязанному IP-адресу в MacHistory и UnfoundMAC и
// формирует текст отчёта. Вторичного индекса по IP нет, поэтому оба бакета
// перебираются полностью (размер порядка тысяч записей — для одиночного
// поиска в CLI приемлемо). IP хранится и у конечных точек (MacHistory), и у
// «не найденных» MAC (UnfoundMAC — линк за пределами области, но ARP-привязка
// на коммутаторе есть), поэтому ищем в обоих. Приоритет — запись с историей.
func searchByIP(canonicalIP string) string {
	var macRec *MacRecord
	var unfRec *UnfoundRecord
	found := false
	err := db.View(func(tx *bbolt.Tx) error {
		// MacHistory — первичный вариант с историей перемещений.
		if b := tx.Bucket(bucketName); b != nil {
			if err := b.ForEach(func(_k, v []byte) error {
				if found {
					return nil
				}
				var r MacRecord
				if err := json.Unmarshal(v, &r); err != nil {
					return nil
				}
				if strings.EqualFold(strings.TrimSpace(r.IP), canonicalIP) {
					macRec = &r
					found = true
				}
				return nil
			}); err != nil {
				return err
			}
		}
		// UnfoundMAC — проверяем, только если IP ещё не нашли в MacHistory.
		if !found {
			if b := tx.Bucket(unfoundBucket); b != nil {
				return b.ForEach(func(_k, v []byte) error {
					var r UnfoundRecord
					if err := json.Unmarshal(v, &r); err != nil {
						return nil
					}
					if strings.EqualFold(strings.TrimSpace(r.IP), canonicalIP) {
						unfRec = &r
						found = true
					}
					return nil
				})
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Sprintf("Ошибка чтения БД: %v", err)
	}
	if !found {
		return fmt.Sprintf("IP %s не найден в базе", canonicalIP)
	}
	if macRec != nil && (macRec.Current.SwitchID != "" || len(macRec.History) > 0) {
		return formatMacResult(macRec.MacAddress, macRec)
	}
	// IP найден у «не найденного» MAC — выводим его статус, как в searchByMAC.
	var b strings.Builder
	fmt.Fprintf(&b, "MAC %s\n", formatMAC(unfRec.MacAddress))
	fmt.Fprintf(&b, "  Статус:     не резолвится в конечную точку (reason=%s)\n", unfRec.Reason)
	if unfRec.IP != "" {
		fmt.Fprintf(&b, "  IP:         %s\n", unfRec.IP)
	}
	if unfRec.LastSwitch != "" {
		fmt.Fprintf(&b, "  Последний раз: %s / %s (%s)\n", unfRec.LastSwitch, unfRec.LastPort, ts(unfRec.LastSeen))
	}
	return b.String()
}

// formatMacResult формирует челочитаемый отчёт по записи MacRecord: MAC,
// привязанный IP, текущее место нахождения и история перемещений.
func formatMacResult(macKey string, rec *MacRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MAC %s\n", formatMAC(macKey))
	if rec.IP != "" {
		fmt.Fprintf(&b, "  IP:         %s\n", rec.IP)
	}
	if rec.Current.SwitchID != "" {
		fmt.Fprintf(&b, "  Сейчас:     %s / %s (%s)\n", rec.Current.SwitchID, rec.Current.Port, ts(rec.Current.Timestamp))
	}
	for i, h := range rec.History {
		fmt.Fprintf(&b, "  История %d:  %s / %s (%s)\n", i+1, h.SwitchID, h.Port, ts(h.Timestamp))
	}
	return b.String()
}

// normalizeIP приводит строку к каноническому IPv4-виду (четыре октета через
// «.» без ведущих нулей) и возвращает false, если входная строка не валидный
// IPv4-адрес. Нужен, чтобы ввод пользователя и IP из ARP-таблицы сравнивались
// в одинаковом виде.
func normalizeIP(ip string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return "", false
	}
	var canonical strings.Builder
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		if i > 0 {
			canonical.WriteByte('.')
		}
		canonical.WriteString(strconv.Itoa(n))
	}
	return canonical.String(), true
}

// macToCisco приводит канонический MAC-ключ (12 hex нижнего регистра) к
// cisco-виду «aabb.cc00.1030», как он выводится в `sh arp`/`sh mac
// address-table`. Нужен, чтобы искать MAC в ARP-таблице через
// cisaccs.CisFindArp (он сравнивает без нормализации разделителей).
func macToCisco(key string) string {
	// Ключ должен быть кратен 4 (канонический MAC — 12 hex). Нормальные MAC из
	// ARP-индекса уже валидированы, но resolveArpIP может передать macToKey от
	// «битой» строки из MAC-таблицы (ParseMacLine не валидирует длину), иначе
	// key[i:i+4] упадёт с panic «slice bounds out of range».
	if len(key)%4 != 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(key); i += 4 {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(key[i : i+4])
	}
	return b.String()
}

// arpLineRe парсит строку `sh arp`, повторяя логику cisaccs.ParseArpLine (её
// парсер находится в internal-пакете cisaccs и недоступен из cmacdbs).
var arpLineRe = regexp.MustCompile(`^Internet\s+(\S+)\s+[0-9|-]+\s+(\S+)\s+ARPA\s+(\S+)$`)

// buildArpIpIndex строит индекс «MAC (cisco-вид) → канонический IP» из вывода
// `sh arp` один раз на весь запуск. MAC нормализуется через macToKey/macToCisco,
// чтобы ключ индек совпал с тем, который используется при запросе
// (macToCisco(macKey)). Регулярка компилируется один раз, весь проход — O(N).
func buildArpIpIndex(arpLines []string) map[string]string {
	idx := make(map[string]string, len(arpLines))
	for _, line := range arpLines {
		res := arpLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(res) < 3 || res[2] == "Incomplete" {
			continue
		}
		// MAC-ключ должен быть каноническим (12 hex), иначе macToCisco уйдёт за
		// пределы строки. Неканонические/битые MAC в ARP-таблице привязке не
		// подлежат — запрос всегда приходит в 12-символьном виде.
		key := macToKey(res[2])
		if len(key) != 12 {
			continue
		}
		if ip, ok := normalizeIP(res[1]); ok {
			idx[macToCisco(key)] = ip
		}
	}
	return idx
}

// resolveArpIP возвращает канонический IPv4-адрес для MAC-ключа из заранее
// построенного ARP-индекса (O(1)). Пустая строка, если привязки нет.
func resolveArpIP(arpIpByMac map[string]string, macKey string) string {
	if ip, ok := arpIpByMac[macToCisco(macKey)]; ok {
		return ip
	}
	return ""
}

// macCandidateKeys возвращает формы ключа, в которых один и тот же MAC (в
// каноническом виде — 12 hex без разделителей) теоретически может храниться в
// БД. cisco-нотация группирует по 4 символа: 4cbd.8f73.d94d, тире: 4cbd-8f73-d94d.
// После миграции ключи канонические, поэтому совпадает первая форма; остальное —
// defensive-мера.
func macCandidateKeys(canonical string) []string {
	forms := []string{canonical}
	for _, sep := range []string{".", "-"} {
		var b strings.Builder
		for i := 0; i < len(canonical); i += 4 {
			if i > 0 {
				b.WriteString(sep)
			}
			b.WriteString(canonical[i : i+4])
		}
		forms = append(forms, b.String())
	}
	return forms
}

// normalizeMAC приводит строку к каноническому MAC-ключу (hex, нижний регистр,
// без разделителей — как в ключах БД) и возвращает false, если входная строка
// не похожа на валидный MAC-адрес. Принимаются разделители «:», «-», «» и
// cisco-вид «0011.2233.4455».
func normalizeMAC(mac string) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ':
			return -1
		}
		return r
	}, strings.TrimSpace(mac))
	clean = strings.ToLower(clean)
	if len(clean) != 12 {
		return "", false
	}
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	return clean, true
}

// formatMAC возвращает канонический ключ в человеочитаемом виде 00:11:22:33:44:55.
func formatMAC(key string) string {
	var b strings.Builder
	for i := 0; i+1 < len(key); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(key[i : i+2]))
	}
	return b.String()
}

// ts форматирует временную метку для вывода.
func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func getHostsFile() string {
	if v := cli.CisFileName; v != "" {
		return v
	}
	return "hosts.yaml"
}

func getPasswdFile() string {
	if v := cli.PwdFileName; v != "" {
		return v
	}
	return "groups.yaml"
}

// macToKey приводит MAC к каноническому виду ключа БД: 12 hex-символов нижнего
// регистра без любых разделителей («:», «-», «», пробел).
func macToKey(mac string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ':
			return -1
		}
		return r
	}, strings.ToLower(mac))
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
	// Короткая форма Cisco для Port-Channel — «Po» + номер (Po14, Po1/0/14).
	// Требование цифры после «po» защищает от ложных совпадений (например
	// гипотетические policy…).
	if strings.HasPrefix(li, "po") && len(li) > 2 && li[2] >= '0' && li[2] <= '9' {
		return true
	}
	return false
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

// loadUnfoundMAC возвращает запись из «не найденных» MAC (ноль, если её нет).
func loadUnfoundMAC(macAddr string) (*UnfoundRecord, error) {
	var rec *UnfoundRecord
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(unfoundBucket)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(macToKey(macAddr)))
		if data == nil {
			return nil
		}
		rec = &UnfoundRecord{}
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
		// MAC уже есть — обновляем LastSeen/LastSwitch/LastPort и, если
		// классификация изменилась, Reason/Neighbor (например external -> internal).
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
		if rec.Reason != "" {
			cur.Reason = rec.Reason
		}
		if rec.Neighbor != "" {
			cur.Neighbor = rec.Neighbor
		}
		if rec.IP != "" {
			cur.IP = rec.IP
		}
		data, err := json.Marshal(cur)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

func saveEmptySVI(switchID string, vlanID int, svi cisaccs.IntDescSVI) error {
	if svi.Status != "up" || svi.Protocol != "up" {
		return nil
	}
	key := fmt.Sprintf("%s_%04d", switchID, vlanID)
	rec := SVIRecord{SwitchID: switchID, VlanID: svi.VlanID, Description: svi.Description}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(emptyBucketName)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), data)
	})
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
				NeighborHostname: strings.ToLower(deviceID),
				NeighborDeviceID: deviceID,
				LocalInterface:   localIface,
				RemoteInterface:  remoteIface,
			}
			deviceID = ""
		}
	}
	return result
}
