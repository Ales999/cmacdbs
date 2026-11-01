package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ales999/cisaccs/v2"
	"github.com/ales999/cmacdbs/nxthst"
	"go.etcd.io/bbolt"
)

type switchResult struct {
	data SwitchMACData
	err  error
}

// macLocation — где именно (коммутатор + интерфейс) был замечен MAC-адрес.
type macLocation struct {
	switchName string
	iface      string
}

// linkReasonResult — результат классификации линк-MAC: какие порты/хосты
// относятся к внешней (external) и внутренней (internal) категориям.
type linkReasonResult struct {
	isExternal bool
	extLoc     macLocation
	extHost    string
	isInternal bool
	intLoc     macLocation
	intHost    string
}

// sviSeenUpdate — изменение метки видимости MAC на VLAN коммутатора за запуск.
type sviSeenUpdate struct {
	switchID string
	vlanID   int
	hasMac   bool
	now      time.Time
}

// sviEmptyDelete — ключ SVI, который надо убрать из пустых (VLAN снова занят).
type sviEmptyDelete struct {
	switchID string
	vlanID   int
}

func collectFromSwitch(acc *cisaccs.CisAccount, swName string) switchResult {
	debugf("Connecting to switch %s", swName)

	var output1, output2, cdpOut []string
	var err1, err2, err3 error

	output1, err1 = acc.OneCisExecuteSsh(swName, 22, []string{"sh mac address-table"})
	if err1 != nil {
		return switchResult{err: fmt.Errorf("switch %s sh mac address-table: %w", swName, err1)}
	}

	output2, err2 = acc.OneCisExecuteSsh(swName, 22, []string{"sh int description | b ^Vl"})
	if err2 != nil {
		return switchResult{err: fmt.Errorf("switch %s sh int description: %w", swName, err2)}
	}

	// CDP (filtered) + etherchannel — отдаётся вместе, так как nxthst
	// FindNextPortbyMac парсит и CDP, и группы Port-Channel из одного массива.
	cdpOut, err3 = acc.OneCisExecuteSsh(swName, 22, []string{"sh etherchannel detail | i Group:|Port:", "sh cdp entry * | i Device|Interface"})
	if err3 != nil {
		return switchResult{err: fmt.Errorf("switch %s sh cdp/etherchannel: %w", swName, err3)}
	}

	parsedMacs := cisaccs.CisGetAllMacEntries(output1)
	sviList := cisaccs.ParseIntDescSVI(output2)
	cdpMap := parseCDPNeighbors(cdpOut)

	return switchResult{
		data: SwitchMACData{
			SwitchName:   swName,
			MACs:         parsedMacs,
			SVIs:         sviList,
			CDPNeighbors: cdpMap,
			CDPLines:     cdpOut,
		},
	}
}

// linkMACReason классифицирует MAC, который виден только на линк-портах (без
// конечной точки на access-порту). Возвращает, ведёт ли хотя бы один линк за
// пределами управляемой области (external) и/или в управляемую область
// (internal — маршрутизатор, где sh mac пуст, или устройство, от которого не
// смогли получить данные). Для каждого случая возвращается первый подходящий
// порт. Если портов нет — оба флага остаются false.
func linkMACReason(linkLocs []macLocation, cdpLinesBySwitch map[string][]string, hostNamesSet map[string]bool) linkReasonResult {
	var res linkReasonResult
	var debugCount int
	cache := make(map[string]bool)
	isManaged := func(loc macLocation) (bool, string) {
		key := loc.switchName + "|" + loc.iface
		if v, ok := cache[key]; ok {
			return v, ""
		}
		found, remote := nxthst.FindNextPortbyMac(cdpLinesBySwitch[loc.switchName], nxthst.NewLocMacLineData("", "", loc.iface))
		managed := found && hostNamesSet[strings.ToLower(remote)]
		if debugCount < 15 {
			debugf("link-only %s/%s -> CDP found=%v host=%q managed=%v", loc.switchName, loc.iface, found, remote, managed)
			debugCount++
		}
		cache[key] = managed
		return managed, remote
	}
	for _, loc := range linkLocs {
		managed, remote := isManaged(loc)
		if managed {
			if !res.isInternal {
				res.isInternal = true
				res.intLoc = loc
				res.intHost = remote
			}
		} else if !res.isExternal {
			res.isExternal = true
			res.extLoc = loc
			res.extHost = remote
		}
	}
	return res
}

func collectDataAndSave() {
	scanMu.Lock()
	if isScanning {
		fmt.Println("Already scanning, skipping.")
		scanMu.Unlock()
		return
	}
	isScanning = true
	scanMu.Unlock()
	defer func() {
		scanMu.Lock()
		isScanning = false
		scanMu.Unlock()
	}()

	cisFile := getHostsFile()
	pwdFile := getPasswdFile()

	acc := cisaccs.NewCisAccount(cisFile, pwdFile)

	allHostsData, err := acc.GetHostsDataByHostName()
	if err != nil {
		log.Printf("Warning: could not load hosts data: %v", err)
	}

	hostNamesSet := make(map[string]bool)
	for _, h := range allHostsData {
		hostNamesSet[strings.ToLower(h.NameDev)] = true
	}

	var (
		mu           sync.Mutex
		allCollected []SwitchMACData
		visited      = make(map[string]bool)
		queue        []string
		emptySVIs    []struct {
			switchID string
			vlanID   int
			svi      cisaccs.IntDescSVI
		}
		discoveredManaged = make(map[string]bool)
		sviSeenUpdates    []sviSeenUpdate
		emptySVIDeletes   []sviEmptyDelete
	)

	for _, sw := range rootSwitches {
		visited[strings.ToLower(sw)] = true
		queue = append(queue, strings.ToLower(sw))
	}

	for len(queue) > 0 {
		var batchWg sync.WaitGroup
		currentBatch := queue
		queue = nil

		resultCh := make(chan switchResult, len(currentBatch))

		for _, swNameRaw := range currentBatch {
			swName := swNameRaw
			batchWg.Add(1)
			go func(name string) {
				defer batchWg.Done()
				resultCh <- collectFromSwitch(acc, name)
			}(swName)
		}

		batchWg.Wait()
		close(resultCh)

		var batchNewQueue []string
		for res := range resultCh {
			if res.err != nil {
				log.Printf("Error collecting from switch: %v", res.err)
				continue
			}
			mu.Lock()
			allCollected = append(allCollected, res.data)

			vlansWithMacs := vlanSet(res.data.MACs)
			for _, sv := range res.data.SVIs {
				if sv.Status != "up" || sv.Protocol != "up" {
					continue
				}
				now := time.Now()
				if vlansWithMacs[sv.VlanID] {
					// VLAN занят динамическим MAC — обновляем метку видимости и
					// убираем SVI из пустых, если был помечен.
					sviSeenUpdates = append(sviSeenUpdates, sviSeenUpdate{switchID: res.data.SwitchName, vlanID: sv.VlanID, hasMac: true, now: now})
					emptySVIDeletes = append(emptySVIDeletes, sviEmptyDelete{switchID: res.data.SwitchName, vlanID: sv.VlanID})
				} else {
					// Кандидат в пустые: метка видимости, время первого наблюдения.
					sviSeenUpdates = append(sviSeenUpdates, sviSeenUpdate{switchID: res.data.SwitchName, vlanID: sv.VlanID, hasMac: false, now: now})
					emptySVIs = append(emptySVIs, struct {
						switchID string
						vlanID   int
						svi      cisaccs.IntDescSVI
					}{switchID: res.data.SwitchName, vlanID: sv.VlanID, svi: sv})
				}
			}

			for _, neighbor := range res.data.CDPNeighbors {
				nh := strings.ToLower(neighbor.NeighborHostname)
				if !visited[nh] && hostNamesSet[nh] {
					visited[nh] = true
					batchNewQueue = append(batchNewQueue, nh)
					discoveredManaged[nh] = true
					debugf("Discovered downstream switch %s via CDP on %s (%s)", nh, res.data.SwitchName, neighbor.LocalInterface)
				}
			}
			mu.Unlock()
		}

		queue = batchNewQueue
	}

	// Применяем метки видимости MAC по VLAN единым транктом (из BFS).
	if err := applySVISeenUpdates(sviSeenUpdates); err != nil {
		log.Printf("Error applying SVI seen tracking: %v", err)
	}

	// Помечаем пустыми только те SVI, что без MAC уже больше месяца.
	var confirmedEmpty int
	for _, e := range emptySVIs {
		if !sviIsEmptyConfirmed(e.switchID, e.vlanID, time.Now()) {
			continue
		}
		if err := saveEmptySVI(e.switchID, e.vlanID, e.svi); err != nil {
			log.Printf("Error saving empty SVI: %v", err)
			continue
		}
		confirmedEmpty++
	}
	// Убираем из пустых VLAN, которые вновь заняты динамическим MAC.
	for _, d := range emptySVIDeletes {
		if err := deleteEmptySVI(d.switchID, d.vlanID); err != nil {
			log.Printf("Error deleting empty SVI: %v", err)
		}
	}

	var totalMacs int
	var newCount, changeCount, unchangedCount int

	// Deterministic order: sort collected data by switch name so that the "first"
	// switch seen for a given MAC is stable across runs (avoids nondeterministic
	// trunk-duplicate churn).
	sort.Slice(allCollected, func(i, j int) bool {
		if allCollected[i].SwitchName == allCollected[j].SwitchName {
			return false
		}
		return allCollected[i].SwitchName < allCollected[j].SwitchName
	})

	// Индекс CDP+etherchannel по коммутаторам: switch -> линии вывода. Нужен
	// для резолвинга линк-портов до соседнего хоста через nxthst.
	cdpLinesBySwitch := make(map[string][]string)
	for _, data := range allCollected {
		cdpLinesBySwitch[data.SwitchName] = data.CDPLines
	}

	// First pass: собрать все локации (switch, порт) для каждого MAC.
	type macInfo struct {
		locations []macLocation
		switchSet map[string]bool
	}
	macInfos := make(map[string]*macInfo)
	for _, data := range allCollected {
		for _, m := range data.MACs {
			// Ключ нормализуем через macToKey (нижний регистр, без любых
			// разделителей — «:», «-», «», пробел), иначе один и тот же MAC в
			// разных форматах на разных платформах (4500 — 0e55.6c89.a819,
			// 9k/9500 — f4339234d502) посчитается за два разных.
			macAddr := macToKey(m.GetMac())
			loc := macLocation{switchName: data.SwitchName, iface: m.GetIface()}
			info, exists := macInfos[macAddr]
			if !exists {
				macInfos[macAddr] = &macInfo{
					locations: []macLocation{loc},
					switchSet: map[string]bool{data.SwitchName: true},
				}
			} else {
				info.locations = append(info.locations, loc)
				info.switchSet[data.SwitchName] = true
			}
		}
	}

	// Second pass: классификация каждого уникального MAC.
	type updateEntry struct {
		macAddr string
		record  MacRecord
	}
	var updates []updateEntry

	macAddrs := make([]string, 0, len(macInfos))
	for macAddr := range macInfos {
		macAddrs = append(macAddrs, macAddr)
	}
	sort.Strings(macAddrs)

	var unfoundCount int
	var internalCount int

	for _, macAddr := range macAddrs {
		info := macInfos[macAddr]
		totalMacs++

		// Ищем конечную точку — первый MAC на access-порту. Оставшиеся локации
		// — линк-порты (ведут к другому коммутатору/устройству).
		var endpoint *macLocation
		var linkLocs []macLocation
		for i := range info.locations {
			loc := info.locations[i]
			if portIsLink(loc.iface) {
				linkLocs = append(linkLocs, loc)
			} else {
				endpoint = &info.locations[i]
				break
			}
		}

		if endpoint != nil {
			// MAC найден: конечная точка на access-порту. Записываем в MacHistory.
			existing, _ := loadMacRecord(macAddr)
			newVisit := Visit{
				SwitchID:  endpoint.switchName,
				Port:      endpoint.iface,
				Timestamp: time.Now(),
			}
			if existing.MacAddress != "" && strings.EqualFold(existing.Current.SwitchID, endpoint.switchName) && strings.EqualFold(existing.Current.Port, endpoint.iface) {
				unchangedCount++
			} else if existing.MacAddress != "" {
				if len(existing.History) >= 3 {
					existing.History = existing.History[:2]
				}
				existing.History = append([]Visit{existing.Current}, existing.History...)
				changeCount++
			} else {
				newCount++
			}
			existing.MacAddress = macAddr
			existing.Current = newVisit
			updates = append(updates, updateEntry{macAddr: macAddr, record: *existing})
		} else {
			// Конечной точки нет — все локация на линк-портах. Резолвим каждый
			// порт через CDP: если линк ведет в управляемую область (сосед в
			// hosts.yaml) — это internal (роутер/устройство без данных), иначе
			// external — за пределами сети.
			reason := linkMACReason(linkLocs, cdpLinesBySwitch, hostNamesSet)
			if reason.isExternal {
				unfoundCount++
				if err := saveUnfoundMAC(macAddr, UnfoundRecord{
					MacAddress: macAddr,
					LastSwitch: reason.extLoc.switchName,
					LastPort:   reason.extLoc.iface,
					Neighbor:   reason.extHost,
					Reason:     "external",
					LastSeen:   time.Now(),
				}); err != nil {
					log.Printf("Error saving unfound MAC %s: %v", macAddr, err)
				}
			} else if reason.isInternal {
				internalCount++
				if err := saveUnfoundMAC(macAddr, UnfoundRecord{
					MacAddress: macAddr,
					LastSwitch: reason.intLoc.switchName,
					LastPort:   reason.intLoc.iface,
					Neighbor:   reason.intHost,
					Reason:     "internal",
					LastSeen:   time.Now(),
				}); err != nil {
					log.Printf("Error saving internal MAC %s: %v", macAddr, err)
				}
			}
		}
	}

	// Batch write all updates in one transaction
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		for _, u := range updates {
			data, _ := json.Marshal(u.record)
			if err := b.Put([]byte(macToKey(u.macAddr)), data); err != nil {
				log.Printf("Error saving MAC %s: %v", u.macAddr, err)
			}
		}
		return nil
	}); err != nil {
		log.Printf("Error batch writing MAC records: %v", err)
	}

	// Топология: снимок CDP-соседей каждого коммутатора (перезаписывается).
	scannedSet := make(map[string]bool, len(allCollected))
	for _, d := range allCollected {
		scannedSet[d.SwitchName] = true
		if err := saveTopologySwitch(buildTopology(d, hostNamesSet)); err != nil {
			log.Printf("Error saving topology for %s: %v", d.SwitchName, err)
		}
	}
	// В управляемую область считаем и сканируемые, и объявленные соседями в CDP.
	knownNow := make(map[string]bool, len(scannedSet)+len(discoveredManaged))
	for k := range scannedSet {
		knownNow[k] = true
	}
	for k := range discoveredManaged {
		knownNow[k] = true
	}
	if err := reconcileTopology(knownNow); err != nil {
		log.Printf("Error reconciling topology: %v", err)
	}

	fmt.Printf("\n=== MAC Collection Summary ===\n")
	fmt.Printf("Switches collected: %d\n", len(allCollected))
	var totalParsed int
	for _, d := range allCollected {
		totalParsed += len(d.MACs)
	}
	fmt.Printf("Total parsed MAC entries (all switches): %d\n", totalParsed)
	fmt.Printf("Unique MACs found: %d\n", totalMacs)
	fmt.Printf("Empty SVIs candidate (empty <%dd): %d\n", emptySVIDays, len(emptySVIs))
	fmt.Printf("Empty SVIs confirmed (empty >%dd): %d\n", emptySVIDays, confirmedEmpty)
	fmt.Printf("New MACs: %d\n", newCount)
	fmt.Printf("Changed MACs: %d\n", changeCount)
	fmt.Printf("Unchanged MACs: %d\n", unchangedCount)
	fmt.Printf("Unfound MACs (link leads outside): %d\n", unfoundCount)
	fmt.Printf("Internal/interface MACs (port not found): %d\n", internalCount)
	if len(emptySVIs) > 0 {
		fmt.Printf("---\nEmpty SVIs (no MACs):\n")
		for _, s := range emptySVIs {
			fmt.Printf("  %s - %s\n", s.switchID, s.svi.Interface)
		}
	}
}
