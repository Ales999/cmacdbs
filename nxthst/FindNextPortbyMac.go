package nxthst

import (
	"strings"
)

type LocMacLineData struct {
	vlan  string
	mac   string
	iface string
}

func NewLocMacLineData(
	vlan string,
	mac string,
	iface string,
) *LocMacLineData {

	return &LocMacLineData{
		vlan:  vlan,
		mac:   mac,
		iface: iface,
	}
}

func FindNextPortbyMac(txtlines []string, currhost string, fmi LocMacLineData) (bool, string) {

	// Найденный интерфейс на текущем хосте
	curriface := ConvertLongIfaceName(fmi.iface)

	// Массив структур с данными по CDP
	var cdpinfos []CdpLineData

	// Массив структур с данными по Port-Channel
	var pchinfos []PrtChlInfo
	// Признак что порт соседа указан ка Port-Channel
	var nextpch bool

	// Признак найденного совпадения по CDP
	var cdpmathfound bool

	//fmt.Println("Current host:", currhost)

	//fmt.Println("Test parsing cisco CDP")
	cdpinfos = parsecdp(txtlines)

	if strings.HasPrefix(fmi.iface, "Port-channel") || strings.HasPrefix(fmi.iface, "Po") {
		//fmt.Println("Test parsing cisco Port-Channel")
		pchinfos = parseprtch(txtlines)
		nextpch = true
	}

	// print debug
	//fmt.Println(fmi)
	//fmt.Println(curriface)
	//fmt.Println(cdpinfos)
	//if len(pchinfos) > 0 {
	//fmt.Println("+-+-+-+-+-+-")
	//fmt.Println(pchinfos)
	//}
	//fmt.Println("---=== -------------------- ===---")
	var hstremote string

	var foundmultihost bool // Явно что-то не то, раз много хостов
	if nextpch {
		//fmt.Println("Find ports in PrtCh", curriface)
		for _, pccdpinfo := range pchinfos {
			if strings.EqualFold(ConvertLongIfaceName(fmi.iface), pccdpinfo.GroupID) {
				//fmt.Println(pccdpinfo.GroupPorts)
				for _, cdpinfo := range cdpinfos {
					//hstremote = cdpinfo.Remname
					for _, groupport := range pccdpinfo.GroupPorts {
						if strings.EqualFold(cdpinfo.Locface, groupport) {
							if cdpmathfound {
								if !strings.EqualFold(hstremote, cdpinfo.Remname) {
									foundmultihost = true
								}
							}
							hstremote = cdpinfo.Remname
							//fmt.Println("Next Host", hstremote)
							cdpmathfound = true
						}

					}
				}

			}

		}
		if foundmultihost {
			//fmt.Println("Обнаружена аномалия - много хостов, завершение")
			return false, "Обнаружена аномалия - много хостов, завершение"
		}
	} else { // Если это не Port-Channel, а обычный порт.

		// Бежим по CDP
		for _, cdpinfo := range cdpinfos {
			// print debug
			//fmt.Println(curriface, cdpinfo.Locface)

			if strings.EqualFold(curriface, cdpinfo.Locface) {
				//fmt.Println("Found match", curriface, cdpinfo.Locface)
				//fmt.Println("Next Host:", cdpinfo.Remname)
				hstremote = cdpinfo.Remname
				cdpmathfound = true
				break
			}
		}
		if !cdpmathfound {
			return false, ""
		}

	}
	return true, strings.ToLower(hstremote)

}
