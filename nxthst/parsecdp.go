package nxthst

import (
	"regexp"
	"strings"
)

type CdpLineData struct {
	Remname string
	Locface string
	Remface string
}

func NewCdpLineData(remname string, locface string, remface string) *CdpLineData {
	return &CdpLineData{
		Remname: remname,
		Locface: locface,
		Remface: remface,
	}

}

// parsecdp - парсинг CDP данных, команда: `sh cdp entry * | i Device|Interface`
func parsecdp(txtlines []string) []CdpLineData {

	var ret []CdpLineData

	for n, line := range txtlines {
		if len(line) == 0 {
			continue
		}

		if strings.HasPrefix(line, "Device ID") {

			// Созданим новый срез из текущей и следующей строки
			tlsts := txtlines[n : n+2]

			if len(tlsts) > 1 && strings.HasPrefix(tlsts[1], "Interface:") && strings.Contains(tlsts[1], "outgoing port") {
				cdpinfo := parseCdpLine(line, tlsts[1])

				// print debug
				//fmt.Println(cdpinfo.Remname, cdpinfo.Locface, cdpinfo.Remface)

				ret = append(ret, cdpinfo)
			}

		}

	}
	return ret
}

func parseCdpLine(idline string, ifacesline string) CdpLineData {

	/*

		cmds = append(cmds, "sh cdp entry * | i  Device|Interface")

		Device ID: CORE9500.local.ru
		Interface: TenGigabitEthernet2/3/4,  Port ID (outgoing port): TwentyFiveGigE1/0/15
		Device ID: ucsmgmtx-B.ocs.ru(FDO23260JDG)
		Interface: TenGigabitEthernet1/1/2,  Port ID (outgoing port): Ethernet1/33
	*/

	var hostname string

	// Парсим строку DeviceID - разложим по частям
	cuttingIdLine := strings.FieldsFunc(idline, func(r rune) bool {
		return r == ' '
	})
	if len(cuttingIdLine[2]) == 0 {
		return CdpLineData{}
	}

	hostname = cuttingIdLine[2]

	// Если имя хоста содержит скобки с серийным номером (output cisco nexus this)
	if strings.ContainsRune(hostname, '(') && strings.ContainsRune(hostname, ')') {
		// Example: nexus5548_1(SDI15620DSC) --> nexus5548_1
		re, _ := regexp.Compile(`^([^(]+)(\(\S+)$`)
		res := re.FindStringSubmatch(hostname)
		if len(res) > 0 {
			hostname = res[1]
		}
	}

	// Уберем домен если есть, оставим только имя хоста.
	if strings.Contains(hostname, ".") {
		cuttingOnlyName := strings.FieldsFunc(hostname, func(r rune) bool {
			return r == '.'
		})
		hostname = cuttingOnlyName[0]
	}

	// Парсим строку Interfaces - разложим по частям
	cuttingIfaces := strings.FieldsFunc(ifacesline, func(r rune) bool {
		return r == ' '
	})
	// Удалим последнюю запятую из имени локального интерфейса, если она есть.
	var lociface = strings.TrimSuffix(cuttingIfaces[1], ",") //  TrimEndSuffix(cuttingIfaces[1], ",")

	return *NewCdpLineData(hostname, ConvertLongIfaceName(lociface), ConvertLongIfaceName(cuttingIfaces[6]))

}
