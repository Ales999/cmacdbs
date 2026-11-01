package nxthst

import (
	"strings"
)

type PrtChlInfo struct {
	GroupID    string
	GroupPorts []string
}

func NewPrtChlInfo(groupid string, ports []string) PrtChlInfo {
	return PrtChlInfo{
		GroupID:    groupid,
		GroupPorts: ports,
	}
}

// parseprtch - Парсинг Port-Channel
//
// Парсим строки при выполнение команды 'sh etherchannel detail | i Group:|Port:'
// на cisco
func parseprtch(txtlines []string) []PrtChlInfo {
	var ret []PrtChlInfo

	/**
	// "sh etherchannel detail | i Group:|Port:"
	Group: 1
	Port: Twe1/0/1
	Port: Twe2/0/1
	Group: 15
	Port: Twe1/0/15
	Port: Twe2/0/15
	Group: 16
	Port: Twe1/0/16
	Port: Twe2/0/16
	Group: 17
	Port: Twe1/0/17
	Port: Twe1/0/18
	Port: Twe2/0/17
	Port: Twe2/0/18
	Group: 19
	Port: Twe1/0/19
	Port: Twe1/0/20
	Port: Twe2/0/19
	Port: Twe2/0/20
	*/
	for n, line := range txtlines {
		if len(line) == 0 {
			continue
		}

		if strings.HasPrefix(line, "Group:") {

			cuttingGroupByTree := strings.FieldsFunc(line, func(r rune) bool {
				return r == ' '
			})

			var tmpgrprts []string // группа портов в данном ether-channel

			// Выбираем остатки что еще не сканировали в отдельный слайс (только следующие 20 строк)
			var tlsts []string
			if len(txtlines[n+1:]) > 16 { // Если осталось в файле больше 16 строк то берем только 15 строк
				tlsts = txtlines[n+1 : n+15]
			} else {
				tlsts = txtlines[n+1:]
			}
			// Ищем порты
			for _, plst := range tlsts {
				if !strings.HasPrefix(plst, "Port:") {
					break
				}
				// Парсим строку - разложим по частям
				cuttingPortsByTree := strings.FieldsFunc(plst, func(r rune) bool {
					return r == ' '
				})

				tmpgrprts = append(tmpgrprts, ConvertLongIfaceName(cuttingPortsByTree[1]))

			}

			//print debug
			//fmt.Println(cuttingGroupByTree[1], tmpgrprts)

			ret = append(ret, NewPrtChlInfo("Po"+cuttingGroupByTree[1], tmpgrprts))

		}

	}

	return ret

}
