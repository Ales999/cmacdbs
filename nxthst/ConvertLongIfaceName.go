package nxthst

import (
	"regexp"
	"strings"
)

// Компилируем паттерны один раз — функция вызывается очень часто.
var (
	rePortChannel = regexp.MustCompile(`^(Po)rt-channel(\d+)`)
	reTwe         = regexp.MustCompile(`^(\S{3})\D+(\d\S+)`)
	reShort       = regexp.MustCompile(`^(\S{2})\D+(\d\S+)`)
)

// ConvertLongIfaceName - Convert long iface name to simple
//
// @Example:
//
// TenGigabitEthernet2/3/4 --> Ten2/3/4
// Port-channel14 --> Po14
func ConvertLongIfaceName(ifacename string) string {
	// Convert TwentyFiveGigE2/0/18 --> Twe2/0/18
	// TenGigabitEthernet1/1/3 --> Te1/1/3
	// GigabitEthernet1/0/9 --> Gi1/0/9

	var re *regexp.Regexp
	switch {
	case strings.HasPrefix(ifacename, "Port-channel"):
		re = rePortChannel
	case strings.HasPrefix(ifacename, "Twe"): // Using in cisco 9500 // TODO: нужна более стабильная проверка формата именования.
		re = reTwe
	default:
		re = reShort
	}

	// Выполняем парсинг
	res := re.FindStringSubmatch(ifacename)
	// Если успешен - то его и возвращяем
	if len(res) > 0 {
		return res[1] + res[2]
	}

	// Иначе возвращаем без изменений
	return ifacename
}
