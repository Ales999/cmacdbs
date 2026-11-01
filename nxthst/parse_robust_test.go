package nxthst

import "testing"

// TestParseRobustNoPanic проверяет, что «битые» строки вывода коммутатора не
// роняют парсер паникой (index out of range) — см. REVIEW.md п.2.
func TestParseRobustNoPanic(t *testing.T) {
	// Device ID короче 3 полей + Interface без полного набора полей.
	if got := parsecdp([]string{"Device ID:", "Interface: X, Port ID (outgoing port): Y"}); got != nil {
		t.Errorf("parsecdp short id = %v, want nil", got)
	}
	// Interface-строка с недостаточным числом полей.
	if got := parsecdp([]string{"Device ID: h", "Interface: X"}); got != nil {
		t.Errorf("parsecdp short iface = %v, want nil", got)
	}
	// parseCdpLine напрямую: короткий id.
	if d := parseCdpLine("Device ID:", "Interface: a, Port ID (outgoing port): b"); d != (CdpLineData{}) {
		t.Errorf("parseCdpLine short id = %v, want zero", d)
	}
	// parseCdpLine напрямую: короткая ifaces-line (<7 полей).
	if d := parseCdpLine("Device ID: h", "Interface: a"); d != (CdpLineData{}) {
		t.Errorf("parseCdpLine short iface = %v, want zero", d)
	}

	// Group без номера и Port без порта.
	if got := parseprtch([]string{"Group:", "Port:"}); got != nil {
		t.Errorf("parseprtch malformed = %v, want nil", got)
	}

	// Device ID в последней строке (иначе txtlines[n:n+2] ушёл бы за пределы).
	if got := parsecdp([]string{"Device ID: last"}); got != nil {
		t.Errorf("parsecdp trailing Device ID = %v, want nil", got)
	}

	// FindNextPortbyMac на пустом/битом вводе не должен паниковать.
	FindNextPortbyMac(nil, NewLocMacLineData("", "", "Gi0/1"))
	FindNextPortbyMac([]string{"garbage"}, NewLocMacLineData("", "", "Po99"))
}
