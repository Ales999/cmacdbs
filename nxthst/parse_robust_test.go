package nxthst

import (
	"fmt"
	"testing"
)

// TestParseprtchLargeBundle проверяет, что Port-Channel с числом членов больше
// старой границы среза (14) парсится целиком, без потери портов — см. REVIEW.md п.8.
func TestParseprtchLargeBundle(t *testing.T) {
	const n = 20
	lines := []string{"Group: 99"}
	for i := 1; i <= n; i++ {
		lines = append(lines, fmt.Sprintf("Port: TenGigabitEthernet1/0/%d", i))
	}
	// Следующая группа — опора, на которой парсер должен остановиться.
	lines = append(lines, "Group: 100", "Port: TenGigabitEthernet1/0/99")

	got := parseprtch(lines)
	if len(got) != 2 {
		t.Fatalf("expected 2 groups, got %d: %v", len(got), got)
	}
	if got[0].GroupID != "Po99" {
		t.Errorf("group id = %q, want Po99", got[0].GroupID)
	}
	if len(got[0].GroupPorts) != n {
		t.Errorf("expected %d ports in Po99, got %d: %v", n, len(got[0].GroupPorts), got[0].GroupPorts)
	}
}

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
