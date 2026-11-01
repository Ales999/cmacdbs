package main

import (
	"testing"

	"github.com/ales999/cmacdbs/nxthst"
)

// TestFindNextPortbyMacIntegration проверяет, что nxthst резолвит линк-порт
// (и обычный, и Port-Channel) до соседнего хоста, отрезая домен. Опора на
// реальный вывод `sh cdp entry * | i Device|Interface` +
// `sh etherchannel detail | i Group:|Port:`.
func TestFindNextPortbyMacIntegration(t *testing.T) {
	// Switch swA: Po14 -> myswcm36, Po15 -> myswcm37 (Port-Channel, члены —
	// длинные имена), прямой порт -> server1 (с доменом).
	filtered := []string{
		"Group: 14",
		"Port: FiftyGigE2/0/39",
		"Port: FiftyGigE2/0/40",
		"Group: 15",
		"Port: TenGigabitEthernet1/1/4",
		"Port: TenGigabitEthernet1/1/5",
		"Device ID: myswcm36",
		"Interface: FiftyGigE2/0/39,  Port ID (outgoing port): TenGigabitEthernet1/0/2",
		"Device ID: myswcm36",
		"Interface: FiftyGigE2/0/40,  Port ID (outgoing port): TenGigabitEthernet1/0/3",
		"Device ID: myswcm37",
		"Interface: TenGigabitEthernet1/1/4,  Port ID (outgoing port): TenGigabitEthernet2/1/4",
		"Device ID: myswcm37",
		"Interface: TenGigabitEthernet1/1/5,  Port ID (outgoing port): TenGigabitEthernet2/1/5",
		"Device ID: server1.mydomain.internal",
		"Interface: TenGigabitEthernet1/1/9,  Port ID (outgoing port): Ethernet1/33",
	}

	cases := []struct {
		iface     string
		wantFound bool
		wantHost  string
	}{
		{"Po14", true, "myswcm36"},
		{"Port-channel14", true, "myswcm36"},
		{"Po15", true, "myswcm37"},
		{"TenGigabitEthernet1/1/9", true, "server1"},
		{"TenGigabitEthernet1/1/4", true, "myswcm37"},
	}
	for _, c := range cases {
		found, host := nxthst.FindNextPortbyMac(filtered, "swA", *nxthst.NewLocMacLineData("", "", c.iface))
		if found != c.wantFound || host != c.wantHost {
			t.Errorf("iface %q: got found=%v host=%q, want found=%v host=%q", c.iface, found, host, c.wantFound, c.wantHost)
		}
	}
}
