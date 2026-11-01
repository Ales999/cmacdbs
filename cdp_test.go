package main

import (
	"reflect"
	"strings"
	"testing"
)

func splitLines(s string) []string { return strings.Split(s, "\n") }

const swTmsCore01CDP = `Device ID: Tmscore01.domain.test
Entry address(es): 
  IP address: 172.22.59.38
Platform: cisco WS-C2960X-48FPD-L,  Capabilities: Switch IGMP 
Interface: FiftyGigE2/0/39,  Port ID (outgoing port): TenGigabitEthernet1/0/2
Holdtime : 175 sec

Version :
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E13, RELEASE SOFTWARE (fc3)

advertisement version: 2
Peer Source MAC: a4b2.39a5.1334
VTP Management Domain: 'SWT'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 172.22.59.38

-------------------------
Device ID: Tmscore01.domain.test
Entry address(es): 
  IP address: 172.22.59.38
Platform: cisco WS-C2960X-48FPD-L,  Capabilities: Switch IGMP 
Interface: FiftyGigE1/0/39,  Port ID (outgoing port): TenGigabitEthernet1/0/1
Holdtime : 159 sec

advertisement version: 2
Peer Source MAC: a4b2.39a5.1333
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 172.22.59.38

-------------------------
Device ID: Tmscore02.domain.test
Entry address(es): 
  IP address: 172.22.59.9
Platform: cisco C9200L-48PL-4X,  Capabilities: Switch IGMP 
Interface: FiftyGigE1/0/8,  Port ID (outgoing port): TenGigabitEthernet1/1/4
Holdtime : 129 sec

advertisement version: 2
Peer Source MAC: d085.43f4.5ab4
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 172.22.59.9
`

const swDcm4500CDP = `Device ID: 0050568d209a
Entry address(es): 
  IP address: 172.24.25.150
Platform: Cisco-VM-SPID,  Capabilities: Host 
Interface: TenGigabitEthernet1/1/13,  Port ID (outgoing port): eth0
Holdtime : 179 sec

advertisement version: 2
Unidirectional Mode: off

-------------------------
Device ID: myswcm36.domain.test
Entry address(es): 
  IP address: 172.24.32.17
Platform: cisco WS-C3650-8X24UQ,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet2/1/25,  Port ID (outgoing port): TenGigabitEthernet1/1/4
Holdtime : 160 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 172.24.32.17
Unidirectional Mode: off

-------------------------
Device ID: myswcm36.domain.test
Entry address(es): 
  IP address: 172.24.32.17
Platform: cisco WS-C3650-8X24UQ,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet1/1/25,  Port ID (outgoing port): TenGigabitEthernet2/1/4
Holdtime : 155 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 172.24.32.17
Unidirectional Mode: off

-------------------------
Device ID: myswcm37
Entry address(es): 
  IP address: 192.168.9.150
Platform: cisco WS-C3750X-48,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet1/1/24,  Port ID (outgoing port): TenGigabitEthernet1/1/2
Holdtime : 169 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 192.168.9.150
Unidirectional Mode: off

-------------------------
Device ID: myswcm37
Entry address(es): 
  IP address: 192.168.9.150
Platform: cisco WS-C3750X-48,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet2/1/24,  Port ID (outgoing port): TenGigabitEthernet2/1/2
Holdtime : 166 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 192.168.9.150
Unidirectional Mode: off
`

const swDcm4500ExtCDP = `Device ID: myswcm45.domain.test
Entry address(es): 
  IP address: 192.168.3.253
Platform: cisco WS-C4500X-32,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet1/1/27,  Port ID (outgoing port): TenGigabitEthernet1/1/15
Holdtime : 129 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 192.168.3.253
Unidirectional Mode: off

-------------------------
Device ID: myswcm45.domain.test
Entry address(es): 
  IP address: 192.168.3.253
Platform: cisco WS-C4500X-32,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet2/1/28,  Port ID (outgoing port): TenGigabitEthernet2/1/4
Holdtime : 145 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 192.168.3.253
Unidirectional Mode: off

-------------------------
Device ID: myswcm45.domain.test
Entry address(es): 
  IP address: 192.168.3.253
Platform: cisco WS-C4500X-32,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet2/1/27,  Port ID (outgoing port): TenGigabitEthernet1/2/8
Holdtime : 170 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 192.168.3.253
Unidirectional Mode: off

-------------------------
Device ID: myswcm45.domain.test
Entry address(es): 
  IP address: 192.168.3.253
Platform: cisco WS-C4500X-32,  Capabilities: Router Switch IGMP 
Interface: TenGigabitEthernet1/1/28,  Port ID (outgoing port): TenGigabitEthernet2/2/8
Holdtime : 171 sec

advertisement version: 2
VTP Management Domain: 'DCM-Core'
Native VLAN: 1
Duplex: full
Management address(es): 
  IP address: 192.168.3.253
Unidirectional Mode: off
`

func TestParseCDPNeighborsMultiLink(t *testing.T) {
	got := parseCDPNeighbors(splitLines(swTmsCore01CDP))
	want := map[string]CDPNeighbor{
		"FiftyGigE2/0/39": {NeighborHostname: "tmscore01", NeighborDeviceID: "Tmscore01", LocalInterface: "FiftyGigE2/0/39", RemoteInterface: "TenGigabitEthernet1/0/2"},
		"FiftyGigE1/0/39": {NeighborHostname: "tmscore01", NeighborDeviceID: "Tmscore01", LocalInterface: "FiftyGigE1/0/39", RemoteInterface: "TenGigabitEthernet1/0/1"},
		"FiftyGigE1/0/8":  {NeighborHostname: "tmscore02", NeighborDeviceID: "Tmscore02", LocalInterface: "FiftyGigE1/0/8", RemoteInterface: "TenGigabitEthernet1/1/4"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestParseCDPNeighborsMixedTopology(t *testing.T) {
	got := parseCDPNeighbors(splitLines(swDcm4500CDP))
	want := map[string]CDPNeighbor{
		"TenGigabitEthernet1/1/13": {NeighborHostname: "0050568d209a", NeighborDeviceID: "0050568d209a", LocalInterface: "TenGigabitEthernet1/1/13", RemoteInterface: "eth0"},
		"TenGigabitEthernet2/1/25": {NeighborHostname: "myswcm36", NeighborDeviceID: "myswcm36", LocalInterface: "TenGigabitEthernet2/1/25", RemoteInterface: "TenGigabitEthernet1/1/4"},
		"TenGigabitEthernet1/1/25": {NeighborHostname: "myswcm36", NeighborDeviceID: "myswcm36", LocalInterface: "TenGigabitEthernet1/1/25", RemoteInterface: "TenGigabitEthernet2/1/4"},
		"TenGigabitEthernet1/1/24": {NeighborHostname: "myswcm37", NeighborDeviceID: "myswcm37", LocalInterface: "TenGigabitEthernet1/1/24", RemoteInterface: "TenGigabitEthernet1/1/2"},
		"TenGigabitEthernet2/1/24": {NeighborHostname: "myswcm37", NeighborDeviceID: "myswcm37", LocalInterface: "TenGigabitEthernet2/1/24", RemoteInterface: "TenGigabitEthernet2/1/2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestParseCDPNeighborsTrunkBundle(t *testing.T) {
	got := parseCDPNeighbors(splitLines(swDcm4500ExtCDP))
	if len(got) != 4 {
		t.Fatalf("expected 4 link entries, got %d: %v", len(got), got)
	}
	for _, iface := range []string{
		"TenGigabitEthernet1/1/27",
		"TenGigabitEthernet2/1/28",
		"TenGigabitEthernet2/1/27",
		"TenGigabitEthernet1/1/28",
	} {
		nb, ok := got[iface]
		if !ok {
			t.Errorf("missing interface %q in %v", iface, got)
			continue
		}
		if nb.NeighborHostname != "myswcm45" {
			t.Errorf("%s neighbor = %q, want myswcm45", iface, nb.NeighborHostname)
		}
	}
}

func TestParseCDPNeighborsEmpty(t *testing.T) {
	got := parseCDPNeighbors(nil)
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

// cdpLinesPlain — минимальные CDP-линии (sh cdp entry * | i Device|Interface)
// для обычных портов. FindNextPortbyMac резолвит их без etherchannel.
func cdpLinesPlain(entries [][2]string) []string {
	var out []string
	for _, e := range entries {
		out = append(out, "Device ID: "+e[0], "Interface: "+e[1]+",  Port ID (outgoing port): TenGigabitEthernet1/0/1")
	}
	return out
}

func TestLinkMACReason(t *testing.T) {
	managed := map[string]bool{"myswcm36": true, "myswcm37": true}

	t.Run("all managed -> internal", func(t *testing.T) {
		links := []macLocation{
			{switchName: "swA", iface: "TenGigabitEthernet1/1/1"},
			{switchName: "swA", iface: "TenGigabitEthernet1/1/2"},
		}
		cdp := map[string][]string{
			"swA": cdpLinesPlain([][2]string{
				{"myswcm36", "TenGigabitEthernet1/1/1"},
				{"myswcm37", "TenGigabitEthernet1/1/2"},
			}),
		}
		res := linkMACReason(links, cdp, managed)
		if res.isExternal || !res.isInternal {
			t.Errorf("want internal only, got ext=%v internal=%v", res.isExternal, res.isInternal)
		}
		if res.intLoc.iface != "TenGigabitEthernet1/1/1" {
			t.Errorf("want first internal port, got %v", res.intLoc.iface)
		}
		if res.intHost != "myswcm36" {
			t.Errorf("want internal host myswcm36, got %q", res.intHost)
		}
	})

	t.Run("all external -> external", func(t *testing.T) {
		links := []macLocation{{switchName: "swA", iface: "TenGigabitEthernet1/1/9"}}
		cdp := map[string][]string{
			"swA": cdpLinesPlain([][2]string{{"server1.test", "TenGigabitEthernet1/1/9"}}),
		}
		res := linkMACReason(links, cdp, managed)
		if !res.isExternal || res.isInternal {
			t.Errorf("want external only, got ext=%v internal=%v", res.isExternal, res.isInternal)
		}
		if res.extLoc.iface != "TenGigabitEthernet1/1/9" {
			t.Errorf("want external port, got %v", res.extLoc.iface)
		}
		if res.extHost != "server1" {
			t.Errorf("want external host server1 (domain stripped), got %q", res.extHost)
		}
	})

	t.Run("no CDP entry -> external", func(t *testing.T) {
		links := []macLocation{{switchName: "swA", iface: "TenGigabitEthernet1/1/1"}}
		cdp := map[string][]string{"swA": nil}
		res := linkMACReason(links, cdp, managed)
		if !res.isExternal || res.isInternal {
			t.Errorf("missing CDP should be external, got ext=%v internal=%v", res.isExternal, res.isInternal)
		}
		if res.extLoc.iface != "TenGigabitEthernet1/1/1" {
			t.Errorf("want external port, got %v", res.extLoc.iface)
		}
	})

	t.Run("mixed -> first of each", func(t *testing.T) {
		links := []macLocation{
			{switchName: "swA", iface: "TenGigabitEthernet1/1/1"}, // managed (internal)
			{switchName: "swA", iface: "TenGigabitEthernet1/1/2"}, // external
			{switchName: "swA", iface: "TenGigabitEthernet1/1/3"}, // managed
		}
		cdp := map[string][]string{
			"swA": cdpLinesPlain([][2]string{
				{"myswcm36", "TenGigabitEthernet1/1/1"},
				{"server1.test", "TenGigabitEthernet1/1/2"},
				{"myswcm37", "TenGigabitEthernet1/1/3"},
			}),
		}
		res := linkMACReason(links, cdp, managed)
		if !res.isExternal || !res.isInternal {
			t.Errorf("want both, got ext=%v internal=%v", res.isExternal, res.isInternal)
		}
		if res.extLoc.iface != "TenGigabitEthernet1/1/2" || res.intLoc.iface != "TenGigabitEthernet1/1/1" {
			t.Errorf("want ext=.../2 internal=.../1, got ext=%v internal=%v", res.extLoc.iface, res.intLoc.iface)
		}
	})

	t.Run("empty -> neither", func(t *testing.T) {
		res := linkMACReason(nil, nil, managed)
		if res.isExternal || res.isInternal {
			t.Errorf("want all false, got ext=%v internal=%v", res.isExternal, res.isInternal)
		}
	})
}
