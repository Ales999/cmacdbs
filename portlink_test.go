package main

import "testing"

func TestPortIsLink(t *testing.T) {
	cases := []struct {
		iface string
		want  bool
	}{
		{"Po14", true},
		{"Port-channel14", true},
		{"Po1/0/14", true},
		{"Eth-Trunk5", true},
		{"Bundle-Ether1", true},
		{"Gi0/1", false},
		{"TenGigabitEthernet1/0/13", false},
		{"Ethernet1/33", false},
		{"Vl166", false},
		{"", false},
	}
	for _, c := range cases {
		if got := portIsLink(c.iface); got != c.want {
			t.Errorf("portIsLink(%q) = %v, want %v", c.iface, got, c.want)
		}
	}
}
