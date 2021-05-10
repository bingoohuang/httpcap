package main

import "net"

// Iface defines
type Iface struct {
	Name     string
	Loopback bool
}

// ListIfaces lists the host's interfaces.
func ListIfaces() map[string]Iface {
	m := make(map[string]Iface)

	ifaces, err := net.Interfaces()
	if err != nil {
		return m
	}

	for _, f := range ifaces {
		if f.Flags&net.FlagUp != net.FlagUp {
			continue
		}
		m[f.Name] = Iface{
			Name:     f.Name,
			Loopback: f.Flags&net.FlagLoopback == net.FlagLoopback,
		}
	}

	return m
}
