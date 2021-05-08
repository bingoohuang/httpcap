package main

import "net"

type Iface struct {
	Name     string
	Loopback bool
}

func ListIfaces() map[string]Iface {
	m := make(map[string]Iface)

	ifaces, err := net.Interfaces()
	if err != nil {
		return m
	}

	for _, f := range ifaces {
		if f.Flags&net.FlagUp == 0 {
			continue
		}
		m[f.Name] = Iface{
			Name:     f.Name,
			Loopback: f.Flags&net.FlagLoopback == net.FlagLoopback,
		}
	}

	return m
}
