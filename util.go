package main

import (
	"log"
	"strconv"
	"strings"
)

// Split splits the string s to slices with trimmed and empty ignored.
func Split(s string) (ret []string) {
	for _, sub := range strings.Split(s, ",") {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			ret = append(ret, sub)
		}
	}

	return ret
}

// SplitInt splits the string s to int slices with trimmed and empty ignored.
func SplitInt(s string) (ret []int) {
	for _, sub := range Split(s) {
		v, err := strconv.Atoi(sub)
		if err != nil {
			log.Fatalf("E! %s is invalid", sub)
		}
		ret = append(ret, v)
	}

	return ret
}
