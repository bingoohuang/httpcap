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

// SliceItem returns the element of ss slice at index if index is valid, or defaultValue returned.
func SliceItem(ss []string, index int, defaultValue string) string {
	if index < len(ss) {
		return ss[index]
	}

	return defaultValue
}
