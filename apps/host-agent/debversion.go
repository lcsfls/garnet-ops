package main

// Debian versions compared as dpkg does (deb-version(7)); the same algorithm as compareDebVersions in @garnetops/core/deb-version,
// tested against the same pairs.

import (
	"strconv"
	"strings"
)

func splitDebVersion(v string) (epoch int, upstream, revision string, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, "", "", false
	}
	if before, after, found := strings.Cut(v, ":"); found {
		n, err := strconv.Atoi(before)
		if err != nil || n < 0 || len(before) > 9 {
			return 0, "", "", false
		}
		epoch, v = n, after
	}
	upstream = v
	if at := strings.LastIndex(v, "-"); at != -1 {
		upstream, revision = v[:at], v[at+1:]
	}
	if upstream == "" || upstream[0] < '0' || upstream[0] > '9' {
		return 0, "", "", false
	}
	return epoch, upstream, revision, true
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// charAt is the byte at i, or 0 past the end.
func charAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func debOrder(c byte) int {
	switch {
	case c == 0 || isDigit(c):
		return 0
	case isLetter(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's comparison of an upstream version or a revision.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(charAt(a, i)), debOrder(charAt(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for charAt(a, i) == '0' {
			i++
		}
		for charAt(b, j) == '0' {
			j++
		}
		for isDigit(charAt(a, i)) && isDigit(charAt(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(charAt(a, i)) {
			return 1
		}
		if isDigit(charAt(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// CompareDebVersions is negative if a is older than b, positive if newer, 0 if equal. Text that is not a version sorts first.
func CompareDebVersions(a, b string) int {
	ea, ua, ra, okA := splitDebVersion(a)
	eb, ub, rb, okB := splitDebVersion(b)
	if !okA || !okB {
		x, y := 0, 0
		if okA {
			x = 1
		}
		if okB {
			y = 1
		}
		return x - y
	}
	if ea != eb {
		return ea - eb
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}
