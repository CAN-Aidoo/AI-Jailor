package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type account struct {
	uid, gid uint32
	home     string
	groups   []uint32
}

// lookupUser parses /etc/passwd and /etc/group directly. os/user would need cgo,
// and we ship a static, cgo-free binary.
func lookupUser(name, passwdPath, groupPath string) (*account, error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var acc *account
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 6 || p[0] != name {
			continue
		}
		uid, e1 := strconv.ParseUint(p[2], 10, 32)
		gid, e2 := strconv.ParseUint(p[3], 10, 32)
		if e1 != nil || e2 != nil {
			return nil, fmt.Errorf("malformed passwd entry for %q", name)
		}
		acc = &account{uid: uint32(uid), gid: uint32(gid), home: p[5]}
		break
	}
	if acc == nil {
		return nil, fmt.Errorf("unknown user %q", name)
	}
	acc.groups = []uint32{acc.gid}
	if g, err := os.Open(groupPath); err == nil {
		defer g.Close()
		gs := bufio.NewScanner(g)
		for gs.Scan() {
			p := strings.Split(gs.Text(), ":")
			if len(p) < 4 {
				continue
			}
			for _, m := range strings.Split(p[3], ",") {
				if m == name {
					if id, err := strconv.ParseUint(p[2], 10, 32); err == nil && uint32(id) != acc.gid {
						acc.groups = append(acc.groups, uint32(id))
					}
				}
			}
		}
	}
	return acc, nil
}
