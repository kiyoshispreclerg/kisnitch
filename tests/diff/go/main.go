// SPDX-License-Identifier: GPL-3.0-or-later
//
// Evaluates the differential corpus with upstream's rule package and writes
// one "<id> <result>" line per case. tests/diff/ks_diff.c does the same with
// Kisnitch; tests/diff/run.sh compares both outputs.
//
// Usage (from the repository root): go run ./tests/diff/go corpus.json out.txt
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/netstat"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
)

type jProcess struct {
	PID       int               `json:"pid"`
	Path      string            `json:"path"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	Checksums map[string]string `json:"checksums"`
	Parent    *jProcess         `json:"parent"`
}

type jConn struct {
	Protocol string    `json:"protocol"`
	DstHost  string    `json:"dst_host"`
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	SrcPort  uint      `json:"src_port"`
	DstPort  uint      `json:"dst_port"`
	IfaceIn  int       `json:"iface_in"`
	IfaceOut int       `json:"iface_out"`
	UID      int       `json:"uid"`
	Process  *jProcess `json:"process"`
}

type jCase struct {
	ID           string          `json:"id"`
	Conn         string          `json:"conn"`
	HasChecksums bool            `json:"has_checksums"`
	Path         *string         `json:"path"`
	Operator     json.RawMessage `json:"operator"`
}

type jRuleset struct {
	ID    string            `json:"id"`
	Conn  string            `json:"conn"`
	Rules []json.RawMessage `json:"rules"`
}

type jBattery struct {
	Conn     string   `json:"conn"`
	Patterns []string `json:"patterns"`
	Subjects []string `json:"subjects"`
}

type corpus struct {
	Aliases      string           `json:"aliases"`
	Conns        map[string]jConn `json:"conns"`
	Cases        []jCase          `json:"cases"`
	Rulesets     []jRuleset       `json:"rulesets"`
	RegexBattery jBattery         `json:"regex_battery"`
}

func mkProc(j *jProcess) *procmon.Process {
	if j == nil {
		return nil
	}
	p := procmon.NewProcessEmpty(j.PID, "")
	p.Path = j.Path
	if j.Args != nil {
		p.Args = j.Args
	}
	for k, v := range j.Env {
		p.Env[k] = v
	}
	for k, v := range j.Checksums {
		p.Checksums[k] = v
	}
	p.Parent = mkProc(j.Parent)
	return p
}

func mkConn(j jConn, path *string) *conman.Connection {
	c := &conman.Connection{
		Protocol: j.Protocol,
		DstHost:  j.DstHost,
		SrcIP:    net.ParseIP(j.SrcIP),
		DstIP:    net.ParseIP(j.DstIP),
		SrcPort:  j.SrcPort,
		DstPort:  j.DstPort,
		Entry:    &netstat.Entry{UserId: j.UID},
		Pkt:      &netfilter.Packet{IfaceInIdx: j.IfaceIn, IfaceOutIdx: j.IfaceOut},
		Process:  mkProc(j.Process),
	}
	if c.Process == nil {
		// Upstream never evaluates rules without a process.
		c.Process = procmon.NewProcessEmpty(0, "")
	}
	if path != nil {
		c.Process.Path = *path
	}
	return c
}

func usesLists(o *rule.Operator) bool {
	if o.Type == rule.Lists {
		return true
	}
	for i := range o.List {
		if o.List[i].Type == rule.Lists {
			return true
		}
	}
	return false
}

// evalOperator mirrors what the loader does with a rule's operator.
func evalOperator(raw []byte, conn *conman.Connection, hasChecksums bool) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = "panic"
		}
	}()
	var op rule.Operator
	if err := json.Unmarshal(raw, &op); err != nil {
		return "parse-error"
	}
	if err := op.Compile(); err != nil {
		return "compile-error"
	}
	if op.Type == rule.List {
		for i := range op.List {
			if err := op.List[i].Compile(); err != nil {
				return "compile-error"
			}
		}
	}
	if usesLists(&op) {
		// Lists are loaded by a goroutine.
		time.Sleep(300 * time.Millisecond)
	}
	if op.Match(conn, hasChecksums) {
		return "match"
	}
	return "nomatch"
}

func evalRuleset(rs jRuleset, conn *conman.Connection) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = "panic"
		}
	}()
	dir, err := os.MkdirTemp("", "ksdiff")
	if err != nil {
		return "tmpdir-error"
	}
	defer os.RemoveAll(dir)
	for i, r := range rs.Rules {
		name := filepath.Join(dir, fmt.Sprintf("%03d.json", i))
		if err := os.WriteFile(name, r, 0600); err != nil {
			return "write-error"
		}
	}
	l, err := rule.NewLoader(false)
	if err != nil {
		return "loader-error"
	}
	if err := l.Load(dir); err != nil {
		return "load-error"
	}
	m := l.FindFirstMatch(conn)
	name := "<nil>"
	if m != nil {
		name = m.Name
	}
	return name + " n=" + strconv.Itoa(l.NumRules())
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: diff corpus.json out.txt")
		os.Exit(2)
	}
	log.SetLogLevel(100) // silence upstream's logging on stdout

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := rule.LoadAliases(c.Aliases); err != nil {
		fmt.Fprintln(os.Stderr, "aliases:", err)
		os.Exit(1)
	}

	f, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	w := bufio.NewWriter(f)
	defer f.Close()
	defer w.Flush()

	for _, k := range c.Cases {
		conn := mkConn(c.Conns[k.Conn], k.Path)
		fmt.Fprintf(w, "%s %s\n", k.ID, evalOperator(k.Operator, conn, k.HasChecksums))
	}
	b := c.RegexBattery
	for pi, pattern := range b.Patterns {
		for si, subject := range b.Subjects {
			for _, sens := range []bool{true, false} {
				op, _ := json.Marshal(map[string]interface{}{
					"type": "regexp", "operand": "process.path", "data": pattern,
					"sensitive": sens,
				})
				s := subject
				conn := mkConn(c.Conns[b.Conn], &s)
				tag := "i"
				if sens {
					tag = "s"
				}
				fmt.Fprintf(w, "re-%d-%d-%s %s\n", pi, si, tag, evalOperator(op, conn, false))
			}
		}
	}
	for _, rs := range c.Rulesets {
		conn := mkConn(c.Conns[rs.Conn], nil)
		fmt.Fprintf(w, "%s %s\n", rs.ID, evalRuleset(rs, conn))
	}
}
