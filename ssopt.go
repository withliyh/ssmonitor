package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	iptablesApi "github.com/withliyh/ssmonitor/iptables"
	"github.com/withliyh/ssmonitor/utilexec"
)

type Interface interface {
	InitIptChains() error
	DelIptChains() error
	AddMonitorPort(port int, name string) error
	DelMonitorPort(port int) error
	ShowPortInfo(port int) (string, error)
	ShowAllPortInfo() map[int]*SSUserInfo
	ParsePortInfo() error
}
type SSMonitor struct {
	ports    map[int]*SSUserInfo
	iptables iptablesApi.Interface
}

type RuleInfo struct {
	pkts        string
	bytes       string
	target      string
	proto       string
	opt         string
	in          string
	out         string
	source      string
	destination string
	port        int
}

type SSUserInfo struct {
	Port  int
	Name  string
	Bytes string
}

func (user *SSUserInfo) String() string {
	return fmt.Sprint("%d \t %s \t %s\n", user.Port, user.Name, user.Bytes)
}

const (
	SS_IN_RULES  iptablesApi.Chain = "SS_IN_RULES"
	SS_OUT_RULES iptablesApi.Chain = "SS_OUT_RULES"
)

func New() Interface {
	ss := &SSMonitor{
		ports:    make(map[int]*SSUserInfo),
		iptables: iptablesApi.New(utilexec.New(), iptablesApi.ProtocolIpv4),
	}
	return ss
}

func (ss *SSMonitor) InitIptChains() error {
	if _, err := ss.iptables.EnsureChain(iptablesApi.TableFilter, SS_IN_RULES); err != nil {
		return err
	}
	if _, err := ss.iptables.EnsureChain(iptablesApi.TableFilter, SS_OUT_RULES); err != nil {
		return err
	}
	if _, err := ss.iptables.EnsureRule(iptablesApi.Append, iptablesApi.TableFilter, iptablesApi.ChainInput, []string{"-j", string(SS_IN_RULES)}...); err != nil {
		return err
	}
	if _, err := ss.iptables.EnsureRule(iptablesApi.Append, iptablesApi.TableFilter, iptablesApi.ChainOutput, []string{"-j", string(SS_OUT_RULES)}...); err != nil {
		return err
	}
	return nil
}

func (ss *SSMonitor) DelIptChains() error {
	if err := ss.iptables.FlushChain(iptablesApi.TableFilter, SS_IN_RULES); err != nil {
		return err
	}
	if err := ss.iptables.FlushChain(iptablesApi.TableFilter, SS_OUT_RULES); err != nil {
		return err
	}
	if err := ss.iptables.DeleteRule(iptablesApi.TableFilter, SS_IN_RULES, []string{"-j", string(SS_IN_RULES)}...); err != nil {
		return err
	}
	if err := ss.iptables.DeleteRule(iptablesApi.TableFilter, SS_OUT_RULES, []string{"-j", string(SS_OUT_RULES)}...); err != nil {
		return err
	}
	if err := ss.iptables.DeleteChain(iptablesApi.TableFilter, SS_IN_RULES); err != nil {
		return err
	}
	if err := ss.iptables.DeleteChain(iptablesApi.TableFilter, SS_OUT_RULES); err != nil {
		return err
	}
	return nil
}

func (ss *SSMonitor) AddMonitorPort(port int, name string) error {
	user := &SSUserInfo{
		Port:  port,
		Name:  name,
		Bytes: "",
	}
	ss.ports[port] = user
	if _, err := ss.iptables.EnsureRule(iptablesApi.Append, iptablesApi.TableFilter, SS_IN_RULES,
		[]string{"-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}...); err != nil {
		return err
	}
	if _, err := ss.iptables.EnsureRule(iptablesApi.Append, iptablesApi.TableFilter, SS_OUT_RULES,
		[]string{"-p", "tcp", "--sport", strconv.Itoa(port), "-j", "ACCEPT"}...); err != nil {
		return err
	}
	return nil
}

func (ss *SSMonitor) DelMonitorPort(port int) error {
	delete(ss.ports, port)
	if err := ss.iptables.DeleteRule(iptablesApi.TableFilter, SS_OUT_RULES,
		[]string{"-p", "tcp", "--sport", strconv.Itoa(port), "-j", "ACCEPT"}...); err != nil {
		return err
	}
	if err := ss.iptables.DeleteRule(iptablesApi.TableFilter, SS_OUT_RULES,
		[]string{"-p", "tcp", "--sport", strconv.Itoa(port), "-j", "ACCEPT"}...); err != nil {
		return err
	}
	return nil
}

func (ss *SSMonitor) ParsePortInfo() error {
	out, err := ss.iptables.ListChainRules(iptablesApi.TableFilter, SS_OUT_RULES, []string{"-nv"}...)
	if err != nil {
		return err
	}

	result, err := parse(out)
	if err != nil {
		return err
	}
	for k, v := range ss.ports {
		item, ok := result[k]
		if ok {
			v.Bytes = item.bytes
		}
	}

	return nil
}
func (ss *SSMonitor) ShowPortInfo(port int) (string, error) {
	user, ok := ss.ports[port]
	if !ok {
		return "", fmt.Errorf("can't port info :%d", port)
	}
	return user.Bytes, nil
}

func (ss *SSMonitor) ShowAllPortInfo() map[int]*SSUserInfo {
	return ss.ports
}

func parse(out []byte) (map[int]*RuleInfo, error) {
	result := make(map[int]*RuleInfo)
	parts := strings.Split(string(out), "destination")
	lines := strings.Split(parts[1], "\n")
	lines = lines[1 : len(lines)-1]
	re := regexp.MustCompile("[\\s]+")
	for _, line := range lines {
		fields := re.Split(line, -1)
		if strings.TrimSpace(fields[0]) == "" {
			fields = fields[1:]
		}
		if len(fields) != 11 {
			for i, e := range fields {
				fmt.Printf("%d \t\t %s\n", i, e)
			}
			fmt.Println()
			return nil, fmt.Errorf("split fields count error:%s", line)
		}
		if "tcp" != fields[3] {
			continue
		}
		idx := strings.Index(fields[10], ":")
		if idx < 0 {
			return nil, fmt.Errorf("no find split token in :%s\n", fields[10])
		}
		portParts := []byte(fields[10])[idx+1:]
		port, err := strconv.Atoi(string(portParts))
		if err != nil {
			return nil, fmt.Errorf(err.Error())
		}

		rule := &RuleInfo{}

		rule.pkts = fields[0]
		rule.bytes = fields[1]
		rule.opt = fields[2]
		rule.proto = fields[3]
		rule.target = fields[4]
		rule.in = fields[5]
		rule.out = fields[6]
		rule.source = fields[7]
		rule.destination = fields[8]
		rule.port = port
		result[port] = rule
	}
	return result, nil
}
