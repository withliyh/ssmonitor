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
	if _, err := ss.iptables.EnsureRule(iptablesApi.Append, iptablesApi.TableFilter, SS_IN_RULES, []string{"-j", string(SS_IN_RULES)}...); err != nil {
		return err
	}
	if _, err := ss.iptables.EnsureRule(iptablesApi.Append, iptablesApi.TableFilter, SS_OUT_RULES, []string{"-j", string(SS_OUT_RULES)}...); err != nil {
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
	re1 := regexp.MustCompile("tcp spt:[\\d]+")
	re2 := regexp.MustCompile("[\\s]+") //以空白字符分割字符串

	parts := strings.Split(string(out), "destination")

	if parts == nil || len(parts) != 2 {
		return fmt.Errorf("port info bytes parse error.\n")
	}
	lines := re1.Split(parts[1], -1)
	lines = lines[:len(lines)-1]
	ports := re1.FindAllString(parts[1], -1)

	if len(lines) != len(ports) {
		return fmt.Errorf("port info line count not equ port line count.")
	}

	for i, line := range lines {
		fieldSlice := re2.Split(line, -1)
		portStr := strings.Split(ports[i], ":")[1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("can't conver %s to a number.", portStr)
		}

		user := ss.ports[port]
		if user != nil {
			user.Bytes = fieldSlice[1]
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
