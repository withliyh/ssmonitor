package iptables

import (
	"testing"

	"github.com/withliyh/iptables/utilexec"
)

func TestGetVersion(t *testing.T) {
	iptablesApi := New(utilexec.New(), ProtocolIpv4)
	version, err := iptablesApi.GetVersion()
	if err != nil {
		t.Errorf(err.Error())
	}
	if version != "1.4.1" {
		t.Errorf("get version :%s,but corrent version is 1.4.21", version)
	}

}
