package main

import (
	"flag"
	"fmt"

	"github.com/golang/glog"
)

func main() {
	flag.Parse()
	defer glog.Flush()
	monitor := New()
	err := monitor.InitIptChains()
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8387, "liyang")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8388, "fuyuanliang")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8389, "chenzhilin")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8390, "chenshitao")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8391, "xulingshan")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8392, "jinghuijun")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8393, "zhengyangjie")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	err = monitor.AddMonitorPort(8394, "zhenglinggeng")
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}

	err = monitor.ParsePortInfo()
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}

	portInfos := monitor.ShowAllPortInfo()
	for _, user := range portInfos {
		fmt.Printf("Port:%d\tBytes:%s\t\tUser:%s\n", user.Port, user.Bytes, user.Name)
	}

}
