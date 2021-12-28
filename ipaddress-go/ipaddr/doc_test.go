package ipaddr_test

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
)

func Example_address() {
	ipv6Str := "a:b:c:d::a:b/64"
	ipv6AddrStr := ipaddr.NewIPAddressString(ipv6Str)
	if ipAddr, err := ipv6AddrStr.ToAddress(); err != nil {
		// handle improperly formatted host name or address string
		fmt.Println("parse error: " + err.Error())
	} else {
		// use the address
		fmt.Printf("%v is in CIDR prefix block %v", ipAddr, ipAddr.ToPrefixBlock())
	}
	// Output: a:b:c:d::a:b/64 is in CIDR prefix block a:b:c:d::/64
}

func Example_host() {
	hostPortStr := "[a:b:c:d:e:f:a:b]:8080"
	hostServiceStr := "a.b.com:service"
	hostAddressStr := "1.2.3.4"
	dnsStr := "a.b.com"

	host := ipaddr.NewHostName(hostPortStr)
	socketAddress := host.ToNetTCPAddr()
	fmt.Println("using %v from %v", socketAddress, host)
	// use socket address

	host = ipaddr.NewHostName(hostServiceStr)
	socketAddress = host.ToNetTCPAddrService(func(service string) ipaddr.Port {
		switch service {
		case "service":
			res := ipaddr.PortNum(100)
			return &res
		}
		return nil
	})
	fmt.Println("using %v from %v", socketAddress, host)
	// use socket address

	host = ipaddr.NewHostName(hostAddressStr)
	address := host.AsAddress() // does not resolve
	fmt.Println("using %v from %v", address, host)
	// use address

	host = ipaddr.NewHostName(dnsStr)
	address, err := host.ToAddress() // resolves if necessary
	if err == nil {
		fmt.Println("using %v from %v", address, host)
		// use address
	}
}
