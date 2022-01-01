//
// Copyright 2020-2021 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

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
	fmt.Printf("using %v from %v\n", socketAddress, host)
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
	fmt.Printf("using %v from %v\n", socketAddress, host)
	// use socket address

	host = ipaddr.NewHostName(hostAddressStr)
	address := host.AsAddress() // does not resolve
	fmt.Printf("using %v from %v\n", address, host)
	// use address

	host = ipaddr.NewHostName(dnsStr)
	address, err := host.ToAddress() // resolves if necessary
	if err == nil {
		fmt.Printf("using %v from %v\n", address, host)
		// use address
	}
}
