//
// Copyright 2020-2022 Sean C Foley
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

package test

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstrparam"
)

type OrderingSupplier func(string, int) *Ordering
type OrderingComparator func(one, two *Ordering) int

var (
	orderingOpts    = new(addrstrparam.IPAddressStringParamsBuilder).AllowAll(true).SetRangeParams(addrstrparam.WildcardAndRange).ParseEmptyStrAs(addrstrparam.NoAddressOption).GetIPv6AddressParamsBuilder().AllowZone(false).GetParentBuilder().ToParams()
	macOrderingOpts = new(addrstrparam.MACAddressStringParamsBuilder).AllowAll(true).AllowEmpty(true).SetRangeParams(addrstrparam.WildcardAndRange).ToParams()
)

type addressOrderTest struct {
	testBase
}

func (t addressOrderTest) run() {
	t.testOrder()
}

func (t addressOrderTest) testOrder() {

	ipAddressOrderingSupplier := func(str string, i int) *Ordering {
		addr := t.createParamsAddress(str, orderingOpts).GetAddress()
		if addr != nil {
			return &Ordering{
				nestedType: addr.ToAddressBase(),
				order:      i,
			}
		}
		return nil
	}
	macAddressOrderingSupplier := func(str string, i int) *Ordering {
		addr := t.createMACParamsAddress(str, macOrderingOpts).GetAddress()
		if addr != nil {
			return &Ordering{
				nestedType: addr.ToAddressBase(),
				order:      i,
			}
		}
		return nil
	}
	ipaddressStringOrderingSupplier := func(str string, i int) *Ordering {
		return &Ordering{
			nestedIPAddrString: ipaddr.NewIPAddressStringParams(str, orderingOpts),
			order:              i,
		}
	}
	macaddressStringOrderingSupplier := func(str string, i int) *Ordering {
		return &Ordering{
			nestedMACAddrString: ipaddr.NewMACAddressStringParams(str, macOrderingOpts),
			order:               i,
		}
	}
	nilOrderingSupplier := func(str string, i int) *Ordering {
		return nil
	}
	t.testDefaultOrder(ipaddressStringOrderingSupplier, nilOrderingSupplier) //cannot remember if there is a reason why we do this one twice

	lowValComparator := ipaddr.LowValueComparator
	ipAddressLowValComparator := func(one, two *Ordering) int {
		result := lowValComparator.Compare(one.nestedType, two.nestedType)
		return result
	}
	ipAddressStringLowValComparator := func(one, two *Ordering) int {
		var result int
		oneAddr := one.nestedIPAddrString.GetAddress()
		twoAddr := two.nestedIPAddrString.GetAddress()
		if oneAddr != nil && twoAddr != nil {
			result = lowValComparator.Compare(oneAddr, twoAddr)
		} else {
			result = one.nestedIPAddrString.Compare(two.nestedIPAddrString)
		}
		return result
	}
	macAddressStringLowValComparator := func(one, two *Ordering) int {
		var result int
		oneAddr := one.nestedMACAddrString.GetAddress()
		twoAddr := two.nestedMACAddrString.GetAddress()
		if oneAddr != nil && twoAddr != nil {
			result = lowValComparator.Compare(oneAddr, twoAddr)
		} else {
			result = one.nestedMACAddrString.Compare(two.nestedMACAddrString)
		}
		return result
	}

	t.testLowValueOrder(ipAddressStringLowValComparator, ipaddressStringOrderingSupplier, nilOrderingSupplier)
	t.testLowValueOrder(macAddressStringLowValComparator, nilOrderingSupplier, macaddressStringOrderingSupplier)
	t.testLowValueOrder(ipAddressLowValComparator, ipAddressOrderingSupplier, macAddressOrderingSupplier)

	highValComparator := ipaddr.HighValueComparator

	ipAddressHighValComparator := func(one, two *Ordering) int {
		result := highValComparator.Compare(one.nestedType, two.nestedType)
		return result
	}
	ipAddressStringHighValComparator := func(one, two *Ordering) int {
		var result int
		oneAddr := one.nestedIPAddrString.GetAddress()
		twoAddr := two.nestedIPAddrString.GetAddress()
		if oneAddr != nil && twoAddr != nil {
			result = highValComparator.Compare(oneAddr, twoAddr)
		} else {
			result = one.nestedIPAddrString.Compare(two.nestedIPAddrString)
		}
		return result
	}
	macAddressStringHighValComparator := func(one, two *Ordering) int {
		var result int
		oneAddr := one.nestedMACAddrString.GetAddress()
		twoAddr := two.nestedMACAddrString.GetAddress()
		if oneAddr != nil && twoAddr != nil {
			result = highValComparator.Compare(oneAddr, twoAddr)
		} else {
			result = one.nestedMACAddrString.Compare(two.nestedMACAddrString)
		}
		return result
	}
	t.testHighValueOrder(ipAddressStringHighValComparator, ipaddressStringOrderingSupplier, nilOrderingSupplier)
	t.testHighValueOrder(macAddressStringHighValComparator, nilOrderingSupplier, macaddressStringOrderingSupplier)
	t.testHighValueOrder(ipAddressHighValComparator, ipAddressOrderingSupplier, macAddressOrderingSupplier)

	t.testDefaultOrder(ipaddressStringOrderingSupplier, nilOrderingSupplier)
	t.testDefaultOrder(nilOrderingSupplier, macaddressStringOrderingSupplier)
	t.testDefaultOrder(ipAddressOrderingSupplier, macAddressOrderingSupplier)
}

type Ordering struct {
	nestedType          *ipaddr.Address
	nestedIPAddrString  *ipaddr.IPAddressString
	nestedMACAddrString *ipaddr.MACAddressString

	order int
}

func (o *Ordering) getDescription() string {
	if o.nestedIPAddrString != nil {
		return fmt.Sprintf("(expected index %d) %v", o.order, o.nestedIPAddrString)
	} else if o.nestedMACAddrString != nil {
		return fmt.Sprintf("(expected index %d) %v", o.order, o.nestedMACAddrString)
	}
	return fmt.Sprintf("(expected index %d) %v", o.order, o.nestedType)
}

func (o *Ordering) CompareTo(other *Ordering) int {
	var result int
	if o.nestedIPAddrString != nil {
		result = o.nestedIPAddrString.Compare(other.nestedIPAddrString)
	} else if o.nestedMACAddrString != nil {
		result = o.nestedMACAddrString.Compare(other.nestedMACAddrString)
	} else {
		result = o.nestedType.Compare(other.nestedType)
	}
	return result
}

// The default order goes by count first, and then the count of the more significant segment followed by the lower value magnitude in the same segment.
func (t addressOrderTest) testDefaultOrder(ipAddressSupplier, macAddressSupplier OrderingSupplier) {

	var ordering []*Ordering
	//invalid
	strs := []string{ //these are already sorted by natural string ordering
		"/129", //invalid prefix
		"bla",
		"fo",
		"foo",
		"four",
		"xxx",
	}

	//order is INVALID, EMPTY, IPV4, IPV6, ALL
	orderNumber := 0

	for _, s := range strs {
		ordering = append(ordering, ipAddressSupplier(s, orderNumber))
		ordering = append(ordering, macAddressSupplier(s, orderNumber))
		orderNumber++
	}

	//empty
	ordering = append(ordering, macAddressSupplier("", orderNumber))
	ordering = append(ordering, macAddressSupplier("  ", orderNumber))
	ordering = append(ordering, macAddressSupplier("     ", orderNumber))
	ordering = append(ordering, macAddressSupplier("", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:0:0:0", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("1:00:00:2:03:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("01:00:00:02:03:04", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:0:0:fe:ff:fe", orderNumber))
	orderNumber++
	ordering = append(ordering, macAddressSupplier("ff:0:0:fe:ff:ff", orderNumber))
	orderNumber++
	ordering = append(ordering, macAddressSupplier("ff:0:0:ff:ff:fe", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:0:0:ff:ff:ff", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:ff:ff:ff:ff:ff", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("a1:f0:2:3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3-4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:2:1-3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:f0-ff:2:3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:*:2:03:4:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("01:*:02:03:04:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0-7f:2:3:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0-ff:*:*:*:8", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:0:0:*:*:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("*:0:0:*:%*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:a:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("0-1:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:*:*:*:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("0:0:0:0:0:0:0:1", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:0:0:0:0:0", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:ff:ff:ff:ff:ff:ff:ff", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:*:*:*:*:*:*", orderNumber))
	orderNumber++

	//empty
	ordering = append(ordering, ipAddressSupplier("", orderNumber))
	ordering = append(ordering, ipAddressSupplier("  ", orderNumber))
	ordering = append(ordering, ipAddressSupplier("     ", orderNumber))
	ordering = append(ordering, ipAddressSupplier("", orderNumber))
	orderNumber++

	//a bunch of address and prefixes
	ordering = append(ordering, ipAddressSupplier("1.0.0.0", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.3.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.2.003.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.2.3.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("001.002.003.004", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("255.254.255.254", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("255.254.255.255", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("255.255.255.254", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("255.255.255.255", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.3.*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.002.3.*/31", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.*.*/17", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.002.*.*/16", orderNumber))

	ordering = append(ordering, ipAddressSupplier("1.002.0.0/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("001.002.000.000/16", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.2.000.0/15", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.2.0.0/15", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*.*.1-3.*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*.*.*.*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*.*.%*.*", orderNumber))
	orderNumber++

	// ipv6

	ordering = append(ordering, ipAddressSupplier("1::", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:3:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:003:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("0001:0000::0002:0003:0004", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff::fffe:ffff:fffe", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::fffe:ffff:ffff", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::ffff:ffff:fffe", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::ffff:ffff:ffff", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:3:*/127", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:*/111", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1::2:1-3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*::*:*:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*::*:%*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1:0:*/31", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*::*:*:*:*:*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::/17", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1:8000::/17", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("a1:8000::/17", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1::/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("0001::/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1:*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*:*:a:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("2::/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*:*:*:*:*:*:*:*/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*:*:*:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("**", orderNumber))
	ordering = append(ordering, ipAddressSupplier(" *", orderNumber))
	ordering = append(ordering, ipAddressSupplier("%%", orderNumber))
	orderNumber++

	t.checkOrdering(ordering, orderNumber, nil)
}

func (t addressOrderTest) testHighValueOrder(comparator OrderingComparator, ipAddressSupplier, macAddressSupplier OrderingSupplier) {

	var ordering []*Ordering

	//order is INVALID, EMPTY, IPV4, IPV6, ALL
	orderNumber := 0

	//invalid
	strs := []string{ //these are already sorted by natural string ordering
		"/129", //invalid prefix
		"bla",
		"fo",
		"foo",
		"four",
		"xxx",
	}
	for _, s := range strs {
		ordering = append(ordering, ipAddressSupplier(s, orderNumber))
		ordering = append(ordering, macAddressSupplier(s, orderNumber))
		orderNumber++
	}

	//empty
	ordering = append(ordering, macAddressSupplier("", orderNumber))
	ordering = append(ordering, macAddressSupplier("  ", orderNumber))
	ordering = append(ordering, macAddressSupplier("     ", orderNumber))
	ordering = append(ordering, macAddressSupplier("", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:0:0:0", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("1:00:00:2:03:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("01:00:00:02:03:04", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3-4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:2:1-3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0-7f:2:3:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:*:2:03:4:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("01:*:02:03:04:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:f0-ff:2:3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0-ff:*:*:*:8", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("0-1:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("a1:f0:2:3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:0:0:fe:ff:fe", orderNumber))
	orderNumber++
	ordering = append(ordering, macAddressSupplier("ff:0:0:fe:ff:ff", orderNumber))
	orderNumber++
	ordering = append(ordering, macAddressSupplier("ff:0:0:ff:ff:fe", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:0:0:*:*:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("*:0:0:*:%*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:0:0:ff:ff:ff", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:a:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:*:*:*:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:ff:ff:ff:ff:ff", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("0:0:0:0:0:0:0:1", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:0:0:0:0:0", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:*:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:ff:ff:ff:ff:ff:ff:ff", orderNumber))
	orderNumber++

	//empty

	ordering = append(ordering, ipAddressSupplier("", orderNumber))
	ordering = append(ordering, ipAddressSupplier("  ", orderNumber))
	ordering = append(ordering, ipAddressSupplier("     ", orderNumber))
	ordering = append(ordering, ipAddressSupplier("", orderNumber))
	orderNumber++

	//a bunch of address

	ordering = append(ordering, ipAddressSupplier("1.0.0.0", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.0.*/17", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.3.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.2.003.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.2.3.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("001.002.003.004", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.3.*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.002.3.*/31", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1.002.0.0/17", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.002.0-127.*/17", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1.002.0.0/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("001.002.000.000/16", orderNumber))

	ordering = append(ordering, ipAddressSupplier("1.002.*.*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.2.000.0/15", orderNumber))

	ordering = append(ordering, ipAddressSupplier("1.2-3.*.*/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("255.254.255.254", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("255.254.255.255", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*.*.1-3.*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("255.255.255.254", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*.*.*.*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*.*.%*.*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("255.255.255.255", orderNumber))
	orderNumber++

	// IPv6

	ordering = append(ordering, ipAddressSupplier("1::", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::*/31", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::*/17", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:2:*/111", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1::2:3:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:003:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("0001:0000::0002:0003:0004", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1::2:2-3:*/111", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:2:0/111", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:3:*/127", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:1-3:4:*", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1:0-1:*/31", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1::/17", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1:0-7fff:*:*/17", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("0001:0000::0000:0000:0000/16", orderNumber))

	ordering = append(ordering, ipAddressSupplier("1:*/17", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1:*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1:8000::/17", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("2:*/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("2::/15", orderNumber))
	ordering = append(ordering, ipAddressSupplier("2-3:*/15", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("a1:8000::/17", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff::fffe:ffff:fffe", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::fffe:ffff:ffff", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::ffff:ffff:fffe", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*::*:*:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*::*:%*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff::ffff:ffff:ffff", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*::*:*:*:*:*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*:*:a:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*:*:*:*:*:*:*:*/16", orderNumber))

	ordering = append(ordering, ipAddressSupplier("*:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*:*:*:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("**", orderNumber))
	ordering = append(ordering, ipAddressSupplier(" *", orderNumber))
	ordering = append(ordering, ipAddressSupplier("%%", orderNumber))
	orderNumber++

	t.checkOrdering(ordering, orderNumber, comparator)
}

func (t addressOrderTest) testLowValueOrder(comparator OrderingComparator, ipAddressSupplier, macAddressSupplier OrderingSupplier) {

	var ordering []*Ordering

	//order is INVALID, EMPTY, IPV4, IPV6, ALL
	orderNumber := 0

	//invalid
	strs := []string{ //these are already sorted by natural string ordering
		"/129", //invalid prefix
		"bla",
		"fo",
		"foo",
		"four",
		"xxx",
	}
	for _, s := range strs {
		ordering = append(ordering, ipAddressSupplier(s, orderNumber))
		orderNumber++
		ordering = append(ordering, macAddressSupplier(s, orderNumber))
		orderNumber++
	}

	//empty
	ordering = append(ordering, macAddressSupplier("", orderNumber))
	ordering = append(ordering, macAddressSupplier("  ", orderNumber))
	ordering = append(ordering, macAddressSupplier("     ", orderNumber))
	ordering = append(ordering, macAddressSupplier("", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("0-1:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:0:0:*:*:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("*:0:0:*:%*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:*:*:*:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:a:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:0:0:0", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0-ff:*:*:*:8", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3-4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("1:00:00:2:03:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("1:0:0:2:3:4", orderNumber))
	ordering = append(ordering, macAddressSupplier("01:00:00:02:03:04", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:2:1-3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0-7f:2:3:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:*:2:03:4:*", orderNumber))
	ordering = append(ordering, macAddressSupplier("01:*:02:03:04:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:f0-ff:2:3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("a1:f0:2:3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:0:0:fe:ff:fe", orderNumber))
	orderNumber++
	ordering = append(ordering, macAddressSupplier("ff:0:0:fe:ff:ff", orderNumber))
	orderNumber++
	ordering = append(ordering, macAddressSupplier("ff:0:0:ff:ff:fe", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:0:0:ff:ff:ff", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:ff:ff:ff:ff:ff", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("*:*:*:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("0:0:0:0:0:0:0:1", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("1:0:0:0:0:0:0:0", orderNumber))
	orderNumber++

	ordering = append(ordering, macAddressSupplier("ff:ff:ff:ff:ff:ff:ff:ff", orderNumber))
	orderNumber++

	//empty
	ordering = append(ordering, ipAddressSupplier("", orderNumber))
	ordering = append(ordering, ipAddressSupplier("  ", orderNumber))
	ordering = append(ordering, ipAddressSupplier("     ", orderNumber))
	ordering = append(ordering, ipAddressSupplier("", orderNumber))
	orderNumber++

	//a bunch of address

	ordering = append(ordering, ipAddressSupplier("*.*.*.*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*.*.%*.*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*.*.1-3.*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.0.0.0", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.000.0.*/17", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.0.0/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("001.002.000.000/16", orderNumber))

	ordering = append(ordering, ipAddressSupplier("1.002.*.*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.2.000.0/15", orderNumber))

	ordering = append(ordering, ipAddressSupplier("1.2-3.*.*/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.3.*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.002.3.*/31", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1.002.3.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.2.003.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1.2.3.4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("001.002.003.004", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("255.254.255.254", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("255.254.255.255", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("255.255.255.254", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("255.255.255.255", orderNumber))
	orderNumber++

	// IPv6

	ordering = append(ordering, ipAddressSupplier("*::*:*:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*::*:%*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*::*:*:*:*:*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*:*:*:*:*:*:*:*/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*:*:*:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*:*:a:*:*:*:*:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1:0::*/16", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1:0:*/16", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::/31", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::/17", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1:0::/17", orderNumber))

	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("0001:0000::0000:0000:0000/16", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1:*/17", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1:*/16", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:2:*/111", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:3:*/127", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:3:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:003:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:4", orderNumber))
	ordering = append(ordering, ipAddressSupplier("0001:0000::0002:0003:0004", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:1-3:4:*", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("1:8000::/17", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("2::0:*/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("2:0:*/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("2:*/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("2::/15", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("a1:8000::/17", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff::fffe:ffff:fffe", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::fffe:ffff:ffff", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::ffff:ffff:fffe", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("ffff::ffff:ffff:ffff", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff:ffff:ffff::", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff:ffff:ffff:ffff::1", orderNumber))
	orderNumber++

	ordering = append(ordering, ipAddressSupplier("*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("**", orderNumber))
	ordering = append(ordering, ipAddressSupplier(" *", orderNumber))
	ordering = append(ordering, ipAddressSupplier("%%", orderNumber))
	orderNumber++

	t.checkOrdering(ordering, orderNumber, comparator)
}

func (t addressOrderTest) checkOrdering(ordering []*Ordering, orderCount int, comparator OrderingComparator) {
	length := len(ordering)
	for i := 0; i < length; i++ {
		val := ordering[i]
		if val == nil {
			j := length - 1
			for j > i {
				if ordering[j] != nil {
					ordering[i] = ordering[j]
					ordering[j] = nil
					break
				}
				j--
			}
			length = j
		}
	}
	ordering = ordering[:length]
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(ordering), func(i, j int) { ordering[i], ordering[j] = ordering[j], ordering[i] })

	if comparator != nil {
		sort.Slice(ordering, func(i, j int) bool {
			return comparator(ordering[i], ordering[j]) < 0
		})
	} else {
		sort.Slice(ordering, func(i, j int) bool {
			return ordering[i].CompareTo(ordering[j]) < 0
		})
	}

	failedOrdering := false
	lastOrder := -1
	for i := 0; i < len(ordering); i++ {
		orderingItem := ordering[i]
		order := orderingItem.order
		if order < lastOrder {
			failedOrdering = true
			failureStr := fmt.Sprintf("item %v: %v is in wrong place in ordering ( order number: %v, previous order number: %v)", i+1, orderingItem.nestedType, order, lastOrder)
			t.addFailure(newFailure(failureStr, nil))
		}
		lastOrder = order
	}

	if failedOrdering {
		sorted := make([]string, 0, len(ordering))
		previousOrder, lastIndex := -1, -1
		for i := 0; i < len(ordering); i++ {
			o := ordering[i]
			currentOrder := o.order
			var index int
			if currentOrder == previousOrder {
				index = lastIndex
			} else {
				index = i + 1
			}
			sorted = append(sorted, fmt.Sprintf("\n(sorted index %v) %v", index, o.getDescription()))
			previousOrder = currentOrder
			lastIndex = index
		}

		t.addFailure(newFailure(fmt.Sprintf("ordering failed: %v", sorted), nil))
	}

	t.incrementTestCount()
}
