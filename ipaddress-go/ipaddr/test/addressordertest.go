package test

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrparam"
	"math/rand"
	"sort"
	"time"
)

type OrderingSupplier func(string, int) *Ordering
type OrderingComparator func(one, two *Ordering) int

var (
	orderingOpts    = new(addrparam.IPAddressStringParametersBuilder).AllowAll(true).SetRangeParameters(addrparam.WildcardAndRange).ParseEmptyStrAs(addrparam.NoAddressOption).GetIPv6AddressParametersBuilder().AllowZone(false).GetParentBuilder().ToParams()
	macOrderingOpts = new(addrparam.MACAddressStringParametersBuilder).AllowAll(true).AllowEmpty(true).SetRangeParameters(addrparam.WildcardAndRange).ToParams()
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
		//expected := one.order - two.order
		//if (result < 0 && expected >= 0) || (result > 0 && expected <= 0) || (result == 0 && expected != 0) {
		//	lowValComparator.Compare(one.nestedType, two.nestedType)
		//}
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
		//expected := one.order - two.order
		//if (result < 0 && expected >= 0) || (result > 0 && expected <= 0) || (result == 0 && expected != 0) {
		//	if oneAddr != nil && twoAddr != nil {
		//		fmt.Printf("oops comparing %v and %v\n", oneAddr, twoAddr)
		//		lowValComparator.Compare(oneAddr, twoAddr)
		//	} else {
		//		one.nestedIPAddrString.Compare(two.nestedIPAddrString)
		//	}
		//}
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
		//expected := one.order - two.order
		//if (result < 0 && expected >= 0) || (result > 0 && expected <= 0) || (result == 0 && expected != 0) {
		//	if oneAddr != nil && twoAddr != nil {
		//		lowValComparator.Compare(oneAddr, twoAddr)
		//	} else {
		//		one.nestedMACAddrString.Compare(two.nestedMACAddrString)
		//	}
		//}
		return result
	}

	t.testLowValueOrder(ipAddressStringLowValComparator, ipaddressStringOrderingSupplier, nilOrderingSupplier)
	t.testLowValueOrder(macAddressStringLowValComparator, nilOrderingSupplier, macaddressStringOrderingSupplier)
	t.testLowValueOrder(ipAddressLowValComparator, ipAddressOrderingSupplier, macAddressOrderingSupplier)

	highValComparator := ipaddr.HighValueComparator

	ipAddressHighValComparator := func(one, two *Ordering) int {
		result := highValComparator.Compare(one.nestedType, two.nestedType)
		//expected := one.order - two.order
		//if (result < 0 && expected >= 0) || (result > 0 && expected <= 0) || (result == 0 && expected != 0) {
		//	lowValComparator.Compare(one.nestedType, two.nestedType)
		//}
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
		//expected := one.order - two.order
		//if (result < 0 && expected >= 0) || (result > 0 && expected <= 0) || (result == 0 && expected != 0) {
		//	if oneAddr != nil && twoAddr != nil {
		//		fmt.Printf("oops comparing %v and %v\n", oneAddr, twoAddr)
		//		highValComparator.Compare(oneAddr, twoAddr)
		//	} else {
		//		one.nestedIPAddrString.Compare(two.nestedIPAddrString)
		//	}
		//}
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
		//expected := one.order - two.order
		//if (result < 0 && expected >= 0) || (result > 0 && expected <= 0) || (result == 0 && expected != 0) {
		//	if oneAddr != nil && twoAddr != nil {
		//		fmt.Printf("oops comparing %v and %v\n", oneAddr, twoAddr)
		//		highValComparator.Compare(oneAddr, twoAddr)
		//	} else {
		//		one.nestedMACAddrString.Compare(two.nestedMACAddrString)
		//	}
		//}
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
	//expected := o.order - other.order
	//if (result < 0 && expected >= 0) || (result > 0 && expected <= 0) || (result == 0 && expected != 0) {
	//	if o.nestedIPAddrString != nil {
	//		fmt.Printf("oops comparing %v and %v\n", o.nestedIPAddrString, other.nestedIPAddrString)
	//		o.nestedIPAddrString.Compare(other.nestedIPAddrString)
	//	} else if o.nestedMACAddrString != nil {
	//		fmt.Printf("oops comparing %v and %v\n", o.nestedMACAddrString, other.nestedMACAddrString)
	//		o.nestedMACAddrString.Compare(other.nestedMACAddrString)
	//	} else {
	//		fmt.Printf("oops comparing %v and %v\n", o.nestedType, other.nestedType)
	//		o.nestedType.Compare(other.nestedType)
	//	}
	//}
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

	//order is INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL
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

	//xx ipv6 x;

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

	//ordering = append(ordering, ipAddressSupplier("/128", orderNumber)) //interpreted as ipv6
	//orderNumber++

	ordering = append(ordering, ipAddressSupplier("1::2:3:*/127", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("1::2:3:*/111", orderNumber))
	orderNumber++
	ordering = append(ordering, ipAddressSupplier("1::2:1-3:4:*", orderNumber))
	orderNumber++

	//ordering = append(ordering, ipAddressSupplier("/64", orderNumber)) //interpreted as ipv6
	//orderNumber++

	ordering = append(ordering, ipAddressSupplier("*::*:*:*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("*::*:%*:*", orderNumber))
	orderNumber++

	//ordering = append(ordering, ipAddressSupplier("/33", orderNumber)) //interpreted as ipv6
	//orderNumber++

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

	//ordering = append(ordering, ipAddressSupplier("/32", orderNumber))
	//orderNumber++
	//ordering = append(ordering, ipAddressSupplier("/24", orderNumber))
	//orderNumber++
	//ordering = append(ordering, ipAddressSupplier("/0", orderNumber))
	//orderNumber++

	ordering = append(ordering, ipAddressSupplier("*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("**", orderNumber))
	ordering = append(ordering, ipAddressSupplier(" *", orderNumber))
	ordering = append(ordering, ipAddressSupplier("%%", orderNumber))
	orderNumber++

	t.checkOrdering(ordering, orderNumber, nil)
}

//type AddrComparator func (one, two ipaddr.AddressType) int
//func (t addressOrderTest) testDefaultOrder(ipAddressSupplier, macAddressSupplier func(string, int) *Ordering) {
//func (comp AddressComparator) CompareAddresses(one, two AddressType) int {

func (t addressOrderTest) testHighValueOrder(comparator OrderingComparator, ipAddressSupplier, macAddressSupplier OrderingSupplier) {

	var ordering []*Ordering

	//order is INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL
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

	//a bunch of address and prefixes

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

	//ipv6

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

	//ordering = append(ordering, ipAddressSupplier("/33", orderNumber)) //interpreted as ipv6
	//orderNumber++
	//
	//ordering = append(ordering, ipAddressSupplier("/64", orderNumber)) //interpreted as ipv6
	//orderNumber++
	//
	//ordering = append(ordering, ipAddressSupplier("/128", orderNumber)) //interpreted as ipv6
	//orderNumber++
	//
	//ordering = append(ordering, ipAddressSupplier("/32", orderNumber))
	//orderNumber++
	//ordering = append(ordering, ipAddressSupplier("/24", orderNumber))
	//orderNumber++
	//ordering = append(ordering, ipAddressSupplier("/0", orderNumber))
	//orderNumber++

	ordering = append(ordering, ipAddressSupplier("*", orderNumber))
	ordering = append(ordering, ipAddressSupplier("**", orderNumber))
	ordering = append(ordering, ipAddressSupplier(" *", orderNumber))
	ordering = append(ordering, ipAddressSupplier("%%", orderNumber))
	orderNumber++

	t.checkOrdering(ordering, orderNumber, comparator)
}

func (t addressOrderTest) testLowValueOrder(comparator OrderingComparator, ipAddressSupplier, macAddressSupplier OrderingSupplier) {

	var ordering []*Ordering

	//order is INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL
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

	//a bunch of address and prefixes

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

	//ipv6

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

	//ordering = append(ordering, ipAddressSupplier("/33", orderNumber)) //interpreted as ipv6, ffff:ffff:8000::/33
	//orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff:ffff:ffff::", orderNumber))
	orderNumber++

	//ordering = append(ordering, ipAddressSupplier("/64", orderNumber)) //interpreted as ipv6 ffff:ffff:ffff:ffff::
	//orderNumber++

	ordering = append(ordering, ipAddressSupplier("ffff:ffff:ffff:ffff::1", orderNumber))
	orderNumber++

	//ordering = append(ordering, ipAddressSupplier("/128", orderNumber)) //interpreted as ipv6
	//orderNumber++
	//
	//ordering = append(ordering, ipAddressSupplier("/32", orderNumber))
	//orderNumber++
	//ordering = append(ordering, ipAddressSupplier("/24", orderNumber))
	//orderNumber++
	//ordering = append(ordering, ipAddressSupplier("/0", orderNumber))
	//orderNumber++

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
		//Collections.sort(ordering, comparator);
	} else {
		sort.Slice(ordering, func(i, j int) bool {
			return ordering[i].CompareTo(ordering[j]) < 0
		})
		//Collections.sort(ordering);
	}

	failedOrdering := false
	lastOrder := -1
	for i := 0; i < len(ordering); i++ {
		orderingItem := ordering[i]
		order := orderingItem.order
		if order < lastOrder {
			failedOrdering = true
			failureStr := fmt.Sprintf("item %v: %v is in wrong place in ordering ( order number: %v, previous order number: %v)", (i + 1), orderingItem.nestedType, order, lastOrder)
			t.addFailure(newFailure(failureStr, nil))
		}
		lastOrder = order
	}

	if failedOrdering {
		sorted := make([]string, 0, len(ordering))
		//ArrayList<String> sorted = new ArrayList<String>(ordering.size());
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
