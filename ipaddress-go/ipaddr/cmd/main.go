package main

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"net"

	//ip_addr_old "github.com/seancfoley/ipaddress/ipaddress-go/ipaddrold"
	//"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"

	//"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
)

func main() {
	//ipaddr.Test()

	//ipaddr.divFunc(nil)
	seg := ipaddr.IPv4AddressSegment{}

	seg.GetSegmentValue()

	//seg.getSplitSegments()
	//fmt.Printf("\n%v\n", seg.getDivisionValue())
	//fmt.Printf("%v\n", seg.GetSegmentValue())
	fmt.Printf("%v\n", seg.GetBitCount())
	fmt.Printf("%v\n", seg.GetByteCount())

	grouping := ipaddr.IPv4AddressSection{}
	grouping.GetSegmentCount()
	//grouping.hasNoDivisions()

	builder := ipaddr.IPAddressStringParametersBuilder{}
	params := builder.AllowAll(false).ToParams()
	fmt.Printf("%+v\n", params)

	//params := ipaddr.ipAddressStringParameters{}
	////fmt.Printf("%+v\n", params)
	//init := ipaddr.IPAddressStringParametersBuilder{}
	//params2 := init.AllowAll(false).ToParams()
	//params = *params2
	//_ = params
	////fmt.Printf("%+v\n", params)

	i := -1
	var b byte = byte(i)
	fmt.Printf("byte is %+v\n", b)

	var slc []int
	fmt.Printf("%+v\n", slc) // expecting []
	fmt.Printf("%v\n", slc)  // expecting []
	fmt.Printf("%v\n", slc)  // expecting []

	addr := ipaddr.IPv6Address{}
	fmt.Printf("zero addr is %+v\n", addr)
	fmt.Printf("zero addr is %+v\n", &addr)

	addr4 := ipaddr.IPv4Address{}
	fmt.Printf("zero addr is %+v\n", addr4)
	addr2 := addr4.ToIP()
	fmt.Printf("zero addr is %+v\n", addr2)
	addr2.String()
	addr2.GetSection()
	fmt.Printf("zero addr is %+v\n", addr2.String())
	//fmt.Printf("%+v\n", &addr2)

	ipv4Prefixed := addr4.ToPrefixBlockLen(16)
	fmt.Printf("16 block is %+v\n", ipv4Prefixed)
	fmt.Printf("lower is %+v\n", ipv4Prefixed.GetLower())
	fmt.Printf("upper is %+v\n", ipv4Prefixed.GetUpper())
	fmt.Printf("lower is %+v\n", ipv4Prefixed.GetLower())
	fmt.Printf("upper is %+v\n", ipv4Prefixed.GetUpper())

	_ = addr.GetPrefixCount() // an inherited method

	addr5 := ipaddr.IPAddress{} // expecting []
	fmt.Printf("%+v\n", addr5)
	addr5Upper := addr5.GetUpper()
	fmt.Printf("%+v\n", addr5Upper) // expecting []
	addr6 := addr5Upper.ToIPv4()
	fmt.Printf("%+v\n", addr6) // expecting <nil>

	addrSection := ipaddr.AddressSection{}
	fmt.Printf("%+v\n", addrSection) // expecting [] or <nil>

	ipAddrSection := ipaddr.IPAddressSection{}
	fmt.Printf("%+v\n", ipAddrSection) // expecting [] or <nil>

	ipv4AddrSection := ipaddr.IPv4AddressSection{}
	fmt.Printf("%+v\n", ipv4AddrSection) // expecting [] or <nil>

	//addrStr := ipaddr.IPAddressString{}
	addrStr := ipaddr.NewIPAddressString("1.2.3.4")
	pAddr := addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	//fmt.Printf("All the formats: %v %x %X %o %O %b %d %#x %#o %#b\n",
	//	pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr)
	fmt.Printf("All the formats: default %v\nstring %s\nquoted %q\nquoted backtick %#q\nlowercase hex %x\nuppercase hex %X\nlower hex prefixed %#x\nupper hex prefixed %#X\noctal no prefix %o\noctal prefixed %O\noctal 0 prefix %#o\nbinary %b\nbinary prefixed %#b\ndecimal %d\n\n",
		pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr, pAddr)
	//fmt.Printf("All the formats: %v %x %X %o %O %b %d %#x %#o %#b\n",
	//	*pAddr, *pAddr, *pAddr, *pAddr, *pAddr, *pAddr, *pAddr, *pAddr, *pAddr, *pAddr)
	//fmt.Printf("octal no prefix %o\n", *pAddr)
	//fmt.Printf("octal prefixed %O\n", *pAddr)
	//fmt.Printf("octal 0 prefix %#o\n", *pAddr)
	//fmt.Printf("binary no prefix %b\n", *pAddr)
	//fmt.Printf("binary prefixed %#b\n", *pAddr)

	pAddr = addrStr.GetAddress() // test getting it a second time from the cache
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	cidrStr := ipaddr.NewIPAddressString("255.2.0.0/16")
	cidr := cidrStr.GetAddress()
	fmt.Printf("All the formats: default %v\nstring %s\nquoted %q\nquoted backtick %#q\nlowercase hex %x\nuppercase hex %X\nlower hex prefixed %#x\nupper hex prefixed %#X\noctal no prefix %o\noctal prefixed %O\noctal 0 prefix %#o\nbinary %b\nbinary prefixed %#b\ndecimal %d\n\n",
		cidr, cidr, cidr, cidr, cidr, cidr, cidr, cidr, cidr, cidr, cidr, cidr, cidr, cidr)

	pZeroSec := ipaddr.IPv4AddressSection{}
	//fmt.Printf("octal no prefix %o\noctal prefixed %O\noctal 0 prefix %#o\ndecimal %d\n\n",
	//	pZeroSec, pZeroSec, pZeroSec, pZeroSec)

	fmt.Printf("All the formats for zero section: default %v\nstring %s\nquoted %q\nquoted backtick %#q\nlowercase hex %x\nuppercase hex %X\nlower hex prefixed %#x\nupper hex prefixed %#X\noctal no prefix %o\noctal prefixed %O\noctal 0 prefix %#o\nbinary %b\nbinary prefixed %#b\ndecimal %d\n\n",
		pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec, pZeroSec)

	addrStr = ipaddr.NewIPAddressString("abc.2.3.4")
	noAddr, err := addrStr.ToAddress()
	fmt.Printf("invalid string abc.2.3.4 is %v with err %v\n", noAddr, err)

	ipv4Prefixed2 := pAddr.ToPrefixBlockLen(19)
	fmt.Printf("19 block is %+v\n", ipv4Prefixed2)

	addrStr = ipaddr.NewIPAddressString("a:b:c:d:e:f:a:b")
	pAddr = addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	addrStr = ipaddr.NewIPAddressString("a:b:c:d:e:f:a:b%eth0")
	pAddr = addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	addrStr = ipaddr.NewIPAddressString("a:b:c:d:e:f:1.2.3.4")
	pAddr = addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	ipv4Addr, _ := ipaddr.NewIPv4AddressFromBytes([]byte{1, 0, 1, 0})
	fmt.Printf("%+v\n", ipv4Addr)
	fmt.Printf("%+v\n", *ipv4Addr)

	ipv4Addr, ipv4Err := ipaddr.NewIPv4AddressFromBytes([]byte{1, 1, 0, 1, 0})
	fmt.Printf("%+v %+v\n", ipv4Addr, ipv4Err)

	ipv6Addr, ipv6Err := ipaddr.NewIPv6AddressFromBytes(net.IP{1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc, 1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc})
	fmt.Printf("%+v %+v\n", ipv6Addr, ipv6Err)
	fmt.Printf("%+v\n", *ipv6Addr)
	fmt.Printf("All the formats: default %v\nstring %s\nlowercase hex %x\nuppercase hex %X\nlower hex prefixed %#x\nupper hex prefixed %#X\noctal no prefix %o\noctal prefixed %O\noctal 0 prefix %#o\nbinary %b\nbinary prefixed %#b\ndecimal %d\n\n",
		ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr)
	//ipv6Addr = nil
	//fmt.Printf("All the formats: %v %x %X %o %O %b %#x %#o %#b\n",
	//	ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr, ipv6Addr)

	ipv6Prefixed := ipv6Addr.ToPrefixBlockLen(32)
	fmt.Printf("32 block is %+v\n", ipv6Prefixed)
	ipv6Prefixed = ipv6Addr.ToPrefixBlockLen(40)
	fmt.Printf("40 block is %+v\n", ipv6Prefixed)

	addrDown := ipv6Prefixed.ToAddressBase()
	fmt.Printf("addr down converted 40 block is %+v\n", addrDown)

	addrUp := addrDown.ToIPv6()
	fmt.Printf("addr up converted 40 block is %+v\n", addrUp)

	addrUpNil := addrDown.ToIPv4()
	fmt.Printf("addr up converted nil is %+v\n", addrUpNil)

	ht := ipaddr.NewHostName("bla.com")
	fmt.Printf("%v\n", ht.ToNormalizedString())
	fmt.Printf("%v\n", ht.GetHost())
	//ip := net.IP{1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc, 1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc}
	//foo(ip)
	//foo2(ip)
	//foo3(net.IPAddr{IP: ip})

	//bytes := []byte{1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc, 1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc}
	//foo(bytes)
	//foo2(bytes)
	//foo3(net.IPAddr{IP: bytes})

	fmt.Printf("iterate a segment:\n")
	iter := addrUp.GetSegment(ipaddr.IPv6SegmentCount - 1).PrefixedBlockIterator(5)
	for iter.HasNext() {
		fmt.Printf("%v ", iter.Next())
	}
	fmt.Printf("\niterate another segment:\n")
	iter = addrUp.GetSegment(ipaddr.IPv6SegmentCount - 1).PrefixedBlockIterator(0)
	for iter.HasNext() {
		fmt.Printf("%v ", iter.Next())
	}

	addrStrPref := ipaddr.NewIPAddressString("1.2-11.0.0/15")
	pAddr = addrStrPref.GetAddress()
	newIter := pAddr.GetSection().PrefixBlockIterator()
	fmt.Printf("\nto iterate: %+v", pAddr)
	fmt.Printf("\niterate prefix blocks (prefix len 15):\n")
	for newIter.HasNext() {
		fmt.Printf("%v ", newIter.Next())
	}
	addrStrPref = ipaddr.NewIPAddressString("1.2-11.0.0/16")
	pAddr = addrStrPref.GetAddress()
	fmt.Printf("\nto iterate: %+v", pAddr)
	newIter = pAddr.GetSection().BlockIterator(2)
	fmt.Printf("\niterate a section's first two blocks:\n")
	for newIter.HasNext() {
		fmt.Printf("%v ", newIter.Next())
	}
	newIter = pAddr.GetSection().SequentialBlockIterator()
	fmt.Printf("\nsequential block iterator:\n")
	for newIter.HasNext() {
		fmt.Printf("%v ", newIter.Next())
	}

	addrStrPref1 := ipaddr.NewIPAddressString("1.2.3.4")
	addrStrPref2 := ipaddr.NewIPAddressString("1.2.4.1")
	rng := addrStrPref1.GetAddress().ToIPv4().SpanWithRange(addrStrPref2.GetAddress().ToIPv4())
	riter := rng.Iterator()
	fmt.Printf("\nsequential range iterator:\n")
	for riter.HasNext() {
		fmt.Printf("%v ", riter.Next())
	}
	riter = rng.PrefixBlockIterator(28)
	fmt.Printf("\nsequential range pref block iterator:\n")
	for riter.HasNext() {
		fmt.Printf("%v ", riter.Next())
	}

	sect := addrStrPref1.GetAddress().ToIPv4().GetSection()
	str := sect.ToCanonicalString()
	fmt.Printf("\nString is %s", str)
	addrStrPref6 := ipaddr.NewIPAddressString("1.2.3.4/16")
	sect = addrStrPref6.GetAddress().ToIPv4().GetSection()
	str = sect.ToCanonicalString()
	fmt.Printf("\nString with prefix length is %s", str)

	ipv4Addr = addrStrPref6.GetAddress().ToIPv4()
	str, _ = ipv4Addr.ToInetAtonJoinedString(ipaddr.Inet_aton_radix_hex, 2)
	fmt.Printf("\nInet Aton string with prefix length is %s", str)
	str, _ = ipv4Addr.ToInetAtonJoinedString(ipaddr.Inet_aton_radix_hex, 1)
	fmt.Printf("\nInet Aton string with prefix length is %s", str)
	str, _ = ipv4Addr.ToInetAtonJoinedString(ipaddr.Inet_aton_radix_hex, 0)
	fmt.Printf("\nInet Aton string with prefix length is %s", str)

	addrStrPref7 := ipaddr.NewIPAddressString("1:2:3:4::/64")
	ipv6Sect := addrStrPref7.GetAddress().ToIPv6().GetSection()
	str = ipv6Sect.ToCanonicalString()
	fmt.Printf("\nIPv6 string with prefix length is %s", str)
	str, _ = addrStrPref7.GetAddress().ToIPv6().ToMixedString()
	fmt.Printf("\nIPv6 mixed string with prefix length is %s", str)
	str, _ = addrStrPref7.GetAddress().ToBinaryString(true)
	fmt.Printf("\nIPv6 binary string is %s", str)

	str = addrStrPref7.GetAddress().ToSegmentedBinaryString()
	fmt.Printf("\nIPv6 segmented binary string is %s", str)

	addrStrPref8 := ipaddr.NewIPAddressString("1::4:5:6:7:8fff/64")
	ipv6Sect = addrStrPref8.GetAddress().ToIPv6().GetSection()
	str = ipv6Sect.ToCanonicalString()
	fmt.Printf("\nIPv6 string with prefix length is %s", str)
	str, _ = addrStrPref8.GetAddress().ToIPv6().ToMixedString()
	fmt.Printf("\nIPv6 mixed string with prefix length is %s", str)

	rangiter := rng.PrefixIterator(28)
	fmt.Printf("\nsequential range pref iterator:\n")
	for rangiter.HasNext() {
		fmt.Printf("%v ", rangiter.Next())
	}

	addrStrPref3 := ipaddr.NewIPAddressString("1-4::1/125")
	addrIter := addrStrPref3.GetAddress().PrefixBlockIterator()
	fmt.Printf("\naddress pref block iterator:\n")
	for addrIter.HasNext() {
		fmt.Printf("%v ", addrIter.Next())
	}

	addrStrPref4 := ipaddr.NewIPAddressString("1::1/125")
	addrIter = addrStrPref4.GetAddress().Iterator()
	fmt.Printf("\naddress iterator:\n")
	for addrIter.HasNext() {
		fmt.Printf("%v ", addrIter.Next())
	}

	addrStrPref5 := ipaddr.NewIPAddressString("1::/125")
	addrIter = addrStrPref5.GetAddress().Iterator()
	fmt.Printf("\naddress iterator:\n")
	for addrIter.HasNext() {
		fmt.Printf("%v ", addrIter.Next())
	}

	macStrPref1 := ipaddr.NewMACAddressString("1:2:3:4:5:6")
	mAddr := macStrPref1.GetAddress()
	fmt.Printf("\nmac addr is %+v\n", mAddr)

	macStrPref1 = ipaddr.NewMACAddressString("1:2:3:4:5:*")
	mAddr = macStrPref1.GetAddress()
	fmt.Printf("\nmac addr is %+v\n", mAddr)
	mAddrIter := mAddr.Iterator()
	fmt.Printf("\nmac address iterator:\n")
	for mAddrIter.HasNext() {
		fmt.Printf("%v ", mAddrIter.Next())
	}

	fmt.Printf("\nincremented by 1 mac addr %+v is %+v\n", mAddr, mAddr.Increment(1))
	fmt.Printf("\nincremented by -1 mac addr %+v is %+v\n", mAddr, mAddr.Increment(-1))
	fmt.Printf("\nincremented by -1 and then by +1 mac addr %+v is %+v\n", mAddr, mAddr.Increment(-1).Increment(1))
	fmt.Printf("\nincremented by +1 and then by -1 mac addr %+v is %+v\n", mAddr, mAddr.Increment(1).Increment(-1))

	splitIntoBlocks("0.0.0.0", "0.0.0.254")
	splitIntoBlocks("0.0.0.1", "0.0.0.254")
	splitIntoBlocks("0.0.0.0", "0.0.0.254") // 16 8 4 2 1
	splitIntoBlocks("0.0.0.10", "0.0.0.21")

	splitIntoBlocks("1.2.3.4", "1.2.3.3-5")
	splitIntoBlocks("1.2-3.4.5-6", "2.0.0.0")
	splitIntoBlocks("1.2.3.4", "1.2.4.4") // 16 8 4 2 1
	splitIntoBlocks("0.0.0.0", "255.0.0.0")

	fmt.Printf("\n\n")

	splitIntoBlocksSeq("0.0.0.0", "0.0.0.254")
	splitIntoBlocksSeq("0.0.0.1", "0.0.0.254")
	splitIntoBlocksSeq("0.0.0.0", "0.0.0.254") // 16 8 4 2 1
	splitIntoBlocksSeq("0.0.0.10", "0.0.0.21")

	splitIntoBlocksSeq("1.2.3.4", "1.2.3.3-5")
	splitIntoBlocksSeq("1.2-3.4.5-6", "2.0.0.0")
	splitIntoBlocksSeq("1.2-3.4.5-6", "1.3.4.6")
	splitIntoBlocksSeq("1.2.3.4", "1.2.4.4") // 16 8 4 2 1
	splitIntoBlocksSeq("0.0.0.0", "255.0.0.0")

	fmt.Printf("%v\n\n", merge("209.152.214.112/30", "209.152.214.116/31", "209.152.214.118/31"))
	fmt.Printf("%v\n\n", merge("209.152.214.112/30", "209.152.214.116/32", "209.152.214.118/31"))
	fmt.Printf("%v\n\n", merge("1:2:3:4:8000::/65", "1:2:3:4::/66", "1:2:3:4:4000::/66", "1:2:3:5:4000::/66", "1:2:3:5::/66", "1:2:3:5:8000::/65"))

	delim := "1:2,3,4:3:6:4:5,6fff,7,8,99:6:8"
	delims := ipaddr.ParseDelimitedSegments(delim)
	delimCount := ipaddr.CountDelimitedAddresses(delim)
	i = 0
	for delims.HasNext() {
		i++
		fmt.Printf("%d of %d is %v, from %v\n", i, delimCount, delims.Next(), delim)
	}
	fmt.Println()
	delim = "1:3:6:4:5,6fff,7,8,99:6:2,3,4:8"
	delims = ipaddr.ParseDelimitedSegments(delim)
	delimCount = ipaddr.CountDelimitedAddresses(delim)
	i = 0
	for delims.HasNext() {
		i++
		fmt.Printf("%d of %d is %v, from %v\n", i, delimCount, delims.Next(), delim)
	}
	//bitsPerSegment := 8
	//prefBits := 7
	//maxVal := ^ipaddr.DivInt(0)
	//mask := ^(maxVal << (bitsPerSegment - prefBits))
	//masker := ipaddr.TestMaskRange(0, 4, mask, maxVal)
	//fmt.Printf("masked vals 0 to 4 masked with %v (should be 0 to 1): %v %v\n", mask, masker.GetMaskedLower(0, mask), masker.GetMaskedUpper(4, mask))
	//
	//prefBits = 4
	//mask = ^(maxVal << (bitsPerSegment - prefBits))
	//masker = ipaddr.TestMaskRange(17, 32, mask, maxVal)
	//fmt.Printf("masked vals 17 to 32 masked with %v (should be 0 to 15): %v %v\n", mask, masker.GetMaskedLower(17, mask), masker.GetMaskedUpper(32, mask))
	//
	//masker = ipaddr.TestMaskRange(16, 32, mask, maxVal)
	//fmt.Printf("masked vals 16 to 32 masked with %v (should be 0 to 15): %v %v\n", mask, masker.GetMaskedLower(16, mask), masker.GetMaskedUpper(32, mask))

	// iterate on nil - just checking what happens.  it panics, not surprisingly.
	//var niladdr *ipaddr.IPAddress
	//itr := niladdr.Iterator()
	//for itr.HasNext() {
	//	fmt.Printf("%v ", itr.Next())
	//}

	s := ipaddr.IPv4AddressSegment{}
	res := s.PrefixContains(&s, 6)
	fmt.Printf("Zero seg pref contains %v\n", res)

	// check is we need to "override" methods like ToHexString
	str, _ = ipaddr.NewIPv4Segment(3).ToHexString(true)
	fmt.Println("leading zeros?  Hope not: " + str)
	str, _ = (&ipaddr.IPv4AddressSegment{}).ToHexString(true)
	fmt.Println("leading zeros?  Hope not: " + str)

	// check is we need to "override" methods like ToNormalizedString
	str = ipaddr.NewIPv4Segment(3).ToNormalizedString()
	fmt.Println("leading zeros?  Hope not: " + str)
	str = (&ipaddr.IPv4AddressSegment{}).ToNormalizedString()
	fmt.Println("leading zeros?  Hope not: " + str)

	sega := ipaddr.NewIPv4Segment(128)
	segb := ipaddr.NewIPv4Segment(127)
	seg1 := ipaddr.NewIPv4Segment(3)
	seg2 := ipaddr.NewIPv4Segment(0)
	seg3 := &ipaddr.IPv4AddressSegment{}

	fmt.Printf("compare values: 1? %v nil? %v nil? %v 0? %v 0? %v nil? %v 1? %v 6? %v 8? %v 8? %v\n",
		sega.GetBlockMaskPrefixLen(true),  // should be 1
		segb.GetBlockMaskPrefixLen(true),  // should be nil
		seg1.GetBlockMaskPrefixLen(true),  // should be nil
		seg2.GetBlockMaskPrefixLen(true),  // should be 0 - either 0 or nil
		seg3.GetBlockMaskPrefixLen(true),  // should be 0 - either 0 or nil
		sega.GetBlockMaskPrefixLen(false), // should be nil
		segb.GetBlockMaskPrefixLen(false), // should be 1
		seg1.GetBlockMaskPrefixLen(false), // should be 6
		seg2.GetBlockMaskPrefixLen(false), // should be 8 - either 8 or nil
		seg3.GetBlockMaskPrefixLen(false), // should be 8 - either 8 or nil
	)

	p1 := ipaddr.ToPrefixLen(1)
	p2 := ipaddr.ToPrefixLen(2)
	fmt.Printf("%v %v\n", p1, p2)
	*p1 = *p2
	fmt.Printf("%v %v\n", p1, p2)
	p1 = ipaddr.ToPrefixLen(1)
	p2 = ipaddr.ToPrefixLen(2)
	fmt.Printf("%v %v\n", p1, p2)

	pr1 := ipaddr.ToPort(3)
	pr2 := ipaddr.ToPort(4)
	fmt.Printf("%p %p %v %v\n", pr1, pr2, pr1, pr2)
	*pr1 = *pr2
	fmt.Printf("%p %p %v %v\n", pr1, pr2, pr1, pr2)
	pr1 = ipaddr.ToPort(3)
	pr2 = ipaddr.ToPort(4)
	fmt.Printf("%v %v\n", pr1, pr2)

	fmt.Printf("\n\n")
	//_ = getDoc()
}

func splitIntoBlocks(one, two string) {
	blocks := split(one, two)
	fmt.Printf("%v from splitting %v and %v: %v\n", len(blocks), one, two, blocks)
}

func splitIntoBlocksSeq(one, two string) {
	blocks := splitSeq(one, two)
	fmt.Printf("%v from splitting %v and %v: %v\n", len(blocks), one, two, blocks)
}

func split(oneStr, twoStr string) []*ipaddr.IPv4Address {
	one := ipaddr.NewIPAddressString(oneStr)
	two := ipaddr.NewIPAddressString(twoStr)
	return one.GetAddress().ToIPv4().SpanWithPrefixBlocksTo(two.GetAddress().ToIPv4())
}

func splitSeq(oneStr, twoStr string) []*ipaddr.IPv4Address {
	one := ipaddr.NewIPAddressString(oneStr)
	two := ipaddr.NewIPAddressString(twoStr)
	return one.GetAddress().ToIPv4().SpanWithSequentialBlocksTo(two.GetAddress().ToIPv4())
}

/*
8 from splitting 0.0.0.0 and 0.0.0.254: [0.0.0.0/25, 0.0.0.128/26, 0.0.0.192/27, 0.0.0.224/28, 0.0.0.240/29, 0.0.0.248/30, 0.0.0.252/31, 0.0.0.254/32]
14 from splitting 0.0.0.1 and 0.0.0.254: [0.0.0.1/32, 0.0.0.2/31, 0.0.0.4/30, 0.0.0.8/29, 0.0.0.16/28, 0.0.0.32/27, 0.0.0.64/26, 0.0.0.128/26, 0.0.0.192/27, 0.0.0.224/28, 0.0.0.240/29, 0.0.0.248/30, 0.0.0.252/31, 0.0.0.254/32]
8 from splitting 0.0.0.0 and 0.0.0.254: [0.0.0.0/25, 0.0.0.128/26, 0.0.0.192/27, 0.0.0.224/28, 0.0.0.240/29, 0.0.0.248/30, 0.0.0.252/31, 0.0.0.254/32]
4 from splitting 0.0.0.10 and 0.0.0.21: [0.0.0.10/31, 0.0.0.12/30, 0.0.0.16/30, 0.0.0.20/31]
1 from splitting 1.2.3.4 and 1.2.3.3-5: [1.2.3.3-5]
4 from splitting 1.2-3.4.5-6 and 2.0.0.0: [1.2.4.5-255, 1.2.5-255.*, 1.3-255.*.*, 2.0.0.0]
2 from splitting 1.2.3.4 and 1.2.4.4: [1.2.3.4-255, 1.2.4.0-4]
2 from splitting 0.0.0.0 and 255.0.0.0: [0-254.*.*.*, 255.0.0.0]
*/

func merge(strs ...string) []*ipaddr.IPAddress {
	first := ipaddr.NewIPAddressString(strs[0]).GetAddress()
	var remaining = make([]*ipaddr.IPAddress, len(strs))
	for i := range strs {
		remaining[i] = ipaddr.NewIPAddressString(strs[i]).GetAddress()
	}
	return first.MergeToPrefixBlocks(remaining...)
}

//func foo(bytes []byte) {
//	fmt.Printf("%v\n", bytes)
//}
//func foo2(bytes net.IP) {
//	fmt.Printf("%v\n", bytes)
//}
//func foo3(bytes net.IPAddr) {
//	fmt.Printf("%v\n", bytes)
//}

// go install golang.org/x/tools/cmd/godoc
// cd /Users/scfoley@us.ibm.com/goworkspace/bin
// ./godoc -http=localhost:6060
// http://localhost:6060/pkg/github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/

// src/golang.org/x/tools/godoc/static/ has the templates, specifically godoc.html

// godoc cheat sheet
//https://godoc.org/github.com/fluhus/godoc-tricks#Links

// gdb tips https://gist.github.com/danisfermi/17d6c0078a2fd4c6ee818c954d2de13c
func getDoc() error {
	// Create the AST by parsing src.
	fset := token.NewFileSet() // positions are relative to fset
	pkgs, err := parser.ParseDir(
		fset,
		//"/Users/scfoley@us.ibm.com/goworkspace/src/github.com/seancfoley/ipaddress/ipaddress-go/ipaddr",
		"/Users/scfoley/go/src/github.com/seancfoley/ipaddress/ipaddress-go/ipaddr",
		func(f os.FileInfo) bool { return true },
		parser.ParseComments)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return err
		//panic(err)
	}
	for keystr, valuePkg := range pkgs {
		pkage := doc.New(valuePkg, keystr, 0)
		//pkage := doc.New(valuePkg, keystr, doc.AllMethods)
		//pkage := doc.New(valuePkg, keystr, doc.AllDecls)
		//fmt.Printf("\n%+v", pkage)
		// Print the AST.
		//		ast.Print(fset, pkage)

		for _, t := range pkage.Types {
			fmt.Printf("\n%s", t.Name)
			for _, m := range t.Methods {
				//fmt.Printf("bool %v", doc.AllMethods&doc.AllMethods != 0)
				//https: //golang.org/src/go/doc/doc.go
				//https://golang.org/src/go/doc/reader.go sortedTypes sortedFuncs show how they are filtered
				fmt.Printf("\n%+v", m)
			}
		}
	}
	return nil
}
