package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"math"
)

type macAddressTester struct {
	testBase
}

func (t macAddressTester) run() {

	t.testReverse("1:2:3:4:5:6", false, false)
	t.testReverse("1:1:2:2:3:3", false, false)
	t.testReverse("1:1:1:1:1:1", false, false)
	t.testReverse("0:0:0:0:0:0", true, true)

	t.testReverse("ff:ff:ff:ff:ff:ff", true, true)
	t.testReverse("ff:ff:ff:ff:ff:ff:ff:ff", true, true)

	t.testReverse("ff:80:ff:ff:01:ff", true, false)
	t.testReverse("ff:81:ff:ff:ff:ff", false, true)
	t.testReverse("ff:81:c3:42:24:ff", false, true)
	t.testReverse("ff:1:ff:ff:ff:ff", false, false)

	t.testReverse("11:22:33:44:55:66", false, false)
	t.testReverse("11:11:22:22:33:33", false, false)
	t.testReverse("11:11:22:22:33:33:44:55", false, false)
	t.testReverse("11:11:11:11:11:11:11:11", false, false)
	t.testReverse("0:0:0:0:0:0:00:00", true, true)

	t.testIncrement("ff:ff:ff:ff:f0:0:0:0", 1, "ff:ff:ff:ff:f0:0:0:1")
	t.testIncrement("ff:ff:ff:ff:f0:0:0:0", -1, "ff:ff:ff:ff:ef:ff:ff:ff")
	t.testIncrement("ff:ff:f0:0:0:0", 1, "ff:ff:f0:0:0:1")
	t.testIncrement("ff:ff:f0:0:0:0", -1, "ff:ff:ef:ff:ff:ff")

	t.testIncrement("80:0:0:0:0:0:0:0", math.MinInt64, "0:0:0:0:0:0:0:0")
	t.testIncrement("7f:ff:ff:ff:ff:ff:ff:ff", math.MinInt64, "")
	t.testIncrement("7f:ff:ff:ff:ff:ff:ff:fe", math.MinInt64, "")
	t.testIncrement("0:0:0:0:80:0:0:0", math.MinInt64, "")
	t.testIncrement("80:0:0:0:0:0:0:0", math.MaxInt64, "ff:ff:ff:ff:ff:ff:ff:ff")
	t.testIncrement("80:0:0:0:0:0:0:1", math.MaxInt64, "")

	t.testIncrement("ff:ff:ff:ff:80:0:0:0", -0x80000000, "ff:ff:ff:ff:0:0:0:0")
	t.testIncrement("ff:ff:ff:ff:7f:ff:ff:ff", -0x80000000, "ff:ff:ff:fe:ff:ff:ff:ff")
	t.testIncrement("ff:ff:ff:ff:7f:ff:ff:fe", -0x80000000, "ff:ff:ff:fe:ff:ff:ff:fe")
	t.testIncrement("0:0:0:0:80:0:0:0", -0x80000000, "0:0:0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:0:0:7f:ff:ff:fe", -0x80000000, "")
	t.testIncrement("ff:ff:ff:ff:80:0:0:0", 0x7fffffff, "ff:ff:ff:ff:ff:ff:ff:ff")
	t.testIncrement("ff:ff:ff:ff:80:0:0:1", 0x7fffffff, "")

	t.testIncrement("ff:ff:80:0:0:0", -0x80000000, "ff:ff:0:0:0:0")
	t.testIncrement("ff:ff:7f:ff:ff:ff", -0x80000000, "ff:fe:ff:ff:ff:ff")
	t.testIncrement("ff:ff:7f:ff:ff:fe", -0x80000000, "ff:fe:ff:ff:ff:fe")
	t.testIncrement("0:0:80:0:0:0", -0x80000000, "0:0:0:0:0:0")
	t.testIncrement("0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:7f:ff:ff:ff", -0x80000000, "")
	t.testIncrement("0:0:7f:ff:ff:fe", -0x80000000, "")
	t.testIncrement("ff:ff:80:0:0:0", 0x7fffffff, "ff:ff:ff:ff:ff:ff")
	t.testIncrement("ff:ff:80:0:0:1", 0x7fffffff, "")

	t.testIncrement("0:0:0:0:0:0:0:1", 1, "0:0:0:0:0:0:0:2")
	t.testIncrement("0:0:0:0:0:0:0:1", 0, "0:0:0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:0:0:1", -1, "0:0:0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:0:0:1", -2, "")
	t.testIncrement("0:0:0:0:0:0:0:2", 1, "0:0:0:0:0:0:0:3")
	t.testIncrement("0:0:0:0:0:0:0:2", -1, "0:0:0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:0:0:2", -2, "0:0:0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:0:0:2", -3, "")

	t.testIncrement("0:0:0:0:0:1", 1, "0:0:0:0:0:2")
	t.testIncrement("0:0:0:0:0:1", 0, "0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:1", -1, "0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:1", -2, "")
	t.testIncrement("0:0:0:0:0:2", 1, "0:0:0:0:0:3")
	t.testIncrement("0:0:0:0:0:2", -1, "0:0:0:0:0:1")
	t.testIncrement("0:0:0:0:0:2", -2, "0:0:0:0:0:0")
	t.testIncrement("0:0:0:0:0:2", -3, "")

	t.testIncrement("1:0:0:0:0:0:0:1", 0, "1:0:0:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:0:0:1", 1, "1:0:0:0:0:0:0:2")
	t.testIncrement("1:0:0:0:0:0:0:1", -1, "1:0:0:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:0:0:1", -2, "0:ff:ff:ff:ff:ff:ff:ff")
	t.testIncrement("1:0:0:0:0:0:0:2", 1, "1:0:0:0:0:0:0:3")
	t.testIncrement("1:0:0:0:0:0:0:2", -1, "1:0:0:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:0:0:2", -2, "1:0:0:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:0:0:2", -3, "0:ff:ff:ff:ff:ff:ff:ff")

	t.testIncrement("1:0:0:0:0:1", 0, "1:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:1", 1, "1:0:0:0:0:2")
	t.testIncrement("1:0:0:0:0:1", -1, "1:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:1", -2, "0:ff:ff:ff:ff:ff")
	t.testIncrement("1:0:0:0:0:2", 1, "1:0:0:0:0:3")
	t.testIncrement("1:0:0:0:0:2", -1, "1:0:0:0:0:1")
	t.testIncrement("1:0:0:0:0:2", -2, "1:0:0:0:0:0")
	t.testIncrement("1:0:0:0:0:2", -3, "0:ff:ff:ff:ff:ff")

	t.testIncrement("0:0:0:0:0:0:0:fe", 2, "0:0:0:0:0:0:1:0")
	t.testIncrement("0:0:0:0:0:0:0:ff", 2, "0:0:0:0:0:0:1:1")
	t.testIncrement("0:0:0:0:0:0:1:ff", 2, "0:0:0:0:0:0:2:1")
	t.testIncrement("0:0:0:0:0:0:1:ff", -2, "0:0:0:0:0:0:1:fd")
	t.testIncrement("0:0:0:0:0:0:1:ff", -0x100, "0:0:0:0:0:0:0:ff")
	t.testIncrement("0:0:0:0:0:0:1:ff", -0x101, "0:0:0:0:0:0:0:fe")

	t.testIncrement("0:0:0:0:0:fe", 2, "0:0:0:0:1:0")
	t.testIncrement("0:0:0:0:0:ff", 2, "0:0:0:0:1:1")
	t.testIncrement("0:0:0:0:1:ff", 2, "0:0:0:0:2:1")
	t.testIncrement("0:0:0:0:1:ff", -2, "0:0:0:0:1:fd")
	t.testIncrement("0:0:0:0:1:ff", -0x100, "0:0:0:0:0:ff")
	t.testIncrement("0:0:0:0:1:ff", -0x101, "0:0:0:0:0:fe")

	//TODO
	//t.testPrefixes("25:51:27:12:82:55",
	//	16, -5,
	//	"25:51:27:12:82:55",
	//	"25:51:27:12:82:0",
	//	"25:51:27:12:82:40",
	//	"25:51:0:0:0:0",
	//	"25:51:0:0:0:0")

}

func (t macAddressTester) testReverse(addressStr string, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	str := t.createMACAddress(addressStr)
	//try {
	t.testBase.testReverse(str.GetAddress().ToAddress().Wrap(), bitsReversedIsSame, bitsReversedPerByteIsSame)
	//} catch(RuntimeException e) {
	//addFailure(new Failure("reversal: " + addressStr));
	//}
	t.incrementTestCount()
}

func (t macAddressTester) testIncrement(originalStr string, increment int64, resultStr string) {
	var addr *ipaddr.MACAddress
	if resultStr != "" {
		addr = t.createMACAddress(resultStr).GetAddress()
	}
	t.testBase.testIncrement(t.createMACAddress(originalStr).GetAddress().ToAddress(), increment, addr.ToAddress())
}

//TODO
//func (t macAddressTester) testPrefixes(original string,
//	prefix, adjustment ipaddr.BitCount,
//	next string,
//	previous,
//	adjusted,
//	prefixSet,
//	prefixApplied string) {
//	t.testBase.testPrefixes(t.createMACAddress(original).GetAddress().Wrap(),
//		prefix, adjustment,
//		t.createMACAddress(next).GetAddress().Wrap(),
//		t.createMACAddress(previous).GetAddress().Wrap(),
//		t.createMACAddress(adjusted).GetAddress().Wrap(),
//		t.createMACAddress(prefixSet).GetAddress().Wrap(),
//		t.createMACAddress(prefixApplied).GetAddress().Wrap())
//	t.incrementTestCount()
//}
