package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
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
}

func (t macAddressTester) testReverse(addressStr string, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	str := t.createMACAddress(addressStr)
	//try {
	t.testBase.testReverse(ipaddr.WrappedAddress{str.GetAddress().ToAddress()}, bitsReversedIsSame, bitsReversedPerByteIsSame)
	//} catch(RuntimeException e) {
	//addFailure(new Failure("reversal: " + addressStr));
	//}
	t.incrementTestCount()
}
