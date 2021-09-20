package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
)

type macAddressRangeTester struct {
	macAddressTester
}

func (t macAddressRangeTester) testEquivalentPrefix(host string, prefix ipaddr.BitCount) {
	t.testEquivalentMinPrefix(host, cacheTestBits(prefix), prefix)
}

func (t macAddressRangeTester) testEquivalentMinPrefix(host string, equivPrefix ipaddr.PrefixLen, minPrefix ipaddr.BitCount) {
	str := t.createMACAddress(host)
	h1, err := str.ToAddress()
	if err != nil {
		t.addFailure(newMACFailure(err.Error(), str))
	} else {
		equiv := h1.GetPrefixLenForSingleBlock()
		if !equivPrefix.Equals(equiv) {
			t.addFailure(newMACAddrFailure("failed: prefix expected: "+equivPrefix.String()+" prefix got: "+equiv.String(), h1))
		} else {
			minPref := h1.GetMinPrefixLenForBlock()
			if minPref != minPrefix {
				t.addFailure(newMACAddrFailure("failed: prefix expected: "+minPrefix.String()+" prefix got: "+minPref.String(), h1))
			}
		}
	}
	t.incrementTestCount()
}

func (t macAddressRangeTester) run() {
	t.testEquivalentPrefix("*:*", 0)
	t.testEquivalentPrefix("*:*:*:*:*:*", 0)
	t.testEquivalentPrefix("*:*:*:*:*:*:*:*", 0)
	t.testEquivalentPrefix("80-ff:*", 1)
	t.testEquivalentPrefix("0-7f:*", 1)
	t.testEquivalentPrefix("1:2:*", 16)
	t.testEquivalentPrefix("1:2:*:*:*:*", 16)
	t.testEquivalentMinPrefix("1:2:*:0:*:*", nil, 32)
	t.testEquivalentMinPrefix("1:2:*:0:0:0", nil, 48)

	t.testEquivalentPrefix("1:2:80-ff:*", 17)
	t.testEquivalentPrefix("1:2:00-7f:*", 17)
	t.testEquivalentPrefix("1:2:c0-ff:*", 18)
	t.testEquivalentPrefix("1:2:00-3f:*", 18)
	t.testEquivalentPrefix("1:2:80-bf:*", 18)
	t.testEquivalentPrefix("1:2:40-7f:*", 18)
	t.testEquivalentPrefix("1:2:fc-ff:*", 22)
	t.testEquivalentPrefix("1:2:fc-ff:0-ff:*", 22)
	t.testEquivalentMinPrefix("1:2:fd-ff:0-ff:*", nil, 24)
	t.testEquivalentMinPrefix("1:2:fc-ff:0-fe:*", nil, 32)
	t.testEquivalentMinPrefix("1:2:fb-ff:0-fe:*", nil, 32)
	t.testEquivalentMinPrefix("1:2:fb-ff:0-ff:*", nil, 24)

	t.testReverse("1:2:*:4:5:6", false, false)
	t.testReverse("1:1:1-ff:2:3:3", false, false)
	t.testReverse("1:1:0-fe:1-fe:*:1", false, false)
	t.testReverse("ff:80:*:ff:01:ff", false, false)
	t.testReverse("ff:80:fe:7f:01:ff", true, false)
	t.testReverse("ff:80:*:*:01:ff", true, false)
	t.testReverse("ff:81:ff:*:1-fe:ff", false, true)
	t.testReverse("ff:81:c3:42:24:0-fe", false, true)
	t.testReverse("ff:1:ff:ff:*:*", false, false)
}
