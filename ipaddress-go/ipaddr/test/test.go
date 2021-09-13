package main

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"math/big"
	"strings"
)

type ipAddressTester struct {
	testInterface
}

func (t ipAddressTester) run() {
	t.testEquivalentPrefix("1.2.3.4", 32)

	t.testEquivalentPrefix("0.0.0.0/1", 1)
	t.testEquivalentPrefix("128.0.0.0/1", 1)
	t.testEquivalentPrefix("1.2.0.0/15", 15)
	t.testEquivalentPrefix("1.2.0.0/16", 16)
	t.testEquivalentPrefix("1:2::/32", 32)
	t.testEquivalentPrefix("8000::/1", 1)
	t.testEquivalentPrefix("1:2::/31", 31)
	t.testEquivalentPrefix("1:2::/34", 34)

	t.testEquivalentPrefix("1.2.3.4/32", 32)

	t.testEquivalentPrefix("1.2.3.4/1", 32)
	t.testEquivalentPrefix("1.2.3.4/15", 32)
	t.testEquivalentPrefix("1.2.3.4/16", 32)
	t.testEquivalentPrefix("1.2.3.4/32", 32)
	t.testEquivalentPrefix("1:2::/1", 128)

	t.testEquivalentPrefix("1:2::/128", 128)
}

func (t ipAddressTester) testEquivalentPrefix(host string, prefix ipaddr.BitCount) {
	t.testEquivalentMinPrefix(host, cacheTestBits(prefix), prefix)
}

func (t ipAddressTester) testEquivalentMinPrefix(host string, equivPrefix ipaddr.PrefixLen, minPrefix ipaddr.BitCount) {
	str := t.createAddress(host)
	h1, err := str.ToAddress()
	if err != nil {
		t.addFailure(newFailure("failed "+err.Error(), str))
		return
	}
	equiv := h1.GetPrefixLenForSingleBlock()
	if !equivPrefix.Equals(equiv) {
		t.addFailure(newIPAddrFailure("failed: prefix expected: "+equivPrefix.String()+" prefix got: "+equiv.String(), h1))
	} else {
		prefixed := h1.AssignPrefixForSingleBlock()
		bareHost := host
		index := strings.Index(host, "/")
		if index >= 0 {
			bareHost = host[:index]
		}
		direct := t.createAddress(bareHost + "/" + equivPrefix.String())
		directAddress := direct.GetAddress()
		if equivPrefix != nil && h1.IsPrefixed() && h1.IsPrefixBlock() {
			directAddress = makePrefixSubnet(directAddress)
		}
		var isFailed bool
		if equiv == nil {
			isFailed = prefixed != nil
		} else {
			isFailed = !directAddress.Equals(prefixed)
		}
		if isFailed {
			t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), prefixed))
		} else {
			minPref := h1.GetMinPrefixLenForBlock()
			if minPref != minPrefix {
				t.addFailure(newIPAddrFailure("failed: prefix expected: "+minPrefix.String()+" prefix got: "+minPref.String(), h1))
			} else {
				minPrefixed := h1.AssignMinPrefixForBlock()
				bareHost := host
				index := strings.Index(host, "/")
				if index >= 0 {
					bareHost = host[:index]
				}
				direct = t.createAddress(bareHost + "/" + equivPrefix.String())
				directAddress = direct.GetAddress()
				if h1.IsPrefixed() && h1.IsPrefixBlock() {
					directAddress = makePrefixSubnet(directAddress)
				}
				if !directAddress.Equals(minPrefixed) {
					t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				}
			}
		}
	}
	t.incrementTestCount()
}

var cachedPrefixLens = initPrefLens()

func initPrefLens() []ipaddr.PrefixLen {
	cachedPrefLens := make([]ipaddr.PrefixLen, ipaddr.IPv6BitCount+1)
	for i := ipaddr.BitCount(0); i <= ipaddr.IPv6BitCount; i++ {
		bc := i
		cachedPrefLens[i] = &bc
	}
	return cachedPrefLens
}

func cacheTestBits(i ipaddr.BitCount) ipaddr.PrefixLen {
	if i >= 0 && int(i) < len(cachedPrefixLens) {
		return cachedPrefixLens[i]

	}
	return &i
}

func makePrefixSubnet(directAddress *ipaddr.IPAddress) *ipaddr.IPAddress {
	segs := directAddress.GetSegments()
	pref := directAddress.GetPrefixLen()
	prefSeg := int(*pref / directAddress.GetBitsPerSegment())
	if prefSeg < len(segs) {
		creator := ipaddr.IPAddressCreator{directAddress.GetIPVersion()}
		if directAddress.GetPrefixCount().Cmp(bigOneConst()) == 0 {
			origSeg := segs[prefSeg]
			mask := origSeg.GetSegmentNetworkMask(*pref % directAddress.GetBitsPerSegment())

			segs[prefSeg] = creator.CreateSegment(origSeg.GetSegmentValue()&mask, origSeg.GetUpperSegmentValue()&mask, origSeg.GetSegmentPrefixLen())
			for ps := prefSeg + 1; ps < len(segs); ps++ {
				segs[ps] = creator.CreatePrefixSegment(0, cacheTestBits(0))
			}
			bytes := make([]byte, directAddress.GetByteCount())
			bytesPerSegment := directAddress.GetBytesPerSegment()
			for i, j := 0, 0; i < len(segs); i++ {
				segs[i].CopyBytes(bytes[j:])
				j += bytesPerSegment
			}
			directAddress = creator.FromPrefixedIP(bytes, pref)
		} else {
			//we could have used SegmentValueProvider in both blocks, but mixing it up to test everything
			origSeg := segs[prefSeg]
			mask := origSeg.GetSegmentNetworkMask(*pref % directAddress.GetBitsPerSegment())
			maxValue := directAddress.GetMaxSegmentValue()
			directAddress = creator.FromPrefixedVals(
				func(segmentIndex int) ipaddr.SegInt {
					if segmentIndex < prefSeg {
						return segs[segmentIndex].GetSegmentValue()
					} else if segmentIndex == prefSeg {
						return origSeg.GetSegmentValue() & mask
					} else {
						return 0
					}
				},
				func(segmentIndex int) ipaddr.SegInt {
					if segmentIndex < prefSeg {
						return segs[segmentIndex].GetUpperSegmentValue()
					} else if segmentIndex == prefSeg {
						return origSeg.GetUpperSegmentValue() & mask
					} else {
						return maxValue
					}
				},
				pref,
			)
		}
	}
	return directAddress
}

type ipAddressRangeTester struct {
	ipAddressTester
}

func (t ipAddressRangeTester) run() {
	t.testEquivalentPrefix("*.*.*.*", 0)
	t.testEquivalentPrefix("0-127.*.*.*", 1)
	t.testEquivalentPrefix("128-255.*.*.*", 1)
	t.testEquivalentPrefix("*.*.*.*/1", 0)
	t.testEquivalentPrefix("0.*.*.*/1", 1)
	t.testEquivalentPrefix("128-255.*.*.*/1", 1)
	t.testEquivalentPrefix("1.2.*.*", 16)
	t.testEquivalentPrefix("1.2.*.*/24", 16)
	t.testEquivalentMinPrefix("1.2.*.0/24", cacheTestBits(16), 16)
	t.testEquivalentMinPrefix("1.2.0-255.0/24", cacheTestBits(16), 16)
	t.testEquivalentPrefix("1.2.1.0/24", 24)
	t.testEquivalentPrefix("1.2.1.*/24", 24)
	t.testEquivalentPrefix("1.2.1.*", 24)
	t.testEquivalentMinPrefix("1.2.*.4", nil, 32)
	t.testEquivalentPrefix("1.2.252-255.*", 22)
	t.testEquivalentPrefix("1.2.252-255.0-255", 22)
	t.testEquivalentPrefix("1.2.0-3.0-255", 22)
	t.testEquivalentPrefix("1.2.128-131.0-255", 22)
	t.testEquivalentMinPrefix("1.2.253-255.0-255", nil, 24)
	t.testEquivalentMinPrefix("1.2.252-255.0-254", nil, 32)
	t.testEquivalentMinPrefix("1.2.251-255.0-254", nil, 32)
	t.testEquivalentMinPrefix("1.2.251-255.0-255", nil, 24)

	t.testEquivalentMinPrefix("1.2.1-3.*", nil, 24)
	t.testEquivalentPrefix("1.2.0-3.*", 22)

	t.testEquivalentPrefix("*:*", 0)
	t.testEquivalentPrefix("::/0", 0)
	t.testEquivalentMinPrefix("0-1::/0", nil, 128)
	t.testEquivalentPrefix("::/1", 1)
	t.testEquivalentMinPrefix("0-1::/1", nil, 128)
	t.testEquivalentMinPrefix("8000-ffff::/1", nil, 128)
	t.testEquivalentPrefix("8000-ffff:*", 1)
	t.testEquivalentMinPrefix("7fff-ffff:*", nil, 16)
	t.testEquivalentMinPrefix("7fff-ffff:*/1", nil, 16)
	t.testEquivalentPrefix("11:8000-ffff:*/1", 17)
	t.testEquivalentPrefix("11:8000-ffff:*", 17)
	t.testEquivalentPrefix("1:2:*", 32)
	t.testEquivalentMinPrefix("1:2:*:*::/64", cacheTestBits(32), 32)
	t.testEquivalentPrefix("1:2:*:*/64", 32)
	t.testEquivalentPrefix("1:2:3:4:5:*:*/64", 80)
	t.testEquivalentMinPrefix("1:2:*::/64", nil, 64)
	t.testEquivalentMinPrefix("1:2:*::", nil, 128)
	t.testEquivalentPrefix("1:2:8000-ffff:*", 33)
	t.testEquivalentPrefix("1:2:0000-7fff:*", 33)
	t.testEquivalentPrefix("1:2:c000-ffff:*", 34)
	t.testEquivalentPrefix("1:2:0000-3fff:*", 34)
	t.testEquivalentPrefix("1:2:8000-bfff:*", 34)
	t.testEquivalentPrefix("1:2:4000-7fff:*", 34)
	t.testEquivalentPrefix("1:2:fffc-ffff:*", 46)
	t.testEquivalentPrefix("1:2:fffc-ffff:0-ffff:*", 46)
	t.testEquivalentMinPrefix("1:2:fffd-ffff:0-ffff:*", nil, 48)
	t.testEquivalentMinPrefix("1:2:fffc-ffff:0-fffe:*", nil, 64)
	t.testEquivalentMinPrefix("1:2:fffb-ffff:0-fffe:*", nil, 64)
	t.testEquivalentMinPrefix("1:2:fffb-ffff:0-ffff:*", nil, 48)
}

type macAddressTester struct {
	testInterface
}

type macAddressRangeTester struct {
	macAddressTester
}

func (t macAddressRangeTester) testEquivalentPrefix(host string, prefix ipaddr.BitCount) {
	t.testEquivalentMinPrefix(host, cacheTestBits(prefix), prefix)
}

func (t macAddressRangeTester) testEquivalentMinPrefix(host string, equivPrefix ipaddr.PrefixLen, minPrefix ipaddr.BitCount) {
	str := t.createMACAddress(host)
	//try {
	h1, err := str.ToAddress()
	if err != nil {
		t.addFailure(newMACFailure("failed "+err.Error(), str))
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
		//} catch(AddressStringException e) {
		//	addFailure(new Failure("failed " + e, str));
		//} catch(IncompatibleAddressException e) {
		//	addFailure(new Failure("failed " + e, str));
		//}
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
}

func bigOne() *big.Int {
	return big.NewInt(1)
}

var one = bigOne()

func bigOneConst() *big.Int {
	return one
}
