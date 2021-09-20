package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"strings"
)

//TODO I decided to start with IPAddresstester.runTest and go in order there
//But also handling the same tests in the other testers (so not in order in the other ones)
// So I will need to survey the other oneslater to see what I missed in the others

type ipAddressTester struct {
	testBase
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

	t.testReverse("255.127.128.255", false, false)
	t.testReverse("255.127.128.255/16", false, false)
	t.testReverse("1.2.3.4", false, false)
	t.testReverse("1.1.2.2", false, false)
	t.testReverse("1.1.1.1", false, false)
	t.testReverse("0.0.0.0", true, true)

	t.testReverse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, true)
	t.testReverse("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff", false, false)
	t.testReverse("ffff:ffff:8181:ffff:ffff:ffff:ffff:ffff", false, true)
	t.testReverse("ffff:ffff:c3c3:ffff:ffff:ffff:ffff:ffff", false, true)
	t.testReverse("ffff:4242:c3c3:2424:ffff:ffff:ffff:ffff", false, true)
	t.testReverse("ffff:ffff:8000:ffff:ffff:0001:ffff:ffff", true, false)
	t.testReverse("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff/64", false, false)
	t.testReverse("1:2:3:4:5:6:7:8", false, false)
	t.testReverse("1:1:2:2:3:3:4:4", false, false)
	t.testReverse("1:1:1:1:1:1:1:1", false, false)
	t.testReverse("::", true, true)
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
				direct = t.createAddress(bareHost + "/" + minPrefix.String())
				directAddress = direct.GetAddress()
				if h1.IsPrefixed() && h1.IsPrefixBlock() {
					directAddress = makePrefixSubnet(directAddress)
				}
				//if equiv == nil {
				//	if prefixed != nil {
				//		t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				//	}
				//} else if !directAddress.Equals(minPrefixed) {
				//	t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				//}
				if !directAddress.Equals(minPrefixed) {
					t.addFailure(newIPAddrFailure("failed: prefix expected: "+direct.String(), minPrefixed))
				}
			}
		}
	}
	t.incrementTestCount()
}
func (t ipAddressTester) testReverse(addressStr string, bitsReversedIsSame, bitsReversedPerByteIsSame bool) {
	str := t.createAddress(addressStr)
	addr := str.GetAddress()
	//try {
	t.testBase.testReverse(ipaddr.WrappedAddress{addr.ToAddress()}, bitsReversedIsSame, bitsReversedPerByteIsSame)
	//} catch(RuntimeException e) {
	//	addFailure(new Failure("reversal: " + addressStr));
	//}
	t.incrementTestCount()
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
