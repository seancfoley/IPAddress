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

	t.testPrefixes("255.127.128.255",
		16, -5,
		"255.127.128.255",
		"255.127.128.255/32",
		"255.127.128.255/27",
		"255.127.128.255/16",
		"255.127.128.255/16")

	t.testPrefixes("255.127.128.255/32",
		16, -5,
		"255.127.128.255",
		"255.127.128.0/24",
		"255.127.128.224/27", //xxx need to specify the non prefix subnet xxxx (224-224) range
		"255.127.0.0/16",
		"255.127.0.0/16")

	t.testPrefixes("255.127.0.0/16",
		18, 17,
		"255.127.0.0/24",
		"255.0.0.0/8",
		"255.127.0.0",
		"255.127.0.0/18",
		"255.127.0.0/16")

	t.testPrefixes("255.127.0.0/16",
		18, 16,
		"255.127.0.0/24",
		"255.0.0.0/8",
		"255.127.0.0/32",
		"255.127.0.0/18",
		"255.127.0.0/16")

	t.testPrefixes("254.0.0.0/7",
		18, 17,
		"254.0.0.0/8",
		"0.0.0.0/0",
		"254.0.0.0/24",
		"254.0.0.0/18",
		"254.0.0.0/7")

	t.testPrefixes("254.255.127.128/7",
		18, 17,
		"254.255.127.128/8",
		"0.255.127.128/0",
		"254.0.0.128/24",
		"254.0.63.128/18",
		"254.255.127.128/7")

	t.testPrefixes("254.255.127.128/23",
		18, 17,
		"254.255.126.128/24",
		"254.255.1.128/16",
		"254.255.126.0/32",
		"254.255.65.128/18",
		"254.255.65.128/18")

	t.testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		16, -5,
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/123",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/16",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/16")

	t.testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		16, -5,
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:0/112",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0/123",
		"ffff::/16",
		"ffff::/16")

	t.testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		15, 1,
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/15",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/15")

	t.testPrefixes("ffff:ffff:1:ffff:ffff:ffff:1:ffff/64",
		16, -5,
		"ffff:ffff:1:ffff:0:ffff:1:ffff/80",
		"ffff:ffff:1::ffff:ffff:1:ffff/48",
		"ffff:ffff:1:ffe0:ffff:ffff:1:ffff/59",
		"ffff::ffff:ffff:1:ffff/16",
		"ffff::ffff:ffff:1:ffff/16")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		16, -5,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"ffff:ffff:1:ffc1::/58",
		"ffff:0:0:1::/16",
		"ffff:0:0:1::/16")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		17, -64,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"0:0:0:1::/0",
		"ffff:8000:0:1::/16",
		"ffff:8000:0:1::/16")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		15, -63,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"0:0:0:1::/0",
		"fffe:0:0:1::/15",
		"fffe:0:0:1::/15")

	t.testPrefixes("ffff:ffff:1:ffff::/63",
		65, 1,
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:1::/48",
		"ffff:ffff:1:fffe::/64",
		"ffff:ffff:1:fffe::/65",
		"ffff:ffff:1:ffff::/63")

	t.testPrefixes("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff/128",
		127, 1,
		"ffff:ffff:1:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:1:ffff:ffff:ffff:ffff::/112",
		"ffff:ffff:1:ffff:ffff:ffff:ffff:ffff",
		"ffff:ffff:1:ffff:ffff:ffff:ffff:fffe/127",
		"ffff:ffff:1:ffff:ffff:ffff:ffff:fffe/127")
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
		equiv = h1.GetPrefixLenForSingleBlock()
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
					// orig "1:2:*::/64" failed: expected match between: 1:2:*::*:*:*/64 and 1:2:*::/64
					t.addFailure(newIPAddrFailure("failed: expected match between: "+directAddress.String()+" and "+minPrefixed.String(), minPrefixed))
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

func (t ipAddressTester) testPrefixes(
	orig string,
	prefix, adjustment ipaddr.BitCount,
	next,
	previous,
	adjusted,
	prefixSet,
	prefixApplied string) {
	original := t.createAddress(orig).GetAddress()
	if original.IsPrefixed() {
		removed := original.WithoutPrefixLen()
		for i := 0; i < removed.GetSegmentCount(); i++ {
			if !removed.GetSegment(i).Equals(original.GetSegment(i)) {
				t.addFailure(newIPAddrFailure("removed prefix: "+removed.String(), original))
				break
			}
		}
	}
	t.testBase.testPrefixes(original.Wrap(), // OK make it return WrappedAddress
		//t.testBase.testPrefixes(ipaddr.WrappedAddress{original.ToAddress()},
		prefix, adjustment,
		t.createAddress(next).GetAddress().Wrap(),
		t.createAddress(previous).GetAddress().Wrap(),
		t.createAddress(adjusted).GetAddress().Wrap(),
		t.createAddress(prefixSet).GetAddress().Wrap(),
		t.createAddress(prefixApplied).GetAddress().Wrap())
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
			//maxValue := directAddress.GetMaxSegmentValue()
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
						return 0
					}
				},
				pref,
			)
		}
	}
	return directAddress
}

//void testBitwiseOr(String orig, Integer prefixAdjustment, String or, String expectedResult) {
//		IPAddress original = createAddress(orig).getAddress();
//		IPAddress orAddr = createAddress(or).getAddress();
//		if(prefixAdjustment != null) {
//			original = original.adjustPrefixLength(prefixAdjustment);
//		}
//		try {
//			IPAddress result = original.bitwiseOr(orAddr);
//			if(expectedResult == null) {
//				original.bitwiseOr(orAddr);
//				addFailure(new Failure("ored expected throw " + original + " orAddr: " + orAddr + " result: " + result, original));
//			} else {
//				IPAddress expectedResultAddr = createAddress(expectedResult).getAddress();
//				if(!expectedResultAddr.equals(result)) {
//					addFailure(new Failure("ored expected: " + expectedResultAddr + " actual: " + result, original));
//				}
//				if(result.getPrefixLength() != null) {
//					addFailure(new Failure("ored expected null prefix: " + expectedResultAddr + " actual: " + result.getPrefixLength(), original));
//				}
//			}
//		} catch(IncompatibleAddressException e) {
//			if(expectedResult != null) {
//				addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
//			}
//		}
//		incrementTestCount();
//	}
//
//	void testPrefixBitwiseOr(String orig, Integer prefix, String or, String expectedNetworkResult) {
//		testPrefixBitwiseOr(orig, prefix, or, expectedNetworkResult, null);
//	}
//
//	void testPrefixBitwiseOr(String orig, int prefix, String or, String expectedNetworkResult, String expectedFullResult) {
//		IPAddress original = createAddress(orig).getAddress();
//		IPAddress orAddr = createAddress(or).getAddress();
//		try {
//			IPAddress result = original.bitwiseOrNetwork(orAddr, prefix);
//			if(expectedNetworkResult == null) {
//				addFailure(new Failure("ored network expected throw " + original + " orAddr: " + orAddr + " result: " + result, original));
//			} else {
//				IPAddressString expected = createAddress(expectedNetworkResult);
//				IPAddress expectedResultAddr = expected.getAddress();
//				if(!expectedResultAddr.isPrefixed() || expectedResultAddr.getPrefixLength() != prefix) {
//					expectedResultAddr = expectedResultAddr.setPrefixLength(prefix, false, false);
//				}
//				if(!expectedResultAddr.equals(result)) {
//					result = original.bitwiseOrNetwork(orAddr, prefix); // 3rd seg not pref block in result, which is right because 3rd seg in original was not
//					//but 4th seg in result is pref block, which is also right, while not the base with the expected
//					addFailure(new Failure("ored network expected: " + expectedResultAddr + " actual: " + result, original));
//				}
//				if(!Objects.equals(expectedResultAddr.getPrefixLength(), result.getPrefixLength())) {
//					//result = original.bitwiseOrNetwork(orAddr, prefix);
//					addFailure(new Failure("ored network expected pl: " + expectedResultAddr.getPrefixLength() + " actual: " + result.getPrefixLength(), original));
//				}
//			}
//		} catch(IncompatibleAddressException e) {
//			if(expectedNetworkResult != null) {
//				addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
//			}
//		}
//		try {
//			IPAddress result = original.bitwiseOr(orAddr, true);
//			if(expectedFullResult == null) {
//				addFailure(new Failure("ored expected throw " + original + " orAddr: " + orAddr + " result: " + result, original));
//			} else {
//				IPAddressString expected = createAddress(expectedFullResult);
//				IPAddress expectedResultAddr = expected.getAddress();
//				if(!expectedResultAddr.equals(result) || !Objects.equals(expectedResultAddr.getPrefixLength(), result.getPrefixLength())) {
//					result = original.bitwiseOr(orAddr, true);
//					addFailure(new Failure("ored expected: " + expectedResultAddr + " actual: " + result, original));
//				}
//			}
//		} catch(IncompatibleAddressException e) {
//			if(expectedFullResult != null) {
//				addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
//			}
//		}
//		incrementTestCount();
//	}
