package test

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
)

type hostRangeTester struct {
	hostTester
}

func (t hostRangeTester) run() {

	t.testMatches(true, "1.*.*.*/255.0.0.0", "1.0.0.0/255.0.0.0")
	t.testMatches(true, "1.0.0.0/8", "1.0.0.0/255.0.0.0")

	t.testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4")
	t.testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4")
	t.testMatches(true, "1.2.3.4/255.0.0.0", "1.2.3.4")

	t.testMatches(true, "1.0.0.0/255.0.0.0", "1.*.*.*")
	t.testMatches(true, "1.0.0.0/255.0.0.0", "1.*.___.*")
	t.testMatches(false, "1.0.0.0/255.0.0.0", "1.0-255.*.*") //failing due to the options
	t.testMatchesParams(true, "1.0.0.0/255.0.0.0", "1.0-255.*.*", hostWildcardAndRangeOptions)

	t.testMatchesParams(true, "1-2.0-0.00-00.00-0", "1-2.0.0.0", hostWildcardAndRangeOptions)
	t.testMatchesParams(true, "1-2:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "1-2:0:0:0:0:0:0:0", hostWildcardAndRangeOptions)
	t.testMatchesParams(true, "00-0.0-0.00-00.00-0", "0.0.0.0", hostWildcardAndRangeOptions)
	t.testMatchesParams(true, "0-00:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "::", hostWildcardAndRangeOptions)

	t.testResolved("a::b:*:d:1.2.*%x", "a::b:*:d:1.2.*%x")
	t.testResolved("[a::b:*:d:1.2.*%x]", "a::b:*:d:1.2.*%x")
	t.testResolved("[a::*:c:d:1.*.3.4]", "a::*:c:d:1.*.3.4")
	t.testResolved("2001:0000:1234:0000:*:C1C0:ABCD:0876%x", "2001:0:1234:0:*:c1c0:abcd:876%x")
	t.testResolved("[2001:*:1234:0000:0000:C1C0:ABCD:0876%x]", "2001:*:1234::C1C0:abcd:876%x")
	t.testResolved("[2001:0000:*:0000:0000:C1C0:ABCD:0876]", "2001:0:*::C1C0:abcd:876")
	t.testResolved("2001:0000:*:0000:0000:C1C0:ABCD:0876", "2001:0:*::C1C0:abcd:876")
	t.testResolved("1.2.*.04", "1.2.*.4")
	t.testResolved_inet_aton("1.*.0-255.3", "1.*.*.3")
	t.testResolved_inet_aton("1.*.3", "1.*.0.3")
	t.testResolved("[1.2.*.4]", "1.2.*.4")

	t.testResolved("espn.*.com", "") //no wildcards for hosts, just addresses
	t.testResolved("*.instapundit.com", "")
	t.testResolved("es*n.com", "")
	t.testResolved("inst*undit.com", "")

	if t.fullTest && runDNS {
		t.testResolved("espn.com/24", "199.181.132.*")
	}

	t.testResolved("3*", "")
	t.testResolved("*", "*")
	t.testResolved("3.*", "3.*.*.*")
	t.testResolved("3:*", "3:*:*:*:*:*:*:*")
	t.testResolved("9.*.237.26", "9.*.237.26")
	t.testResolved("*.70.146.*", "*.70.146.*")

	t.hostLabelsTest("*", []string{"*"})
	t.hostLabelsTest("**", []string{"*"})

	t.hostTest(true, "1.2.3.4/1.2.3.4")
	t.hostTest(false, "1.2.3.4/*")
	t.hostTest(false, "1.*.3.4/*")
	t.hostTest(true, "1.*.3.4")
	t.hostTest(true, "1:*:3:4")

	t.testMasked("1.*.3.4", "", nil, "1.*.3.4")
	t.testMasked("1.*.3.4/255.255.1.0", "255.255.1.0", nil, "1.*.1.0")
	t.testMasked("1.*.3.4/255.255.254.0", "255.255.254.0", p23, "1.*.3.4/23")

	t.testMasked("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "", nil, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	t.testMasked("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0:101:0:101:0:101:0:101", "0:101:0:101:0:101:0:101", nil, "0:101:0:101:0:101:0:101")
	t.testMasked("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:8000::", "ffff:ffff:8000::", p33, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/33")
	t.testMasked("ffff:ffff::/ffff:ffff:8000::", "ffff:ffff:8000::", p33, "ffff:ffff::/33")

	t.testMasked("bla.com/ffff:ffff:8000::", "ffff:ffff:8000::", p33, "")
	t.testMasked("bla.com", "", nil, "")

	t.testHostOrWildcardAddress("1_.2.3.4", 4, "1_.2.3.4", "10-19.2.3.4")
	t.testHostOrRangeAddress("1-2.2.3.4", 4, "1-2.2.3.4", "1-2.2.3.4")
	t.testHostOrAddress_inet_aton("1-9.1-2", 2, 4, "1-9.1-2", "1-9.0.0.1-2")
	t.testHostOrAddress_inet_aton("1-9.0x1-0x22", 2, 4, "1-9.0x1-0x22", "1-9.0.0.1-34")
	t.testHostOrAddress_inet_aton("1-9.0x1-0x22", 2, 4, "1-9.0x1-0x22", "1-9.0.0.1-34")
	t.testHostOrAddress_inet_aton("9-1.0X1-0x22", 2, 4, "9-1.0x1-0x22", "1-9.0.0.1-34")
	t.testHostOrAddress_inet_aton("9-1.0X1-0X22", 2, 4, "9-1.0x1-0x22", "1-9.0.0.1-34")
	t.testHostOnly("9-1g.0x1-0x22", 2, "9-1g.0x1-0x22", "")
	t.testHostOrAddress_inet_aton("1-9.0x1-0x22.03.04", 4, 4, "1-9.0x1-0x22.03.04", "1-9.1-34.3.4")
	t.testAddress("1::2", 8, "[1:0:0:0:0:0:0:2]", "1:0:0:0:0:0:0:2")
	t.testAddress("1.2.3.4", 4, "1.2.3.4", "1.2.3.4")

	t.hostTester.run()
}

func (t hostRangeTester) testMatches(matches bool, host1, host2 string) {
	t.testMatchesParams(matches, host1, host2, hostWildcardOptions)
}

func (t hostRangeTester) testHostAndAddress(h *ipaddr.HostName, hostLabelCount, addressLabelCount int, isValidHost, isValidAddress bool, normalizedHostString, normalizedAddressString string) {
	if h.IsValid() != isValidHost {
		t.addFailure(newHostFailure("unexpected invalid host", h))
	} else {
		var expectedLen int
		if isValidAddress {
			expectedLen = addressLabelCount
		} else if isValidHost {
			expectedLen = hostLabelCount
		} else {
			expectedLen = 1
		}
		if len(h.GetNormalizedLabels()) != expectedLen {
			t.addFailure(newHostFailure(fmt.Sprintf("labels length is %v expected %v", len(h.GetNormalizedLabels()), expectedLen), h))
		} else {
			addr := h.AsAddress()
			if isValidAddress != h.IsAddress() {
				t.addFailure(newHostFailure("not address "+addr.String(), h))
			} else if isValidAddress != (addr != nil) {
				t.addFailure(newHostFailure("addr is "+addr.String(), h))
			} else if isValidAddress && addr.ToNormalizedString() != normalizedAddressString {
				t.addFailure(newHostFailure("addr string is "+addr.ToNormalizedString()+" expected "+normalizedAddressString, h))
			} else {
				nhString := h.ToNormalizedString()
				var expected string
				if h.IsAddress() && addr.IsIPv6() {
					if isValidHost {
						expected = normalizedHostString
					} else {
						expected = h.String()
					}
				} else {
					if isValidAddress {
						expected = normalizedAddressString
					} else if isValidHost {
						expected = normalizedHostString
					} else {
						expected = h.String()
					}
				}
				if nhString != expected {
					t.addFailure(newHostFailure("host string is "+nhString+" expected "+expected, h))
				}
			}
		}
	}
	t.incrementTestCount()
}

func (t hostRangeTester) testHostOrAddress_inet_aton(x string, hostLabelCount, addressLabelCount int, normalizedHostString, normalizedAddressString string) {
	t.testHostAndAddressAll(x, hostLabelCount, addressLabelCount, true, false, false, true, normalizedHostString, normalizedAddressString)
}

func (t hostRangeTester) testHostOrRangeAddress(x string, labelCount int, normalizedHostString, normalizedAddressString string) {
	t.testHostAndAddressAll(x, labelCount, labelCount, true, false, true, true, normalizedHostString, normalizedAddressString)
}

func (t hostRangeTester) testHostOrWildcardAddress(x string, labelCount int, normalizedHostString, normalizedAddressString string) {
	t.testHostAndAddressAll(x, labelCount, labelCount, true, true, true, true, normalizedHostString, normalizedAddressString)
}

func (t hostRangeTester) testAddress(x string, labelCount int, normalizedHostString, normalizedAddressString string) {
	t.testHostAndAddressAll(x, labelCount, labelCount, false, true, true, true, normalizedHostString, normalizedAddressString)
}

func (t hostRangeTester) testHostOnly(x string, labelCount int, normalizedHostString, normalizedAddressString string) {
	t.testHostAndAddressAll(x, labelCount, labelCount, true, false, false, false, normalizedHostString, normalizedAddressString)
}

func (t hostRangeTester) testHostAndAddressAll(x string, hostLabelCount, addressLabelCount int, isHostName, isAddressNotRanged, isRangeAddress,
	is_inet_aton_RangeAddress bool,
	normalizedHostString, normalizedAddressString string) {
	//we want to handle 4 cases
	//1. a.b.com host only
	//2. 1:: address
	//3. a-b.c__ either way inet_aton
	//4. a-b.c__.3.4 either way

	h := t.createParamsHost(x, hostOnlyOptions)
	t.testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName, false, normalizedHostString, normalizedAddressString)

	isAddress := isAddressNotRanged
	h = t.createParamsHost(x, hostWildcardOptions)
	t.testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName || isAddress, isAddress, normalizedHostString, normalizedAddressString)

	isAddress = isAddressNotRanged || isRangeAddress
	h = t.createParamsHost(x, hostWildcardAndRangeOptions)
	t.testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName || isAddress, isAddress, normalizedHostString, normalizedAddressString)

	isAddress = isAddressNotRanged || isRangeAddress || is_inet_aton_RangeAddress
	h = t.createParamsHost(x, hostWildcardAndRangeInetAtonOptions)
	t.testHostAndAddress(h, hostLabelCount, addressLabelCount, isHostName || isAddress, isAddress, normalizedHostString, normalizedAddressString)
}

func (t hostRangeTester) testMasked(masked, mask string, prefixLength ipaddr.PrefixLen, result string) {
	maskedHostStr := t.createHost(masked)
	var maskAddr *ipaddr.IPAddress
	if mask != "" {
		maskAddr = t.createAddress(mask).GetAddress()
	}
	if result != "" {
		resultAddr := t.createAddress(result).GetAddress()
		maskedAddr := maskedHostStr.GetAddress()
		if !maskedAddr.Equals(resultAddr) {
			t.addFailure(newIPAddrFailure("masked "+maskedAddr.String()+" instead of expected "+resultAddr.String(), maskedAddr))
		}
	}
	if !addressesEqual(maskAddr, maskedHostStr.GetMask()) {
		//if !maskAddr.Equals(maskedHostStr.GetMask()) {
		t.addFailure(newHostFailure("masked "+maskAddr.String()+" instead of expected "+maskedHostStr.GetMask().String(), maskedHostStr))
	}
	if !maskedHostStr.GetNetworkPrefixLen().Equals(prefixLength) {
		t.addFailure(newHostFailure("masked prefix length was "+maskedHostStr.GetNetworkPrefixLen().String()+" instead of expected "+prefixLength.String(), maskedHostStr))
	}
	t.incrementTestCount()
}
