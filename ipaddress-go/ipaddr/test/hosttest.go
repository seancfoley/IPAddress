package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"strconv"
	"strings"
)

//TODO addressordertest

var runDNS = false

type hostTester struct {
	testBase
}

//TODO need to start like I did with ipaddress, just go through, and while you go, populate hostrange and hostall whenever they have the same tests

func (t hostTester) run() {
	t.testSelf("1.2.3.4", false)
	t.testSelf("1::", false)
	t.testSelf("[1::]", false)
	t.testSelf("bla.com", false)
	t.testSelf("::1", true)
	t.testSelf("[::1]", true)
	t.testSelf("localhost", true)
	t.testSelf("127.0.0.1", true)

	t.testSelf("[127.0.0.1]", true)
	t.testSelf("[localhost]", false) //square brackets are for ipv6
	t.testSelf("-ab-.com", false)

	t.testMatches(true, "a.com", "A.cOm")
	t.testMatches(false, "a.comx", "a.com")
	t.testMatches(false, "1::", "2::")
	t.testMatches(false, "1::", "1.2.3.4")
	t.testMatches(true, "1::", "1:0::")
	t.testMatches(true, "f::", "F:0::")
	t.testMatches(true, "1::", "[1:0::]")
	t.testMatches(true, "[1::]", "1:0::")
	t.testMatches(false, "1::", "1:0:1::")
	t.testMatches(true, "1.2.3.4", "1.2.3.4")
	t.testMatches(true, "1.2.3.4", "001.2.3.04")
	t.testMatches(true, "1.2.3.4", "::ffff:1.2.3.4") //ipv4 mapped
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%a", "1:2:3:4:5:6:102:304%a")
	t.testMatches(false, "1:2:3:4:5:6:1.2.3.4%", "1:2:3:4:5:6:102:304%")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%%", "1:2:3:4:5:6:102:304%%")
	t.testMatches(true, "[1:2:3:4:5:6:1.2.3.4%25%31]", "1:2:3:4:5:6:102:304%1")
	t.testMatches(true, "[1:2:3:4:5:6:102:304%25%31]", "1:2:3:4:5:6:102:304%1")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%-", "1:2:3:4:5:6:102:304%-")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4%-/64", "1:2:3:4:5:6:102:304%-/64")

	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:1.2.3.4")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:0.0.0.0", "1:2:3:4:5:6::")
	t.testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:0:0.0.0.0", "1:2:3:4:5::")
	t.testMatches(true, "[1:2:3:4:5:6::%y]", "1:2:3:4:5:6::%y")
	t.testMatches(true, "[1:2:3:4:5:6::%25y]", "1:2:3:4:5:6::%y") //see rfc 6874 about %25
	t.testMatches(true, "[1:2:3:4:5:6::]/32", "1:2:3:4:5:6::/32")
	t.testMatches(true, "[1:2::]/32", "1:2::/32")
	t.testMatches(true, "[1:ff00::]/24", "1:ff00::/24")
	t.testMatches(true, "[1:ffff::]/24", "1:ffff::/24")
	t.testMatches(false, "1.2.3.4/255.0.0.0", "1.0.0.0/255.0.0.0")

	t.testMatches(true, "[IPv6:1:2:3:4:5:6:7:8%y]", "1:2:3:4:5:6:7:8%y")
	t.testMatches(true, "[IPv6:1:2:3:4:5:6:7:8]", "1:2:3:4:5:6:7:8")
	t.testMatches(true, "[IPv6:1:2:3:4:5:6::]/32", "1:2:3:4:5:6::/32")
	t.testMatches(true, "[IPv6:1:2::]/32", "1:2::/32")
	t.testMatches(true, "[IPv6:::1]", "::1")
	t.testMatches(true, "[IPv6:1::]", "1::")

	t.testResolved("a::b:c:d:1.2.3.4%x", "a::b:c:d:1.2.3.4%x")
	t.testResolved("[a::b:c:d:1.2.3.4%x]", "a::b:c:d:1.2.3.4%x")
	t.testResolved("[a::b:c:d:1.2.3.4]", "a::b:c:d:1.2.3.4") //square brackets can enclose ipv6 in host names but not addresses
	t.testResolved("2001:0000:1234:0000:0000:C1C0:ABCD:0876%x", "2001:0:1234::c1c0:abcd:876%x")
	t.testResolved("[2001:0000:1234:0000:0000:C1C0:ABCD:0876%x]", "2001:0:1234::c1c0:abcd:876%x")
	t.testResolved("[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "2001:0:1234::C1C0:abcd:876") //square brackets can enclose ipv6 in host names but not addresses
	t.testResolved("2001:0000:1234:0000:0000:C1C0:ABCD:0876", "2001:0:1234::C1C0:abcd:876")   //square brackets can enclose ipv6 in host names but not addresses
	t.testResolved("1.2.3.04", "1.2.3.4")
	t.testResolved_inet_aton("1.2.3", "1.2.0.3")
	t.testResolved("[1.2.3.4]", "1.2.3.4")

	if t.fullTest && runDNS {
		t.testResolved("espn.com", "199.181.132.250")
		t.testResolved("espn.com/24", "199.181.132.0/24")
		t.testResolved("instapundit.com", "72.32.173.45")
	}

	t.testResolved("9.32.237.26", "9.32.237.26")
	t.testResolved("9.70.146.84", "9.70.146.84")
	t.testResolved("", "")

	t.testNormalizedHost(true, "[A::b:c:d:1.2.03.4]", "[a:0:0:b:c:d:102:304]")                                 //square brackets can enclose ipv6 in host names but not addresses
	t.testNormalizedHost(true, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "[2001:0:1234:0:0:c1c0:abcd:876]") //square brackets can enclose ipv6 in host names but not addresses
	t.testNormalizedHost(true, "1.2.3.04", "1.2.3.4")

	t.testCanonical("[A:0::c:d:1.2.03.4]", "a::c:d:102:304")                                   //square brackets can enclose ipv6 in host names but not addresses
	t.testCanonical("[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "2001:0:1234::c1c0:abcd:876") //square brackets can enclose ipv6 in host names but not addresses
	t.testCanonical("1.2.3.04", "1.2.3.4")

	t.testNormalizedHost(true, "WWW.ABC.COM", "www.abc.com")
	t.testNormalizedHost(true, "WWW.AB-C.COM", "www.ab-c.com")

	t.testURL("http://1.2.3.4")
	t.testURL("http://[a:a:a:a:b:b:b:b]")
	t.testURL("http://a:a:a:a:b:b:b:b")

	t.hostLabelsTest("one.two.three.four.five.six.seven.EIGHT", []string{"one", "two", "three", "four", "five", "six", "seven", "eight"})
	t.hostLabelsTest("one.two.three.four.fIVE.sIX.seven", []string{"one", "two", "three", "four", "five", "six", "seven"})
	t.hostLabelsTest("one.two.THREE.four.five.six", []string{"one", "two", "three", "four", "five", "six"})
	t.hostLabelsTest("one.two.three.four.five", []string{"one", "two", "three", "four", "five"})
	t.hostLabelsTest("one.two.three.four", []string{"one", "two", "three", "four"})
	t.hostLabelsTest("one.Two.three", []string{"one", "two", "three"})
	t.hostLabelsTest("onE.two", []string{"one", "two"})
	t.hostLabelsTest("one", []string{"one"})
	var emptyLabels []string
	if t.isLenient() {
		emptyLabels = []string{"127", "0", "0", "1"}
	} else {
		emptyLabels = []string{}
	}
	t.hostLabelsTest("", emptyLabels)
	t.hostLabelsTest(" ", emptyLabels)
	t.hostLabelsTest("1.2.3.4", []string{"1", "2", "3", "4"})
	t.hostLabelsTest("1:2:3:4:5:6:7:8", []string{"1", "2", "3", "4", "5", "6", "7", "8"})
	t.hostLabelsTest("[::]", []string{"0", "0", "0", "0", "0", "0", "0", "0"})
	t.hostLabelsTest("::", []string{"0", "0", "0", "0", "0", "0", "0", "0"})

}

func (t hostTester) testSelf(host string, isSelf bool) {
	w := t.createHost(host)
	if isSelf != w.IsSelf() {
		t.addFailure(newHostFailure("failed: isSelf is "+strconv.FormatBool(isSelf), w))
	}
	t.incrementTestCount()
}

func hostConversionMatches(host1, host2 *ipaddr.HostName) bool {
	h1 := host1.AsAddress()
	if h1 != nil && h1.IsIPv4() {
		h2 := host2.AsAddress()
		if !h2.IsIPv4() {
			if conv.IsIPv4Convertible(h2) {
				return h1.Equals(conv.ToIPv4(h2))
			}
		}
	} else if h1 != nil && h1.IsIPv6() {
		h2 := host2.AsAddress()
		if !h2.IsIPv6() {
			if conv.IsIPv6Convertible(h2) {
				return h1.Equals(conv.ToIPv6(h2))
			}
		}
	}
	return false
}

func (t hostTester) testMatches(matches bool, host1, host2 string) {
	t.testMatchesParams(matches, host1, host2, hostOptions)
}

func (t hostTester) testMatchesParams(matches bool, host1, host2 string, options ipaddr.HostNameParameters) {
	h1 := t.createParamsHost(host1, options)
	h2 := t.createParamsHost(host2, options)
	if matches != h1.Equals(h2) && matches != hostConversionMatches(h1, h2) {
		t.addFailure(newHostFailure("failed: match with "+host2, h1))
	} else {
		if matches != h2.Equals(h1) && matches != hostConversionMatches(h2, h1) {
			t.addFailure(newHostFailure("failed: match with "+host1, h2))
		} else {
			//if(matches != h1.Equals(h2) && matches != hostConversionMatches(h1, h2)) {
			//	addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h1, h2));
			//} else {
			t.testNormalizedMatches(h1)
			t.testNormalizedMatches(h2)
			//}
		}
	}
	t.incrementTestCount()
}

func isReserved(c byte) bool {
	isUnreserved :=
		(c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			c == ipaddr.RangeSeparator ||
			c == ipaddr.LabelSeparator ||
			c == '_' ||
			c == '~'
	return !isUnreserved
}

func translateReserved(addr *ipaddr.IPv6Address, str string) string {
	//This is particularly targeted towards the zone
	if !addr.HasZone() {
		return str
	}
	index := strings.Index(str, ipaddr.IPv6ZoneSeparatorStr)
	translated := strings.Builder{}
	translated.Grow(((len(str) - index) * 3) + index)
	translated.WriteString(str[:index])
	translated.WriteString("%25")
	for i := index + 1; i < len(str); i++ {
		c := str[i]
		if isReserved(c) {
			translated.WriteByte('%')
			translated.WriteString(strconv.FormatUint(uint64(c), 16))
		} else {
			translated.WriteByte(c)
		}
	}
	return translated.String()
}

func (t hostTester) testNormalizedMatches(h1 *ipaddr.HostName) {
	var normalized string
	if h1.IsAddress() && h1.AsAddress().IsPrefixed() && h1.AsAddress().IsIPv6() {
		addr := h1.AsAddress().GetLower().WithoutPrefixLen().ToIPv6Address()
		normalized = "[" + translateReserved(addr, addr.ToNormalizedString()) + "]/" + h1.AsAddress().GetNetworkPrefixLen().String()
	} else if h1.IsAddress() && h1.AsAddress().IsIPv6() {
		addr := h1.AsAddress().ToIPv6Address()
		normalized = "[" + translateReserved(addr, addr.ToNormalizedWildcardString()) + "]"
	} else {
		normalized = h1.ToNormalizedString()
	}
	h1Bracketed := h1.ToNormalizedString()
	if h1Bracketed != normalized {
		t.addFailure(newHostFailure("failed: bracketed is "+normalized, h1))
	}
	t.incrementTestCount()
}

func (t hostTester) testResolved_inet_aton(original, expectedResolved string) {
	origAddress := t.createInetAtonHost(original)
	t.testResolvedHost(origAddress, original, expectedResolved)
}

func (t hostTester) testResolved(original, expectedResolved string) {
	origAddress := t.createHost(original)
	t.testResolvedHost(origAddress, original, expectedResolved)
}

func (t hostTester) testResolvedHost(original *ipaddr.HostName, originalStr, expectedResolved string) {
	//try {
	resolvedAddress := original.GetAddress()
	var result bool
	if resolvedAddress == nil && original.IsAllAddresses() && expectedResolved != "" {
		//special case for "*"
		exp := t.createAddress(expectedResolved)
		result = original.AsAddressString().Equals(exp)
	} else {
		if resolvedAddress == nil {
			result = expectedResolved == ""
		} else { //TODO xxx host options above hostWildcardOptions produce 0.0.0.0 but address options wildcardAndRangeAddressOptions produce nil
			expectedStr := t.createAddress(expectedResolved)
			expected := expectedStr.GetAddress()
			result = resolvedAddress.Equals(expected)
		}
	}
	if !result {
		if resolvedAddress == nil {
			t.addFailure(newHostFailure("resolved was nil, original was "+originalStr, original))
		} else {
			t.addFailure(newHostFailure("resolved was "+resolvedAddress.String()+" original was "+originalStr, original))
		}
	} else if resolvedAddress != nil && !(resolvedAddress.IsIPv6() && resolvedAddress.ToIPv6Address().HasZone()) {
		host := resolvedAddress.ToHostName()
		if !original.Equals(host) && !original.IsSelf() && !host.IsSelf() {
			t.addFailure(newHostFailure("reverse was "+host.String()+" original was "+original.String(), original))
		} else if !original.IsAddress() {
			//System.out.println("" + resolvedAddress.toCanonicalHostName());
		}
	}
	//} catch(IncompatibleAddressException e) {
	//	addFailure(new Failure(e.toString(), original));
	//} catch(RuntimeException e) {
	//	addFailure(new Failure(e.toString(), original));
	//}
	t.incrementTestCount()
}

func (t hostTester) testNormalizedHost(expectMatch bool, original, expected string) {
	w := t.createHost(original)
	normalized := w.ToNormalizedString()
	if (normalized != expected) == expectMatch {
		t.addFailure(newHostFailure("normalization was "+normalized, w))
	}
	t.incrementTestCount()
}

func (t hostTester) testCanonical(original, expected string) {
	w := t.createHost(original)
	canonical := w.AsAddress().ToCanonicalString()
	if canonical != (expected) {
		t.addFailure(newHostFailure("canonicalization was "+canonical, w))
	}
	t.incrementTestCount()
}

func (t hostTester) testURL(url string) {
	w := t.createHost(url)
	//try {
	err := w.Validate()
	if err == nil {
		t.addFailure(newHostFailure("failed: "+"URL "+url, w))
	}
	//} catch(HostNameException e) {
	////pass
	//e.getMessage();
	//}
	t.incrementTestCount()
}
