package test

import (
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"strconv"
	"strings"
)

//TODO addressordertest, specialtypestest

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
	t.testMatches(true, `[1:2:3:4:5:6:1.2.3.4%25%31]`, `1:2:3:4:5:6:102:304%1`)
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
}

func (t hostTester) testSelf(host string, isSelf bool) {
	w := t.createHost(host)
	if isSelf != w.IsSelf() {
		t.addFailure(newHostFailure("failed: isSelf is "+strconv.FormatBool(isSelf), w))
	}
	t.incrementTestCount()
}

/*
func conversionMatches(h1, h2 *ipaddr.IPAddressString) bool {
	if h1.IsIPv4() {
		if !h2.IsIPv4() {
			if h2.GetAddress() != nil && conv.IsIPv4Convertible(h2.GetAddress()) {
				return h1.GetAddress().Equals(conv.ToIPv4(h2.GetAddress()))
			}
		}
	} else if h1.IsIPv6() {
		if !h2.IsIPv6() {
			if h2.GetAddress() != nil && conv.IsIPv6Convertible(h2.GetAddress()) {
				return h1.GetAddress().Equals(conv.ToIPv6(h2.GetAddress()))
			}
		}
	}
	return false
}
*/
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
