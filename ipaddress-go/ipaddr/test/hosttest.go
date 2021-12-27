package test

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrformat"
	"net"
	"strconv"
	"strings"
)

var runDNS = false

type hostTester struct {
	testBase
}

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

	t.hostTest(true, "1.2.3.4/1.2.3.4")
	t.hostTest(true, "1.2.3.4/255.0.0.0")
	t.hostTest(true, "abc.com/255.0.0.0")
	t.hostTest(true, "abc.com/::")
	t.hostTest(true, "abc.com/::1")

	//Since service names cannot have ':' and can be at most 15 chars, and since all IPv6 must have a ':' or must be at least 32 digits otherwise, there is no ambiguity below
	//of course, none of the forms below can appear in a URL
	t.hostTest(true, "abc.com/1::1")     //this is abc.com with mask 1::1
	t.hostTest(true, "abc.com/1:1")      //this one is abc.com with prefix 1 and port 1
	t.hostTest(true, "abc.com/1:abc")    //this one is abc.com with prefix 1 and service abc
	t.hostTest(true, "abc.com/1.2.3.4")  //this is abc.com with mask 1.2.3.4
	t.hostTest(true, "abc.com:a1-2-3-4") //this is abc.com with service a1-2-3-4 (note service must have at least one letter)

	t.hostTest(true, "abc.com/1::")
	t.hostTest(true, "abc.com/32")

	t.hostTest(true, "abc.com.")
	t.hostTest(true, "abc.com./32")

	t.hostTest(false, "[1.2.3.4")
	t.hostTest(false, "[1:2:3:4:5:6:7:8")
	t.hostTest(true, "[a::b:c:d:1.2.3.4]") //square brackets can enclose ipv6 in host names but not addresses
	t.hostTest(true, "[a::b:c:d:1.2.3.4%x]")
	t.hostTest(true, "a::b:c:d:1.2.3.4%x")
	t.hostTest(false, "a:b:c:d:1.2.3.4%x")
	t.hostTest(true, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]")   //square brackets can enclose ipv6 in host names but not addresses
	t.hostTest(true, "2001:0000:1234:0000:0000:C1C0:ABCD:0876%x")   //ipv6 must be enclosed in []
	t.hostTest(true, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876%x]") //zones not allowed when using []

	t.hostTest(true, "1:2:3:4:5:6:1.2.3.4%%")       //the % is the zone itself, when treated as an address
	t.hostTest(false, "[1:2:3:4:5:6:1.2.3.4%%]")    //the % is an encoding, when treated as a host
	t.hostTest(true, "1:2:3:4:5:6:1.2.3.4%%")       //the % is allowed in zone, when treated as a address
	t.hostTest(true, "[1:2:3:4:5:6:1.2.3.4%25%31]") //the % is an encoding, when treated as a host, so this is in fact the zone of 1 (%25 is zone char, %31 is 1)
	t.hostTest(true, "1:2:3:4:5:6:1.2.3.4%25%31")   //this is in fact the zone 25%31

	t.hostTest(true, "1.2.3.4")
	t.hostTest_inet_aton(true, "1.2.3")
	t.hostTest(true, "0x1.0x2.0x3.04")
	t.hostTest(true, "0X1.0x2.0x3.04")
	t.hostTest(true, "0x1.0x2.0b3.04")
	t.hostTest(true, "0x1.0x2.0B3.04")
	t.hostTest(true, "[1.2.3.4]")

	t.hostTest(true, "a_b.com")
	t.hostTest(true, "_ab.com")
	t.hostTest(true, "_ab_.com")
	t.hostTest(false, "-ab-.com")
	t.hostTest(false, "ab-.com")
	t.hostTest(false, "-ab.com")
	t.hostTest(false, "ab.-com")
	t.hostTest(false, "ab.com-")

	t.hostTest(true, "a9b.com")
	t.hostTest(true, "9ab.com")
	t.hostTest(true, "999.com")
	t.hostTest(true, "ab9.com")
	t.hostTest(true, "ab9.com9")
	t.hostTest_inet_aton(true, "999")
	t.hostTest_inet_aton(true, "111.999")
	t.hostTest(false, "999.111")

	t.hostTest(false, "a*b.com")
	t.hostTest(false, "*ab.com")
	t.hostTest(false, "ab.com*")
	t.hostTest(false, "*.ab.com")
	t.hostTest(false, "ab.com.*")
	t.hostTest(false, "ab.co&m")
	t.hostTest(false, "#.ab.com")
	t.hostTest(false, "cd.ab.com.~")
	t.hostTest(false, "#x.ab.com")
	t.hostTest(false, "cd.ab.com.x~")
	t.hostTest(false, "x#.ab.com")
	t.hostTest(false, "cd.ab.com.~x")
	t.hostTest(true, "xx.ab.com.xx")

	t.hostTest(true, "ab.cde.fgh.com")
	t.hostTest(true, "aB.cDE.fgh.COm")

	t.hostTest(true, "123-123456789-123456789-123456789-123456789-123456789-123456789.com")   //label 63 chars
	t.hostTest(false, "1234-123456789-123456789-123456789-123456789-123456789-123456789.com") //label 64 chars
	t.hostTest(false, "123.123456789.123456789.123456789.123456789.123456789.123456789.123")  //all numbers
	t.hostTest(true, "aaa.123456789.123456789.123456789.123456789.123456789.123456789.123")   //numbers everywhere but first label

	t.hostTest(false, "a11"+
		"-123456789-123456789-123456789-123456789-12345678."+
		"-123456789-123456789-123456789-123456789-12345678."+
		"-123456789-123456789-123456789-123456789-12345678."+
		"-123456789-123456789-123456789-123456789-12345678."+
		"-123456789-123456789-123456789-123456789-123456789") //253 chars, but segments start with -

	t.hostTest(true, "a11"+
		"-123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-123456789") //253 chars

	t.hostTest(false, "111"+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"01234567890123456789012345678901234567890123456789") //all number

	t.hostTest(true, "222"+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678f") //not all number, 253 chars

	t.hostTest(false, "a222"+
		"-123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-12345678."+
		"0123456789-123456789-123456789-123456789-123456789") //254 chars

	t.hostTest(true, "a33"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789") //253 chars

	t.hostTest(false, "444"+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"01234567890123456789012345678901234567890123456789") //all number

	t.hostTest(true, "555"+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678f") //not all number

	t.hostTest(true, "777"+
		"01234567890123456789012345678901234567890123456789"+
		"0123456789.123456789012345678901234567890123456789"+
		"012345678901234567890123.5678901234567890123456789"+
		"01234567890123456789012345678901234567.90123456789"+
		"0123456789012345678901234567890123456789012345678f") //first 3 segments are 63 chars

	t.hostTest(false, "777"+
		"01234567890123456789012345678901234567890123456789"+
		"01234567890.23456789012345678901234567890123456789"+
		"012345678901234567890123.5678901234567890123456789"+
		"01234567890123456789012345678901234567.90123456789"+
		"0123456789012345678901234567890123456789012345678f") //first segment 64 chars

	t.hostTest(false, "a666"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789"+
		".123456789.123456789.123456789.123456789.123456789") //254 chars

	t.hostTest(true, "a.9."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5") //252 chars, 127 segments

	t.hostTest(false, ".a.7."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5") //252 chars, 127 segments, extra dot at front

	allowTrailingDot2 := true

	t.hostTest(allowTrailingDot2, "222"+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678f.") //not all number, 253 chars with trailing dot

	t.hostTest(allowTrailingDot2, "a.8."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5.") //252 chars, 127 segments, extra dot at end

	t.hostTest(false, "222"+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678."+
		"0123456789012345678901234567890123456789012345678..") // double trailing dot

	t.hostTest(false, "a.6."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."+
		"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5.8") //254 chars, 128 segments

	t.hostTest(false, "a:b:com")
	t.hostTest(true, "a:b::ccc")
	t.hostTest(true, "a:b:c:d:e:f:a:b")

	t.hostTest(false, ".as.b.com") //starts with dot

	allowTrailingDot1 := true
	t.hostTest(allowTrailingDot1, "as.b.com.") //ends with dot
	t.hostTest(false, ".as.b.com.")            //starts and ends with dot
	t.hostTest(false, "as..b.com")             //double dot
	t.hostTest(false, "as.b..com")             //double dot
	t.hostTest(false, "..as.b.com")            //starts with dots
	t.hostTest(false, "as.b.com..")            //ends with dots

	t.hostTest(false, "1.2.3.4:123456789012345a")
	t.hostTest(false, "1.2.3.4:")
	t.hostTest(false, "1.2.3.4:a-")
	t.hostTest(false, "1.2.3.4:-a")
	t.hostTest(false, "1.2.3.4:a--b")
	t.hostTest(false, "1.2.3.4:x-")
	t.hostTest(false, "1.2.3.4:-x")
	t.hostTest(false, "1.2.3.4:x--x")

	allowEmptyZone := true

	t.hostTest(allowEmptyZone, "[::1%25/32]") // empty zone
	t.hostTest(allowEmptyZone, "::1%/32")     // empty zone

	t.hostTest(false, "[a.b.com]:nfs") //non-Ipv6 inside brackets
	t.hostTest(true, "[::]:nfs")

	t.hostTest(true, "255.22.2.111.3.in-addr.arpa:35") //not a valid address but still a valid host
	t.hostTest(false, "[::1]x")
	t.hostTest(false, "[::1x]")
	t.hostTest(false, "[::x1]")
	t.hostTest(false, "x[::1]")
	t.hostTest(false, "[]")
	t.hostTest(false, "[a]")
	t.hostTest(false, "1.2.2.256:33")
	t.hostTest(true, "f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45") //not an address, but a valid host
	t.hostTest(true, "f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int")    //not an address, but a valid host
	t.hostTest(false, "aa-bb-cc-dd-ee-ff-.ipv6-literal.net")
	t.hostTest(true, "aa-bb-cc-dd-ge-ff.ipv6-literal.net") //not an address but a valid host

	t.hostTest(true, "[1::/16]/32")
	t.hostTest(true, "[1::/16]/16")
	t.hostTest(true, "[1.2.3.4/16]/32")
	t.hostTest(true, "[1.2.3.4/16]/16")
	t.hostTest(true, "[1.2.3.4/16]/255.255.255.0")
	t.hostTest(true, "[1.2.3.4/16]/255.255.0.0")
	t.hostTest(true, "[1.2.3.4/255.255.255.0]/16")
	t.hostTest(true, "[1.2.3.4/255.255.0.0]/16")
	t.hostTest(true, "[1.2.3.4/255.255.255.0]/255.255.255.0")
	t.hostTest(true, "[1.2.3.4/255.255.0.0]/255.255.255.0")
	t.hostTest(true, "[1.2.3.4/255.255.255.0]/255.255.0.0")

	t.hostTest(allowEmptyZone, "1::%")                // empty zone
	t.hostTest(allowEmptyZone, "1::%/16")             // empty zone
	t.hostTest(allowEmptyZone, "a:b:c:d:e:f:a:b%/64") // empty zone
	t.hostTest(false, "::1:88888")                    //port too large, also too large to be ipv6 segment
	t.hostTest(false, "::1:88_8")                     //invalid because no letter in service name, nor is it a port
	t.hostTest(t.isLenient(), "::1:88-8")             //valid because address with ranged segment, but it is not a service because no letter, nor a port
	t.hostTest(true, "::1:8888")
	t.hostTest(true, "::1:58888")
	t.hostTest(true, "::1:8a-8")
	t.hostTest(t.isLenient(), "::1:-8a88") //this passes if the second segment considered a range
	t.hostTest(false, "1.2.3.4:-8a8")      //-8a8 can only be a port or service, but leading hyphen not allowed for a service
	t.hostTest(true, "1.2.3.4:8-a8")

	t.hostTest(t.isLenient(), "::1:8a8-:2")
	t.hostTest(t.isLenient(), "::1:-8a8:2")
	t.hostTest(t.isLenient(), "::1:8a8-") //this passes if the second segment considered a range, cannot be a service due to trailing hyphen
	t.hostTest(t.isLenient(), "::1:-8a8") //this passes if the second segment considered a range, cannot be a service due to leading hyphen

	t.hostTest(true, "[1.2.3.4]/255.255.255.0")
	t.hostTest(true, "[::]/ffff::")
	t.hostTest(false, "[::]/255.255.0.0") // prefix len equivalent
	t.hostTest(false, "[::]/0.255.0.0")   // not prefix len
	t.hostTest(false, "[1.2.3.4]/ffff::")
	t.hostTest(false, "[1.2.3.4]/::ffff") // note the colon placement here could be confused with port
	t.hostTest(false, "[1.2.3.4]/ffff::ffff")
	//
	// And now the same but the mask versions don't match
	t.hostTest(true, "[1.2.3.4/255.0.0.0]/255.255.255.0") // prefix len equivalent
	t.hostTest(true, "[::/ff::]/ffff::")
	t.hostTest(false, "[::/ffff::]/255.255.0.0")
	t.hostTest(false, "[::/ffff::]/0.255.0.0") // not prefix len
	t.hostTest(false, "[::/::ffff]/0.255.0.0") // not prefix len
	t.hostTest(false, "[1.2.3.4/0.0.0.255]/ffff::")
	t.hostTest(false, "[1.2.3.4/0.0.0.255]/::ffff") // note the colon placement here could be confused with port
	t.hostTest(false, "[1.2.3.4/0.0.0.255]/ffff::ffff")
	t.hostTest(false, "[1.2.3.4/255.0.0.0]/ffff::")
	t.hostTest(false, "[1.2.3.4/255.0.0.0]/::ffff") // note the colon placement here could be confused with port
	t.hostTest(false, "[1.2.3.4/255.0.0.0]/ffff::ffff")

	portNum1 := ipaddr.PortInt(1)
	portNum3 := ipaddr.PortInt(3)
	portNum33 := ipaddr.PortInt(33)
	//portNum35 := ipaddr.PortInt(35)
	portNum45 := ipaddr.PortInt(45)
	portNum80 := ipaddr.PortInt(80)
	portNum123 := ipaddr.PortInt(123)
	portNum48888 := ipaddr.PortInt(48888)

	port1 := ToPort(portNum1)
	port3 := ToPort(portNum3)
	port33 := ToPort(portNum33)
	port45 := ToPort(portNum45)
	port80 := ToPort(portNum80)
	port123 := ToPort(portNum123)
	port48888 := ToPort(portNum48888)

	//port1 := &portNum1
	//port3 := &portNum3
	//port33 := &portNum33
	////port35 := &portNum35
	//port45 := &portNum45
	//port80 := &portNum80
	//port123 := &portNum123
	//port48888 := &portNum48888

	//TODO LATER ipv6 literal addresses from hosts
	//t.testHostAddressPortZone("aa-bb-cc-dd-ee-ff-aaaa-bbbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbbb", nil, "")
	//t.testHostAddress("aa-bb-cc-dd-ee-ff-aaaa-bbbbseth0.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbbb", "aa:bb:cc:dd:ee:ff:aaaa:bbbb%eth0", nil, "eth0")
	t.testHostPortZone("aa-bb-cc-dd-ee-ff.ipv6-literal.net", "aa-bb-cc-dd-ee-ff.ipv6-literal.net", nil, "") //not a valid address, too few segments, but a valid host
	t.testHostPortZone("aa-Bb-cc-dd-ee-FF.ipv6-literal.net", "aa-bb-cc-dd-ee-ff.ipv6-literal.net", nil, "") //not a valid address, too few segments, but a valid host
	//TODO LATER ipv6 literal addresses from hosts
	//t.testHostAddressPortZone("aa-bb-cc-dd-ee-ff-aaaa-bbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbb", nil, "")
	//t.testHostAddressPortZone("aa-Bb-cc-dd-ee-FF-aaaa-bbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbb", nil, "")
	//t.testHostAddressPortZone("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.arpa", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", nil, "")
	//t.testHostAddressPortZone("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", nil, "")
	//t.testHostAddressPortZone("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int:45", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", port45, "")
	//t.testHostAddressPortZone("F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", port45, "")
	t.testHostPortZone("f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45", "f.f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int", port45, "") //not a valid address, but a valid host
	//TODO LATER ipv6 literal addresses from hosts
	//t.testHostAddressPortZone("255.22.2.111.in-addr.arpa", "111.2.22.255", nil, "")
	//t.testHostAddressPortZone("255.22.2.111.in-addr.arpa:35", "111.2.22.255", port35, "")
	//t.testHostPortZone("255.22.2.111.3.in-addr.arpa:35", "255.22.2.111.3.in-addr.arpa", port35, "")
	t.testHostAddressPortZone("1.2.2.1:33", "1.2.2.1", port33, "")
	t.testHostAddressPortZone("[::1]:33", "::1", port33, "")
	t.testHostAddressPortZone("::1:33", "::1:33", nil, "")
	t.testHostAddress("::1%eth0", "::1", "::1%eth0", nil, "eth0")
	t.testHostAddress("[::1%eth0]:33", "::1", "::1%eth0", port33, "eth0")
	t.testHostPortZone("bla.bla:33", "bla.bla", port33, "")
	t.testHostPortZone("blA:33", "bla", port33, "")
	t.testHostPortZone("f:33", "f", port33, "")
	t.testHostAddressPortZone("f::33", "f::33", nil, "")
	t.testHostAddressPortZone("::1", "::1", nil, "")
	t.testHostAddressPortZone("[::1]", "::1", nil, "")
	// no longer supporting prefix-only addresses?
	//t.testHostAddressPortZonePref("/16", "/16", nil, "", p16)
	//t.testHostAddressPortZonePref("/32", "/32", nil, "", p32)
	//t.testHostAddressPref("/64", "ffff:ffff:ffff:ffff:*:*:*:*", "ffff:ffff:ffff:ffff::/64", nil, "", p64)

	t.testHostAddressWithService("1.2.3.4:nfs", "1.2.3.4", "nfs", "")
	t.testHostPortServZonePref("[::1%eth0]:nfs", "::1", "::1%eth0", nil, "nfs", "eth0", nil)
	t.testHostAddressWithService("1.2.3.4:12345678901234a", "1.2.3.4", "12345678901234a", "")
	t.testHostAddressWithService("[::1]:12345678901234a", "::1", "12345678901234a", "")
	t.testHostAddressWithService("[::1]:12345678901234x", "::1", "12345678901234x", "")
	t.testHostAddressWithService("1.2.3.4:a", "1.2.3.4", "a", "")
	t.testHostAddressWithService("1.2.3.4:a-b-c", "1.2.3.4", "a-b-c", "")
	t.testHostAddressWithService("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:a-b-c", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "a-b-c", "")

	t.testHostPortServZonePref("a.b.c/16:nfs", "a.b.c", "", nil, "nfs", "", p16)
	t.testHostPortServZonePref("a.b.c./16:nfs", "a.b.c", "", nil, "nfs", "", p16)
	t.testHostPortServZonePref("a.b.c/16:80", "a.b.c", "", port80, "", "", p16)
	t.testHostPortServZonePref("a.b.c./16:nfs", "a.b.c", "", nil, "nfs", "", p16)
	t.testHostPortServZonePref("a.b.c./16:80", "a.b.c", "", port80, "", "", p16)
	t.testHostPortServZonePref("a.b.c:80", "a.b.c", "", port80, "", "", nil)
	t.testHostPortServZonePref("a.b.c.:80", "a.b.c", "", port80, "", "", nil)
	t.testHostWithService("a.b.c:nfs", "a.b.c", "nfs", "")
	t.testHostWithService("a.b.com:12345678901234a", "a.b.com", "12345678901234a", "")
	t.testHostWithService("a.b.com.:12345678901234a", "a.b.com", "12345678901234a", "")
	t.testHostWithService("a.b.com:12345678901234x", "a.b.com", "12345678901234x", "")
	t.testHostWithService("a.b.com:x12345678901234", "a.b.com", "x12345678901234", "")
	t.testHostWithService("a.b.com:12345x789012345", "a.b.com", "12345x789012345", "")
	t.testHostWithService("a.b.com:a", "a.b.com", "a", "")
	t.testHostWithService("a.b.com:a-b-c", "a.b.com", "a-b-c", "")
	t.testHostWithService("a.b.c:a-b-c", "a.b.c", "a-b-c", "")
	t.testHostWithService("123-123456789-123456789-123456789-123456789-123456789-123456789.com:a-b-c", "123-123456789-123456789-123456789-123456789-123456789-123456789.com", "a-b-c", "")
	t.testHostWithService("123-123456789-123456789-123456789-123456789-123456789-123456789.com:12345x789012345", "123-123456789-123456789-123456789-123456789-123456789-123456789.com", "12345x789012345", "")

	expectPortParams := new(addrformat.HostNameParametersBuilder).Set(hostOptions).ExpectPort(true).ToParams()
	t.testHostAddressWithService("fe80::6a05:caff:fe3:nfs", "fe80::6a05:caff:fe3", "nfs", "")
	t.testHostAddressPortZone("fe80::6a05:caff:fe3:123", "fe80::6a05:caff:fe3:123", nil, "")
	hostName := t.createParamsHost("fe80::6a05:caff:fe3:123", expectPortParams)
	t.testHostPortServZone(hostName, "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3", port123, "", "")

	t.testHostAddress("[1::%25%241]", "1::", "1::%$1", nil, "$1")
	t.testHostAddress("[1::%%241]", "1::", "1::%$1", nil, "$1") //when zone marker not %25 we are forgiving
	t.testHostAddress("[1::%25%241]:123", "1::", "1::%$1", port123, "$1")
	t.testHostAddress("[1::%%241]:123", "1::", "1::%$1", port123, "$1")
	t.testHostAddress("1::%25%241:123", "1::", "1::%25%241", port123, "25%241") //%hexhex encoding only when inside '[]' since '[]' is the proper URL format
	t.testHostAddress("1::%%241:123", "1::", "1::%%241", port123, "%241")

	t.testHostAddressPref("1::%%1/16", "1:*:*:*:*:*:*:*", "1::%%1/16", nil, "%1", p16)
	t.testHostAddressPref("[1::%251]/16", "1:*:*:*:*:*:*:*", "1::%1/16", nil, "1", p16)

	t.testHostAddressPref("[1::%251/16]:3", "1:*:*:*:*:*:*:*", "1::%1/16", port3, "1", p16)
	t.testHostAddressPref("1::%1/16:3", "1:*:*:*:*:*:*:*", "1::%1/16", port3, "1", p16)
	t.testHostAddressPref("1::%%1/16:3", "1:*:*:*:*:*:*:*", "1::%%1/16", port3, "%1", p16) //that's right, zone, prefix and port!
	t.testHostAddressPref("[1::/16]:3", "1:*:*:*:*:*:*:*", "1::/16", port3, "", p16)

	t.testHostAddressPref("[1::/16]/32", "1:*:*:*:*:*:*:*", "1::/16", nil, "", p16)
	t.testHostAddressPref("[1::/16]/16", "1:*:*:*:*:*:*:*", "1::/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/16]/32", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/16]/16", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/16]/255.255.255.0", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/255.255.255.0]/16", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/16]/255.255.0.0", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/255.255.0.0]/16", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/255.255.0.0]/255.255.255.0", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/255.255.255.0]/255.255.0.0", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("[1.2.3.4/255.255.0.0]/255.255.255.0", "1.2.3.4", "1.2.3.4/16", nil, "", p16)

	t.testHostAddressPref("1::/16:3", "1:*:*:*:*:*:*:*", "1::/16", port3, "", p16)
	t.testHostAddressPref("[1::%251/16]", "1:*:*:*:*:*:*:*", "1::%1/16", nil, "1", p16)
	t.testHostAddressPref("[1::%25%241/16]", "1:*:*:*:*:*:*:*", "1::%$1/16", nil, "$1", p16)

	t.testHostAddressPref("1::%1/16", "1:*:*:*:*:*:*:*", "1::%1/16", nil, "1", p16)
	t.testHostAddressPref("1::%1%1/16", "1:*:*:*:*:*:*:*", "1::%1%1/16", nil, "1%1", p16)
	t.testHostAddressPref("1.2.3.4/16", "1.2.3.4", "1.2.3.4/16", nil, "", p16)
	t.testHostAddressPref("1.2.0.0/16", "1.2.*.*", "1.2.0.0/16", nil, "", p16)
	t.testHostPortServZonePref("a.b.com/24", "a.b.com", "", nil, "", "", p24)
	t.testHostPortServZonePref("a.b.com./24", "a.b.com", "", nil, "", "", p24)
	t.testHostPortServZonePref("a.b.com", "a.b.com", "", nil, "", "", nil)
	t.testHostPortServZonePref("a.b.com.", "a.b.com", "", nil, "", "", nil)
	t.testHostAddressPref("[fe80::%2]/64", "fe80::*:*:*:*", "fe80::%2/64", nil, "2", p64) //prefix outside the host (can be either inside or outside)
	t.testHostAddressPref("fe80::%2/64", "fe80::*:*:*:*", "fe80::%2/64", nil, "2", p64)

	t.testHostAddress("[::123%25%25%25aaa%25]", "::123", "::123%%%aaa%", nil, "%%aaa%")
	t.testHostAddress("[::123%25%25%25%24aa%25]", "::123", "::123%%%$aa%", nil, "%%$aa%")
	t.testHostAddress("[::123%25%24%25%24aa%25]", "::123", "::123%$%$aa%", nil, "$%$aa%")
	t.testHostAddress("::123%%%", "::123", "::123%%%", nil, "%%")

	t.testHostAddress("fe80:0:0:0:0:6a05:caff:fe3%x:123", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", port123, "x")

	t.testHostPortServZonePref("fe80:0:0:0:0:6a05:caff:fe3%x:abc", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", nil, "abc", "x", nil)
	t.testHostPortServZonePref("fe80:0:0:0:0:6a05:caff:fe3%x/64:abc", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x/64", nil, "abc", "x", p64)   //that's right, zone, prefix and service
	t.testHostPortServZonePref("[fe80:0:0:0:0:6a05:caff:fe3%x/64]:abc", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x/64", nil, "abc", "x", p64) //that's right, zone, prefix and service
	t.testHostAddress("fe80::6a05:caff:fe3%x:123", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", port123, "x")
	t.testHostPortServZonePref("fe80::6a05:caff:fe3%x:abc", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", nil, "abc", "x", nil)

	t.testHostAddressPortZone("fe80:0:0:0:0:6a05:caff:fe3", "fe80::6a05:caff:fe3", nil, "")
	t.testHostAddressWithService("fe80:0:0:0:0:0:6a05:caff:fe3", "fe80::6a05:caff", "fe3", "")
	t.testHostAddressPortZone("fe80:0:0:0:0:6a05:caff:fe3:123", "fe80::6a05:caff:fe3", port123, "")
	t.testHostAddressWithService("fe80:0:0:0:0:6a05:caff:fe3:*", "fe80::6a05:caff:fe3", "*", "")
	t.testHostAddressPortZone("::1:8888", "::1:8888", nil, "")
	t.testHostAddressWithService("::1:88g8", "::1", "88g8", "")
	t.testHostAddressWithService("::1:88a8", "::1:88a8", "", "")
	hostName = t.createParamsHost("::1:88a8", expectPortParams)
	t.testHostPortServZone(hostName, "::1", "::1", nil, "88a8", "")
	t.testHostAddressPortZone("::1:48888", "::1", port48888, "")
	t.testHostAddressWithService("::1:nfs", "::1", "nfs", "")
	t.testHostAddressWithService(":::*", "::", "*", "")
	t.testHostAddressPortZone(":::1", "::", port1, "")
	t.testHostAddressPortZone(":::123", "::", port123, "")
	t.testHostAddressPortZone("[::]:123", "::", port123, "")

	t.testHostInetSocketAddress("1.2.3.4:80", "1.2.3.4", portNum80)
	t.testHostInetSocketAddress(":::123", "::", portNum123)
	t.testHostInetSocketAddress("[::]:123", "::", portNum123)
	//t.testHostInetSocketAddress("a.com:123", "a.com", 123);
	//t.testHostInetSocketAddress("espn.com:123", "espn.com", 123);
	//t.testHostInetSocketAddress("foo:123", "foo", 123);
	t.testNotHostInetSocketAddress("1.2.3.4")
	t.testNotHostInetSocketAddress("::")
	t.testNotHostInetSocketAddress("a.com")
	t.testNotHostInetSocketAddress("foo")
	t.testHostInetSocketAddressService("1.2.3.4:http", func(s string) ipaddr.Port {
		if s == "http" {
			port80 := ipaddr.PortInt(80)
			return ToPort(port80)
			//return &port80
		}
		return nil
	}, "1.2.3.4", 80)
	t.testHostInetSocketAddressSA("1.2.3.4:http", func(s string) ipaddr.Port {
		if s == "htt" {
			port80 := ipaddr.PortInt(80)
			return ToPort(port80)
			//return &port80
		}
		return nil
	}, nil)
	t.testHostInetSocketAddressSA("1.2.3.4:http", nil, nil)

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
				return h1.Equal(conv.ToIPv4(h2))
			}
		}
	} else if h1 != nil && h1.IsIPv6() {
		h2 := host2.AsAddress()
		if !h2.IsIPv6() {
			if conv.IsIPv6Convertible(h2) {
				return h1.Equal(conv.ToIPv6(h2))
			}
		}
	}
	return false
}

func (t hostTester) testMatches(matches bool, host1, host2 string) {
	t.testMatchesParams(matches, host1, host2, hostOptions)
}

func (t hostTester) testMatchesParams(matches bool, host1, host2 string, options addrformat.HostNameParameters) {
	h1 := t.createParamsHost(host1, options)
	h2 := t.createParamsHost(host2, options)
	if matches != h1.Equal(h2) && matches != hostConversionMatches(h1, h2) {
		t.addFailure(newHostFailure("failed: match with "+host2, h1))
	} else {
		if matches != h2.Equal(h1) && matches != hostConversionMatches(h2, h1) {
			t.addFailure(newHostFailure("failed: match with "+host1, h2))
		} else {
			//if(matches != h1.Equal(h2) && matches != hostConversionMatches(h1, h2)) {
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
		addr := h1.AsAddress().GetLower().WithoutPrefixLen().ToIPv6()
		normalized = "[" + translateReserved(addr, addr.ToNormalizedString()) + "]/" + h1.AsAddress().GetNetworkPrefixLen().String()
	} else if h1.IsAddress() && h1.AsAddress().IsIPv6() {
		addr := h1.AsAddress().ToIPv6()
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
		result = original.AsAddressString().Equal(exp)
	} else {
		if resolvedAddress == nil {
			result = expectedResolved == ""
		} else {
			expectedStr := t.createAddress(expectedResolved)
			expected := expectedStr.GetAddress()
			result = resolvedAddress.Equal(expected)
		}
	}
	if !result {
		if resolvedAddress == nil {
			t.addFailure(newHostFailure("resolved was nil, original was "+originalStr, original))
		} else {
			t.addFailure(newHostFailure("resolved was "+resolvedAddress.String()+" original was "+originalStr, original))
		}
	} else if resolvedAddress != nil && !(resolvedAddress.IsIPv6() && resolvedAddress.ToIPv6().HasZone()) {
		host := resolvedAddress.ToHostName()
		if !original.Equal(host) && !original.IsSelf() && !host.IsSelf() {
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

func (t hostTester) hostTest_inet_aton(pass bool, x string) {
	addr := t.createInetAtonHost(x)
	t.hostTestDouble(pass, addr, false)
}

func (t hostTester) hostTest(pass bool, x string) {
	addr := t.createHost(x)
	t.hostTestDouble(pass, addr, true)
}

var i int

func (t hostTester) hostTestDouble(pass bool, addr *ipaddr.HostName, doubleTest bool) {
	t.hostNameTest(pass, addr)
	//do it a second time to test the caching
	t.hostNameTest(pass, addr)
	if pass && doubleTest {
		//try {
		//here we call getHost twice, once after calling getNormalizedLabels and once without calling getNormalizedLabels,
		//this is because getHost will use the labels but only if they exist already
		two := t.createParamsHost(addr.String(), addr.GetValidationOptions())
		var twoString, oneString string
		if i%2 == 0 {
			two.GetNormalizedLabels()
			twoString = two.GetHost()
			oneString = addr.GetHost()
		} else {
			oneString = addr.GetHost()
			two.GetNormalizedLabels()
			twoString = two.GetHost()
		}
		i++
		if oneString != twoString {
			t.addFailure(newHostFailure(oneString+" "+twoString, addr))
		}
		//} catch(RuntimeException e) {
		//	addFailure(new Failure(e.getMessage(), addr));
		//}
		t.incrementTestCount()
	}
}

func (t hostTester) hostNameTest(pass bool, addr *ipaddr.HostName) {
	if t.isNotExpected(pass, addr) {
		t.addFailure(newHostFailure("error parsing host "+addr.String(), addr))

		//this part just for debugging
		t.isNotExpected(pass, addr)
	}
	t.incrementTestCount()
}

func (t hostTester) isNotExpected(expectedPass bool, addr *ipaddr.HostName) bool {
	//try {
	err := addr.Validate()
	if err != nil {
		return expectedPass
	}
	return !expectedPass
	//} catch(HostNameException e) {
	//return expectedPass;
	//}
}

func (t hostTester) toExpected(expected string, expectedPort ipaddr.PortInt) *net.TCPAddr {
	h := t.createHost(expected)
	//if(h.IsAddress()) {
	addr := h.GetAddress()
	var zone ipaddr.Zone
	if addr.IsIPv6() {
		zone = addr.ToIPv6().GetZone()
	}
	return &net.TCPAddr{
		IP:   addr.GetNetIP(),
		Port: int(expectedPort),
		Zone: string(zone),
	} //new InetSocketAddress(h.asInetAddress(), expectedPort);
	//}
	//return  &net.TCPAddr{
	//	IP:   addr.GetIP(),
	//	Port: expectedPort,
	//}
	//new InetSocketAddress(h.getHost(), expectedPort);
}

func (t hostTester) testNotHostInetSocketAddress(host string) {
	t.testHostInetSocketAddressSA(host, nil, nil)
}

func (t hostTester) testHostInetSocketAddress(host, expected string, expectedPort ipaddr.PortInt) {
	t.testHostInetSocketAddressService(host, nil, expected, expectedPort)
}

func (t hostTester) testHostInetSocketAddressService(host string, serviceMapper func(string) ipaddr.Port, expected string, expectedPort ipaddr.PortInt) {
	t.testHostInetSocketAddressSA(host, serviceMapper, t.toExpected(expected, expectedPort))
}

func (t hostTester) testHostInetSocketAddressSA(host string, serviceMapper func(string) ipaddr.Port, expected *net.TCPAddr) {
	h := t.createHost(host)
	socketAddr := h.ToNetTCPAddrService(serviceMapper)
	//InetSocketAddress socketAddr = h.asInetSocketAddress(serviceMapper);

	if socketAddr == nil && expected == nil {
	} else if socketAddr == nil || expected == nil {
		t.addFailure(newHostFailure(fmt.Sprintf("socket address mismatch, expected: %v  result: ", expected, socketAddr), h))
	} else if socketAddr.Port != expected.Port || socketAddr.Zone != expected.Zone || !socketAddr.IP.Equal(expected.IP) {
		t.addFailure(newHostFailure("socket address mismatch, expected: "+expected.String()+" result: "+socketAddr.String(), h))
	}
	if socketAddr != nil && h.GetService() == "" {
		h2 := ipaddr.NewHostNameFromNetTCPAddr(socketAddr)
		if !h.Equal(h2) {
			t.addFailure(newHostFailure("socket address mismatch, expected: "+h.String()+" result: "+h2.String(), h))
		}
	}
	t.incrementTestCount()
}

func (t hostTester) testHostAddressWithService(host, hostExpected, serviceExpected string, expectedZone ipaddr.Zone) {
	t.testHostPortServZonePref(host, hostExpected, hostExpected, nil, serviceExpected, expectedZone, nil)
}

func (t hostTester) testHostWithService(host, hostExpected, serviceExpected string, expectedZone ipaddr.Zone) {
	t.testHostPortServZonePref(host, hostExpected, "", nil, serviceExpected, expectedZone, nil)
}

func (t hostTester) testHostAddressPortZone(host, hostExpected string, portExpected ipaddr.Port, expectedZone ipaddr.Zone) {
	t.testHostAddress(host, hostExpected, hostExpected, portExpected, expectedZone)
}

func (t hostTester) testHostAddressPortZonePref(host, hostExpected string, portExpected ipaddr.Port, expectedZone ipaddr.Zone, prefixLength ipaddr.PrefixLen) {
	t.testHostAddressPref(host, hostExpected, hostExpected, portExpected, expectedZone, prefixLength)
}

func (t hostTester) testHostPortZone(host, hostExpected string, portExpected ipaddr.Port, expectedZone ipaddr.Zone) {
	t.testHostPortServZonePref(host, hostExpected, "", portExpected, "", expectedZone, nil)
}

func (t hostTester) testHostAddress(host, hostExpected, addrExpected string, portExpected ipaddr.Port, expectedZone ipaddr.Zone) {
	t.testHostPortServZonePref(host, hostExpected, addrExpected, portExpected, "", expectedZone, nil)
}

func (t hostTester) testHostAddressPref(host, hostExpected, addrExpected string, portExpected ipaddr.Port, expectedZone ipaddr.Zone, prefixLengthExpected ipaddr.PrefixLen) {
	t.testHostPortServZonePref(host, hostExpected, addrExpected, portExpected, "", expectedZone, prefixLengthExpected)
}

func (t hostTester) testHostPortServZonePref(host, hostExpected, addrExpected string, portExpected ipaddr.Port, serviceExpected string, expectedZone ipaddr.Zone, prefixLengthExpected ipaddr.PrefixLen) {
	hostName := t.createHost(host)
	t.testHostAll(hostName, hostExpected, addrExpected, portExpected, serviceExpected, expectedZone, prefixLengthExpected)
}

func (t hostTester) testHostPortServZone(hostName *ipaddr.HostName, hostExpected, addrExpected string, portExpected ipaddr.Port, serviceExpected string, expectedZone ipaddr.Zone) {
	t.testHostAll(hostName, hostExpected, addrExpected, portExpected, serviceExpected, expectedZone, nil)
}

func addressesEqual(one, two *ipaddr.IPAddress) bool {
	return one.Equal(two)
}

func (t hostTester) testHostAll(hostName *ipaddr.HostName, hostExpected, addrExpected string, portExpected ipaddr.Port, serviceExpected string, expectedZone ipaddr.Zone, prefixLengthExpected ipaddr.PrefixLen) {
	//try {
	h := hostName.GetHost()
	var addressExpected *ipaddr.IPAddress
	if addrExpected != "" {
		addressExpected = t.createAddress(addrExpected).GetAddress()
	}
	addrHost := hostName.AsAddress()
	port := hostName.GetPort()
	var zone ipaddr.Zone
	//String zone = null;
	if addrHost != nil && addrHost.IsIPv6() {
		zone = addrHost.ToIPv6().GetZone()
	}
	prefLength := hostName.GetNetworkPrefixLen()
	if h != hostExpected {
		t.addFailure(newHostFailure("failed: host is "+h, hostName))
	} else if !port.Equal(portExpected) {
		t.addFailure(newHostFailure("failed: port is "+port.String(), hostName))
	} else if zone != expectedZone {
		t.addFailure(newHostFailure("failed:  zone is "+zone.String(), hostName))
	} else if !addressesEqual(addrHost, addressExpected) {
		t.addFailure(newHostFailure(fmt.Sprintf("failed: address is %v", addrHost), hostName))
	} else if !prefLength.Equal(prefixLengthExpected) {
		t.addFailure(newHostFailure("failed: prefix is "+prefLength.String(), hostName))
	}
	if addressExpected != nil && addrHost != nil {
		if serviceExpected == "" {
			if portExpected != nil {
				h2 := ipaddr.NewHostNameFromAddrPort(addrHost, portExpected.Num())
				if !h2.Equal(hostName) {
					t.addFailure(newHostFailure("failed: host is "+h2.String(), hostName))
				}
				h3 := ipaddr.NewHostNameFromAddrPort(addressExpected, portExpected.Num())
				if !h3.Equal(hostName) {
					t.addFailure(newHostFailure("failed: host is "+h3.String(), hostName))
				}
			} else if expectedZone == "" {
				if prefixLengthExpected == nil {
					h2 := ipaddr.NewHostNameFromNetIP(addrHost.GetNetIP())
					if !h2.Equal(hostName) {
						t.addFailure(newHostFailure("failed: host is "+h2.String(), hostName))
					}
				} else {
					h2 := ipaddr.NewHostNameFromPrefixedNetIP(addrHost.GetNetIP(), prefixLengthExpected)
					if !h2.Equal(hostName) {
						t.addFailure(newHostFailure("failed: host is "+h2.String(), hostName))
					}
				}
			}
		}
	}
	//} catch(RuntimeException e) {
	//	addFailure(new Failure(e.getMessage(), hostName));
	//}
	t.incrementTestCount()
}

func ToPort(i ipaddr.PortInt) ipaddr.Port {
	res := ipaddr.PortNum(i)
	return &res
}
