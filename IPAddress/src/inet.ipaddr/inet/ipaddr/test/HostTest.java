/*
 * Copyright 2016-2018 Sean C Foley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     or at
 *     https://github.com/seancfoley/IPAddress/blob/master/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package inet.ipaddr.test;

import java.util.Objects;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.format.validate.Validator;
import inet.ipaddr.ipv6.IPv6Address;


public class HostTest extends TestBase {
	
	HostTest(AddressCreator creator) {
		super(creator);
	}
	
	void testResolved_inet_aton(String original, String expectedResolved) {
		HostName origAddress = createHost_inet_aton(original);
		testResolved(origAddress, original, expectedResolved);
	}
	
	void testResolved(String original, String expectedResolved) {
		HostName origAddress = createHost_inet_aton(original);
		testResolved(origAddress, original, expectedResolved);
	}
	
	void testResolved(HostName original, String originalStr, String expectedResolved) {
		try {
			IPAddress resolvedAddress = original.getAddress();
			boolean result;
			if(resolvedAddress == null && original.isAllAddresses() && expectedResolved != null) {
				//special case for "*"
				IPAddressString exp = createAddress(expectedResolved);
				result = original.asAddressString().equals(exp);
			} else {
				result = (resolvedAddress == null) ? (expectedResolved == null) : resolvedAddress.equals(createAddress(expectedResolved).getAddress());
			}
			if(!result) {
				addFailure(new Failure("resolved was " + resolvedAddress + " original was " + originalStr, original));
			} else if (resolvedAddress != null && !(resolvedAddress.isIPv6() && ((IPv6Address) resolvedAddress).hasZone())) {
				HostName host = resolvedAddress.toHostName();
				if(!original.equals(host) && !original.isSelf() && !host.isSelf()) {
					addFailure(new Failure("reverse was " + host + " original was " + original, original));
				} else if(!original.isAddress()) {
					//System.out.println("" + resolvedAddress.toCanonicalHostName());
				}
			}
		} catch(IncompatibleAddressException e) {
			addFailure(new Failure(e.toString(), original));
		} catch(RuntimeException e) {
			addFailure(new Failure(e.toString(), original));
		}
		incrementTestCount();
	}
	
	void testNormalizedHost(boolean expectMatch, String original, String expected) {
		HostName w = createHost(original);
		String normalized = w.toNormalizedString();
		if(!(normalized.equals(expected) == expectMatch)) {
			addFailure(new Failure("normalization was " + normalized, w));
		}
		incrementTestCount();
	}
	
	void testCanonical(String original, String expected) {
		HostName w = createHost(original);
		String canonical = w.asAddress().toCanonicalString();
		if(!canonical.equals(expected)) {
			addFailure(new Failure("canonicalization was " + canonical, w));
		}
		incrementTestCount();
	}
	
	void hostTest_inet_aton(boolean pass, String x) {
		HostName addr = createHost_inet_aton(x);
		hostTestDouble(pass, addr, false);
	}
	
	void hostTest(boolean pass, String x) {
		HostName addr = createHost(x);
		hostTestDouble(pass, addr, true);
	}
	
	static int i;

	void hostTestDouble(boolean pass, HostName addr, boolean doubleTest) {
		hostTest(pass, addr);
		//do it a second time to test the caching
		hostTest(pass, addr);
		if(pass && doubleTest) {
			try {
				//here we call getHost twice, once after calling getNormalizedLabels and once without calling getNormalizedLabels,
				//this is because getHost will use the labels but only if they exist already
				HostName two = createHost(addr.toString(), addr.getValidationOptions());
				String twoString, oneString;
				if(i++ % 2 == 0) {
					two.getNormalizedLabels();
					twoString = two.getHost();
					oneString = addr.getHost();
				} else {
					oneString = addr.getHost();
					two.getNormalizedLabels();
					twoString = two.getHost();
				}
				if(!oneString.equals(twoString)) {
					addFailure(new Failure(oneString + ' ' + twoString, addr));
				}
			} catch(RuntimeException e) {
				addFailure(new Failure(e.getMessage(), addr));
			}
			incrementTestCount();
		}
	}
	
	void hostTest(boolean pass, HostName addr) {
		if(isNotExpected(pass, addr)) {
			addFailure(new Failure(pass, addr));
			
			//this part just for debugging
			isNotExpected(pass, addr);
		}
		incrementTestCount();
	}
	
	boolean isNotExpected(boolean expectedPass, HostName addr) {
		try {
			addr.validate();
			return !expectedPass;
		} catch(HostNameException e) {
			return expectedPass;
		}
	}
	
	void testURL(String url) {
		HostName w = createHost(url);
		try {
			w.validate();
			addFailure(new Failure("failed: " + "URL " + url, w));
		} catch(HostNameException e) {
			//pass
			e.getMessage();
		}
		incrementTestCount();
	}
	
	void testSelf(String host, boolean isSelf) {
		HostName w = createHost(host);
		if(isSelf != w.isSelf()) {
			addFailure(new Failure("failed: isSelf is " + isSelf, w));
		}
		incrementTestCount();
	}
	
	static boolean conversionMatches(HostName host1, HostName host2) {
		IPAddress h1 = host1.asAddress();
		if(h1 != null && h1.isIPv4()) {
			IPAddress h2 = host2.asAddress();
			if(!h2.isIPv4()) {
				if(h2.isIPv4Convertible()) {
					return h1.equals(h2.toIPv4());
				}
			}
		} else if(h1 != null && h1.isIPv6()) {
			IPAddress h2 = host2.asAddress();
			if(!h2.isIPv6()) {
				if(h2.isIPv6Convertible()) {
					return h1.equals(h2.toIPv6());
				}
			}
		}
		return false;
	}
	
	void testMatches(boolean matches, String host1, String host2) {
		testMatches(matches, host1, host2, HOST_OPTIONS);
	}
	
	void testMatches(boolean matches, String host1, String host2, HostNameParameters options) {
		HostName h1 = createHost(host1, options);
		HostName h2 = createHost(host2, options);
		if(matches != h1.matches(h2) && matches != conversionMatches(h1, h2)) {
			addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + host2, h1));
		} else {
			if(matches != h2.matches(h1) && matches != conversionMatches(h2, h1)) {
				addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + host1, h2));
			} else {
				if(matches != h1.equals(h2) && matches != conversionMatches(h1, h2)) {
					addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h1, h2));
				} else {
					testNormalizedMatches(h1);
					testNormalizedMatches(h2);
				}
			}
		}
		incrementTestCount();
	}
	
	private static CharSequence translateReserved(IPv6Address addr, String str) {
		//This is particularly targeted towards the zone
		if(!addr.hasZone()) {
			return str;
		}
		int index = str.indexOf(IPv6Address.ZONE_SEPARATOR);
		StringBuilder translated = new StringBuilder(((str.length() - index) * 3) + index);
		translated.append(str, 0, index);
		translated.append("%25");
		for(int i = index + 1; i < str.length(); i++) {
			char c = str.charAt(i);
			if(Validator.isReserved(c)) {
				translated.append('%').append(Integer.toHexString(c));
			} else {
				translated.append(c);
			}
		}
		return translated;
	}
	
	private void testNormalizedMatches(HostName h1) {
		String normalized;
		if(h1.isAddress() && h1.asAddress().isPrefixed() && h1.asAddress().isIPv6()) {
			IPv6Address addr = h1.asAddress().getLower().withoutPrefixLength().toIPv6();
			normalized = '[' + translateReserved(addr, addr.toNormalizedString()).toString() + "]/" + h1.asAddress().getNetworkPrefixLength();
		} else if(h1.isAddress() && h1.asAddress().isIPv6()) {
			IPv6Address addr = h1.asAddress().toIPv6();
			normalized = '[' + translateReserved(addr, addr.toNormalizedWildcardString()).toString() + "]";
		} else {
			normalized = h1.toNormalizedString();
		}
		String h1Bracketed = h1.toNormalizedString();
		if(!h1Bracketed.equals(normalized)) {
			addFailure(new Failure("failed: bracketed is " + normalized, h1));
		}
		incrementTestCount();
	}
	
	void testHostAddressWithService(String host, String hostExpected, String serviceExpected, String expectedZone) {
		testHost(host, hostExpected, hostExpected, null, serviceExpected, expectedZone, null);
	}
	
	void testHostWithService(String host, String hostExpected, String serviceExpected, String expectedZone) {
		testHost(host, hostExpected, null, null, serviceExpected, expectedZone, null);
	}

	void testHostAddress(String host, String hostExpected, Integer portExpected, String expectedZone) {
		testHostAddress(host, hostExpected, hostExpected, portExpected, expectedZone);
	}
	
	void testHostAddress(String host, String hostExpected, Integer portExpected, String expectedZone, Integer prefixLength) {
		testHostAddress(host, hostExpected, hostExpected, portExpected, expectedZone, prefixLength);
	}

	void testHost(String host, String hostExpected, Integer portExpected, String expectedZone) {
		testHost(host, hostExpected, null, portExpected, null, expectedZone, null);
	}

	void testHostAddress(String host, String hostExpected, String addrExpected, Integer portExpected, String expectedZone) {
		testHost(host, hostExpected, addrExpected, portExpected, null, expectedZone, null);
	}
	
	void testHostAddress(String host, String hostExpected, String addrExpected, Integer portExpected, String expectedZone, Integer prefixLengthExpected) {
		testHost(host, hostExpected, addrExpected, portExpected, null, expectedZone, prefixLengthExpected);
	}

	void testHost(String host, String hostExpected, String addrExpected, Integer portExpected, String serviceExpected, String expectedZone, Integer prefixLengthExpected) {
		HostName hostName = createHost(host);
		testHost(hostName, hostExpected, addrExpected, portExpected, serviceExpected, expectedZone, prefixLengthExpected);
	}

	void testHost(HostName hostName, String hostExpected, String addrExpected, Integer portExpected, String serviceExpected, String expectedZone) {
		testHost(hostName, hostExpected, addrExpected, portExpected, serviceExpected, expectedZone, null);
	}
	
	void testHost(HostName hostName, String hostExpected, String addrExpected, Integer portExpected, String serviceExpected, String expectedZone, Integer prefixLengthExpected) {
		try {
			String h = hostName.getHost();
			IPAddress addressExpected = addrExpected == null ? null : createAddress(addrExpected).getAddress();
			IPAddress addrHost = hostName.asAddress();
			Integer port = hostName.getPort();
			String zone = null;
			if(addrHost != null && addrHost.isIPv6()) {
				zone = addrHost.toIPv6().getZone();
			}
			Integer prefLength = hostName.getNetworkPrefixLength();
			if(!h.equals(hostExpected)) {
				addFailure(new Failure("failed: host is " + h, hostName));
			} else if(!Objects.equals(port, portExpected)) {
				addFailure(new Failure("failed: port is " + port, hostName));
			} else if(!Objects.equals(zone, expectedZone)) {
				addFailure(new Failure("failed:  zone is " + zone, hostName));
			} else if(!Objects.equals(addrHost, addressExpected)) {
				addFailure(new Failure("failed: address is " + addrHost, hostName));
			} else if(!Objects.equals(prefLength, prefixLengthExpected)) {
				addFailure(new Failure("failed: prefix is " + prefLength, hostName));
			}
		} catch(RuntimeException e) {
			addFailure(new Failure(e.getMessage(), hostName));
		}
		incrementTestCount();
	}
	
	boolean isLenient() {
		return false;
	}
	
	public static boolean runDNS = true;
	
	@Override
	void runTest()
	{
		testSelf("1.2.3.4", false);
		testSelf("1::", false);
		testSelf("[1::]", false);
		testSelf("bla.com", false);
		testSelf("::1", true);
		testSelf("[::1]", true);
		testSelf("localhost", true);
		testSelf("127.0.0.1", true);
		
		testSelf("[127.0.0.1]", true);
		testSelf("[localhost]", false);//square brackets are for ipv6
		testSelf("-ab-.com", false);
		
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		boolean isAllSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		
		testMatches(true, "a.com", "A.cOm");
		testMatches(false, "a.comx", "a.com");
		testMatches(false, "1::", "2::");
		testMatches(false, "1::", "1.2.3.4");
		testMatches(true, "1::", "1:0::");
		testMatches(true, "f::", "F:0::");
		testMatches(true, "1::", "[1:0::]");
		testMatches(true, "[1::]", "1:0::");
		testMatches(false, "1::", "1:0:1::");
		testMatches(true, "1.2.3.4", "1.2.3.4");
		testMatches(true, "1.2.3.4", "001.2.3.04");
		testMatches(true, "1.2.3.4", "::ffff:1.2.3.4");//ipv4 mapped
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%a", "1:2:3:4:5:6:102:304%a");
		testMatches(false, "1:2:3:4:5:6:1.2.3.4%", "1:2:3:4:5:6:102:304%");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%%", "1:2:3:4:5:6:102:304%%");
		testMatches(true, "[1:2:3:4:5:6:1.2.3.4%25%31]", "1:2:3:4:5:6:102:304%1");
		testMatches(true, "[1:2:3:4:5:6:102:304%25%31]", "1:2:3:4:5:6:102:304%1");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%-", "1:2:3:4:5:6:102:304%-");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%-/64", "1:2:3:4:5:6:102:304%-/64");
		
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:1.2.3.4");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:0.0.0.0", "1:2:3:4:5:6::");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:0:0.0.0.0", "1:2:3:4:5::");
		testMatches(true, "[1:2:3:4:5:6::%y]", "1:2:3:4:5:6::%y");
		testMatches(true, "[1:2:3:4:5:6::%25y]", "1:2:3:4:5:6::%y");//see rfc 6874 about %25
		testMatches(true, "[1:2:3:4:5:6::]/32", "1:2:3:4:5:6::/32");
		testMatches(true, "[1:2::]/32", "1:2::/32");
		testMatches(true, "[1:ff00::]/24", "1:ff00::/24");
		testMatches(true, "[1:ffff::]/24", "1:ffff::/24");
		testMatches(isAllSubnets, "1.2.3.4/255.0.0.0", "1.0.0.0/255.0.0.0");
		
		testMatches(true, "[IPv6:1:2:3:4:5:6:7:8%y]", "1:2:3:4:5:6:7:8%y");
		testMatches(true, "[IPv6:1:2:3:4:5:6:7:8]", "1:2:3:4:5:6:7:8");
		testMatches(true, "[IPv6:1:2:3:4:5:6::]/32", "1:2:3:4:5:6::/32");
		testMatches(true, "[IPv6:1:2::]/32", "1:2::/32");
		testMatches(true, "[IPv6:::1]", "::1");
		testMatches(true, "[IPv6:1::]", "1::");
		
		testResolved("a::b:c:d:1.2.3.4%x", "a::b:c:d:1.2.3.4%x");
		testResolved("[a::b:c:d:1.2.3.4%x]", "a::b:c:d:1.2.3.4%x");
		testResolved("[a::b:c:d:1.2.3.4]", "a::b:c:d:1.2.3.4");//square brackets can enclose ipv6 in host names but not addresses 
		testResolved("2001:0000:1234:0000:0000:C1C0:ABCD:0876%x", "2001:0:1234::c1c0:abcd:876%x"); 
		testResolved("[2001:0000:1234:0000:0000:C1C0:ABCD:0876%x]", "2001:0:1234::c1c0:abcd:876%x");
		testResolved("[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "2001:0:1234::C1C0:abcd:876");//square brackets can enclose ipv6 in host names but not addresses
		testResolved("2001:0000:1234:0000:0000:C1C0:ABCD:0876", "2001:0:1234::C1C0:abcd:876");//square brackets can enclose ipv6 in host names but not addresses
		testResolved("1.2.3.04", "1.2.3.4");
		testResolved_inet_aton("1.2.3", "1.2.0.3");
		testResolved("[1.2.3.4]", "1.2.3.4");

		if(fullTest && runDNS) {
			testResolved("espn.com", "199.181.132.250");
			testResolved("espn.com/24", "199.181.132.0/24");
			testResolved("instapundit.com", "72.32.173.45");
		}

		testResolved("9.32.237.26", "9.32.237.26");
		testResolved("9.70.146.84", "9.70.146.84");
		testResolved("", null);
		
		testNormalizedHost(true, "[A::b:c:d:1.2.03.4]", "[a:0:0:b:c:d:102:304]");//square brackets can enclose ipv6 in host names but not addresses
		testNormalizedHost(true, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "[2001:0:1234:0:0:c1c0:abcd:876]");//square brackets can enclose ipv6 in host names but not addresses
		testNormalizedHost(true, "1.2.3.04", "1.2.3.4");
		
		testCanonical("[A:0::c:d:1.2.03.4]", "a::c:d:102:304");//square brackets can enclose ipv6 in host names but not addresses
		testCanonical("[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "2001:0:1234::c1c0:abcd:876");//square brackets can enclose ipv6 in host names but not addresses
		testCanonical("1.2.3.04", "1.2.3.4");
		
		testNormalizedHost(true, "WWW.ABC.COM", "www.abc.com");
		testNormalizedHost(true, "WWW.AB-C.COM", "www.ab-c.com");

		testURL("http://1.2.3.4");
		testURL("http://[a:a:a:a:b:b:b:b]");
		testURL("http://a:a:a:a:b:b:b:b");

		hostLabelsTest("one.two.three.four.five.six.seven.EIGHT", new String[] {"one", "two", "three", "four", "five", "six", "seven", "eight"});
		hostLabelsTest("one.two.three.four.fIVE.sIX.seven", new String[] {"one", "two", "three", "four", "five", "six", "seven"});
		hostLabelsTest("one.two.THREE.four.five.six", new String[] {"one", "two", "three", "four", "five", "six"});
		hostLabelsTest("one.two.three.four.five", new String[] {"one", "two", "three", "four", "five"});
		hostLabelsTest("one.two.three.four", new String[] {"one", "two", "three", "four"});
		hostLabelsTest("one.Two.three", new String[] {"one", "two", "three"});
		hostLabelsTest("onE.two", new String[] {"one", "two"});
		hostLabelsTest("one", new String[] {"one"});
		hostLabelsTest("", isLenient() ? new String[] {"127", "0", "0", "1"} : new String[0]);
		hostLabelsTest(" ", isLenient() ? new String[] {"127", "0", "0", "1"} : new String[0]);
		hostLabelsTest("1.2.3.4", new String[] {"1", "2", "3", "4"});
		hostLabelsTest("1:2:3:4:5:6:7:8", new String[] {"1", "2", "3", "4", "5", "6", "7", "8"});
		hostLabelsTest("[::]", new String[] {"0", "0", "0", "0", "0", "0", "0", "0"});
		hostLabelsTest("::", new String[] {"0", "0", "0", "0", "0", "0", "0", "0"});
		
		hostTest(true, "1.2.3.4/1.2.3.4");
		hostTest(true, "1.2.3.4/255.0.0.0");
		hostTest(true, "abc.com/255.0.0.0");
		hostTest(true, "abc.com/::");
		hostTest(true, "abc.com/::1");
		
		//Since service names cannot have ':' and can be at most 15 chars, and since all IPv6 must have a ':' or must be at least 32 digits otherwise, there is no ambiguity below
		//of course, none of the forms below can appear in a URL
		hostTest(true, "abc.com/1::1");//this is abc.com with mask 1::1
		hostTest(true, "abc.com/1:1");//this one is abc.com with prefix 1 and port 1 
		hostTest(true, "abc.com/1:abc");//this one is abc.com with prefix 1 and service abc
		hostTest(true, "abc.com/1.2.3.4");//this is abc.com with mask 1.2.3.4
		hostTest(true, "abc.com:a1-2-3-4");//this is abc.com with service a1-2-3-4 (note service must have at least one letter)
		
		hostTest(true, "abc.com/1::");
		hostTest(true, "abc.com/32");
		
		hostTest(false, "[1.2.3.4");
		hostTest(false, "[1:2:3:4:5:6:7:8");
		hostTest(true,"[a::b:c:d:1.2.3.4]");//square brackets can enclose ipv6 in host names but not addresses
		hostTest(true, "[a::b:c:d:1.2.3.4%x]");
		hostTest(true, "a::b:c:d:1.2.3.4%x");
		hostTest(false, "a:b:c:d:1.2.3.4%x");
		hostTest(true,"[2001:0000:1234:0000:0000:C1C0:ABCD:0876]");//square brackets can enclose ipv6 in host names but not addresses
		hostTest(true, "2001:0000:1234:0000:0000:C1C0:ABCD:0876%x");//ipv6 must be enclosed in []
		hostTest(true, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876%x]");//zones not allowed when using []
		
		hostTest(true, "1:2:3:4:5:6:1.2.3.4%%"); //the % is the zone itself, when treated as an address
		hostTest(false, "[1:2:3:4:5:6:1.2.3.4%%]"); //the % is an encoding, when treated as a host
		hostTest(true, "1:2:3:4:5:6:1.2.3.4%%"); //the % is allowed in zone, when treated as a address
		hostTest(true, "[1:2:3:4:5:6:1.2.3.4%25%31]"); //the % is an encoding, when treated as a host, so this is in fact the zone of 1 (%25 is zone char, %31 is 1)
		hostTest(true, "1:2:3:4:5:6:1.2.3.4%25%31"); //this is in fact the zone 25%31

		hostTest(true, "1.2.3.4");
		hostTest_inet_aton(true, "1.2.3");
		hostTest(true,"0x1.0x2.0x3.04");
		hostTest(true, "[1.2.3.4]");
		
		hostTest(true, "a_b.com");
		hostTest(true, "_ab.com");
		hostTest(true, "_ab_.com");
		hostTest(false, "-ab-.com");
		hostTest(false, "ab-.com");
		hostTest(false, "-ab.com");
		hostTest(false, "ab.-com");
		hostTest(false, "ab.com-");
		
		hostTest(true, "a9b.com");
		hostTest(true, "9ab.com");
		hostTest(true, "999.com");
		hostTest(true, "ab9.com");
		hostTest(true, "ab9.com9");
		hostTest_inet_aton(true, "999");
		hostTest_inet_aton(true, "111.999");
		hostTest(false, "999.111");
		
		hostTest(false, "a*b.com");
		hostTest(false, "*ab.com");
		hostTest(false, "ab.com*");
		hostTest(false, "*.ab.com");
		hostTest(false, "ab.com.*");
		hostTest(false, "ab.co&m");
		hostTest(false, "#.ab.com");
		hostTest(false, "cd.ab.com.~");
		hostTest(false, "#x.ab.com");
		hostTest(false, "cd.ab.com.x~");
		hostTest(false, "x#.ab.com");
		hostTest(false, "cd.ab.com.~x");
		hostTest(true, "xx.ab.com.xx");
		
		hostTest(true, "ab.cde.fgh.com");
		hostTest(true, "aB.cDE.fgh.COm");
		
		hostTest(true, "123-123456789-123456789-123456789-123456789-123456789-123456789.com"); //label 63 chars
		hostTest(false, "1234-123456789-123456789-123456789-123456789-123456789-123456789.com"); //label 64 chars
		hostTest(false, "123.123456789.123456789.123456789.123456789.123456789.123456789.123");//all numbers
		hostTest(true, "aaa.123456789.123456789.123456789.123456789.123456789.123456789.123");//numbers everywhere but first label
		
		hostTest(false, "a11" +
			"-123456789-123456789-123456789-123456789-12345678." +
			"-123456789-123456789-123456789-123456789-12345678." +
			"-123456789-123456789-123456789-123456789-12345678." +
			"-123456789-123456789-123456789-123456789-12345678." +
			"-123456789-123456789-123456789-123456789-123456789"); //253 chars, but segments start with -
		
		hostTest(true, "a11" +
				"-123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-123456789"); //253 chars
			
		hostTest(false, "111" +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"01234567890123456789012345678901234567890123456789"); //all number
		
		hostTest(true, "222" +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678f"); //not all number, 253 chars
		
		hostTest(false, "a222" +
				"-123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-12345678." +
				"0123456789-123456789-123456789-123456789-123456789"); //254 chars
		
		hostTest(true, "a33" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789"); //253 chars
			
		hostTest(false, "444" +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"01234567890123456789012345678901234567890123456789"); //all number
		
		hostTest(true, "555" +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678." +
				"0123456789012345678901234567890123456789012345678f"); //not all number
		
		hostTest(true, "777" +
				"01234567890123456789012345678901234567890123456789" +
				"0123456789.123456789012345678901234567890123456789" +
				"012345678901234567890123.5678901234567890123456789" +
				"01234567890123456789012345678901234567.90123456789" +
				"0123456789012345678901234567890123456789012345678f"); //first 3 segments are 63 chars
		
		hostTest(false, "777" +
				"01234567890123456789012345678901234567890123456789" +
				"01234567890.23456789012345678901234567890123456789" +
				"012345678901234567890123.5678901234567890123456789" +
				"01234567890123456789012345678901234567.90123456789" +
				"0123456789012345678901234567890123456789012345678f"); //first segment 64 chars
		
		hostTest(false, "a666" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789" +
				".123456789.123456789.123456789.123456789.123456789"); //254 chars
		
		hostTest(true, "a.9." +	
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5"); //252 chars, 127 segments
		
		hostTest(false, "a.8." +	
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5."); //252 chars, 127 segments, extra dot at end
		
		hostTest(false, ".a.7." +	
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5"); //252 chars, 127 segments, extra dot at front
		
		hostTest(false, "a.6." +	
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5." +
				"1.1.1.1.1.2.2.2.2.2.3.3.3.3.3.4.4.4.4.4.5.5.5.5.5.8"); //254 chars, 128 segments
		
		hostTest(false, "a:b:com");
		hostTest(true, "a:b::ccc");
		hostTest(true, "a:b:c:d:e:f:a:b");
		
		hostTest(false, ".as.b.com");//starts with dot
		hostTest(false, "as.b.com.");//ends with dot
		hostTest(false, "aas.b.com.");//starts and ends with dot
		hostTest(false, "as..b.com");//double dot
		hostTest(false, "as.b..com");//double dot
		hostTest(false, "..as.b.com");//starts with dots
		hostTest(false, "as.b.com..");//ends with dots	
		
		
		testHostAddress("aa-bb-cc-dd-ee-ff-aaaa-bbbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbbb", null, null);
		testHostAddress("aa-bb-cc-dd-ee-ff-aaaa-bbbbseth0.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbbb", "aa:bb:cc:dd:ee:ff:aaaa:bbbb%eth0", null, "eth0");
		testHost("aa-bb-cc-dd-ee-ff.ipv6-literal.net", "aa-bb-cc-dd-ee-ff.ipv6-literal.net", null, null);//not a valid address, too few segments, but a valid host
		testHost("aa-Bb-cc-dd-ee-FF.ipv6-literal.net", "aa-bb-cc-dd-ee-ff.ipv6-literal.net", null, null);//not a valid address, too few segments, but a valid host
		testHostAddress("aa-bb-cc-dd-ee-ff-aaaa-bbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbb", null, null);
		testHostAddress("aa-Bb-cc-dd-ee-FF-aaaa-bbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbb", null, null);
		testHostAddress("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.arpa", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", null, null);
		testHostAddress("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", null, null);
		testHostAddress("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int:45", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", 45, null);
		testHostAddress("F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", 45, null);
		testHost("f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45", "f.f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int", 45, null);//not a valid address, but a valid host
		testHostAddress("255.22.2.111.in-addr.arpa", "111.2.22.255", null, null);
		testHostAddress("255.22.2.111.in-addr.arpa:35", "111.2.22.255", 35, null);
		testHost("255.22.2.111.3.in-addr.arpa:35", "255.22.2.111.3.in-addr.arpa", 35, null);
		testHostAddress("1.2.2.1:33", "1.2.2.1", 33, null);
		testHostAddress("[::1]:33", "::1", 33, null);
		testHostAddress("::1:33", "::1:33", null, null);
		testHostAddress("::1%eth0", "::1", "::1%eth0", null, "eth0");
		testHostAddress("[::1%eth0]:33", "::1", "::1%eth0", 33, "eth0");
		testHost("bla.bla:33", "bla.bla", 33, null);
		testHost("blA:33", "bla", 33, null);
		testHost("f:33", "f", 33, null);
		testHostAddress("f::33", "f::33", null, null);
		testHostAddress("::1", "::1", null, null);
		testHostAddress("[::1]", "::1", null, null);
		testHostAddress("/16", "/16", null, null, 16);
		testHostAddress("/32", "/32", null, null, 32);
		testHostAddress("/64", isNoAutoSubnets ? "ffff:ffff:ffff:ffff::" : "ffff:ffff:ffff:ffff:*:*:*:*", "ffff:ffff:ffff:ffff::/64", null, null, 64);
		
		hostTest(true, "255.22.2.111.3.in-addr.arpa:35");//not a valid address but still a valid host
		hostTest(false, "[::1]x");
		hostTest(false, "[::1x]");
		hostTest(false, "[::x1]");
		hostTest(false, "x[::1]");
		hostTest(false, "[]");
		hostTest(false, "[a]");
		hostTest(false, "1.2.2.256:33");
		hostTest(true, "f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45");//not an address, but a valid host
		hostTest(true, "f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int");//not an address, but a valid host
		hostTest(false, "aa-bb-cc-dd-ee-ff-.ipv6-literal.net");
		hostTest(true, "aa-bb-cc-dd-ge-ff.ipv6-literal.net"); //not an address but a valid host

		testHostAddressWithService("1.2.3.4:nfs", "1.2.3.4", "nfs", null);
		testHost("[::1%eth0]:nfs", "::1", "::1%eth0", null, "nfs", "eth0", null);
		testHostAddressWithService("1.2.3.4:12345678901234a", "1.2.3.4", "12345678901234a", null);
		hostTest(false, "1.2.3.4:123456789012345a");
		hostTest(false, "1.2.3.4:");
		testHostAddressWithService("[::1]:12345678901234a", "::1", "12345678901234a", null);
		testHostAddressWithService("[::1]:12345678901234x", "::1", "12345678901234x", null);
		testHostAddressWithService("1.2.3.4:a", "1.2.3.4", "a", null);
		testHostAddressWithService("1.2.3.4:a-b-c", "1.2.3.4", "a-b-c", null);
		testHostAddressWithService("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:a-b-c", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "a-b-c", null);
		hostTest(false, "1.2.3.4:a-");
		hostTest(false, "1.2.3.4:-a");
		hostTest(false, "1.2.3.4:a--b");
		hostTest(false, "1.2.3.4:x-");
		hostTest(false, "1.2.3.4:-x");
		hostTest(false, "1.2.3.4:x--x");
		
		testHost("a.b.c/16:nfs", "a.b.c", null, null, "nfs", null, 16);
		testHost("a.b.c/16:80", "a.b.c", null, 80, null, null, 16);
		testHostWithService("a.b.c:nfs", "a.b.c", "nfs", null);
		hostTest(false, "[a.b.com]:nfs");//non-Ipv6 inside brackets
		hostTest(true, "[::]:nfs");
		testHostWithService("a.b.com:12345678901234a", "a.b.com", "12345678901234a", null);
		testHostWithService("a.b.com:12345678901234x", "a.b.com", "12345678901234x", null);
		testHostWithService("a.b.com:x12345678901234", "a.b.com", "x12345678901234", null);
		testHostWithService("a.b.com:12345x789012345", "a.b.com", "12345x789012345", null);
		testHostWithService("a.b.com:a", "a.b.com", "a", null);
		testHostWithService("a.b.com:a-b-c", "a.b.com", "a-b-c", null);
		testHostWithService("a.b.c:a-b-c", "a.b.c", "a-b-c", null);
		testHostWithService("123-123456789-123456789-123456789-123456789-123456789-123456789.com:a-b-c", "123-123456789-123456789-123456789-123456789-123456789-123456789.com", "a-b-c", null);
		testHostWithService("123-123456789-123456789-123456789-123456789-123456789-123456789.com:12345x789012345", "123-123456789-123456789-123456789-123456789-123456789-123456789.com", "12345x789012345", null);
	
		HostNameParameters expectPortParams = HOST_OPTIONS.toBuilder().expectPort(true).toParams();
		testHostAddressWithService("fe80::6a05:caff:fe3:nfs", "fe80::6a05:caff:fe3", "nfs", null);
		testHostAddress("fe80::6a05:caff:fe3:123", "fe80::6a05:caff:fe3:123", null, null);
		HostName hostName = createHost("fe80::6a05:caff:fe3:123", expectPortParams);
		testHost(hostName, "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3", 123, null, null);
		
		testHostAddress("[1::%25%241]", "1::", "1::%$1", null, "$1");
		testHostAddress("[1::%%241]", "1::", "1::%$1", null, "$1");//when zone marker not %25 we are forgiving
		testHostAddress("[1::%25%241]:123", "1::", "1::%$1", 123, "$1");
		testHostAddress("[1::%%241]:123", "1::", "1::%$1", 123, "$1");
		testHostAddress("1::%25%241:123", "1::", "1::%25%241", 123, "25%241");//%hexhex encoding only when inside '[]' since '[]' is the proper URL format
		testHostAddress("1::%%241:123", "1::", "1::%%241", 123, "%241");
		
		testHostAddress("1::%%1/16", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%%1/16", null, "%1", 16);
		testHostAddress("[1::%251]/16", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%1/16", null, "1", 16);
		
		testHostAddress("[1::%251/16]:3", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%1/16", 3, "1", 16);
		testHostAddress("1::%1/16:3", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%1/16", 3, "1", 16);
		testHostAddress("1::%%1/16:3", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%%1/16", 3, "%1", 16);//that's right, zone, prefix and port!
		testHostAddress("[1::/16]:3", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::/16", 3, null, 16);
		hostTest(false, "[1::/16]/32");//conflicting prefix length
		hostTest(true, "[1::/16]/16");
		hostTest(false, "[1.2.3.4/16]/32");//conflicting prefix length
		hostTest(true, "[1.2.3.4/16]/16");
		hostTest(false, "[1.2.3.4/16]/255.255.255.0");//conflicting prefix length
		hostTest(true, "[1.2.3.4/16]/255.255.0.0");
		hostTest(false, "[1.2.3.4/255.255.255.0]/16");//conflicting prefix length
		hostTest(true, "[1.2.3.4/255.255.0.0]/16");
		hostTest(true, "[1.2.3.4/255.255.255.0]/255.255.255.0");
		hostTest(false, "[1.2.3.4/255.255.0.0]/255.255.255.0");//conflicting mask
		hostTest(false, "[1.2.3.4/255.255.255.0]/255.255.0.0");//conflicting mask
		testHostAddress("1::/16:3", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::/16", 3, null, 16);
		testHostAddress("[1::%251/16]", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%1/16", null, "1", 16);
		testHostAddress("[1::%25%241/16]", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%$1/16", null, "$1", 16);

		testHostAddress("1::%1/16", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%1/16", null, "1", 16);
		testHostAddress("1::%1%1/16", isNoAutoSubnets ? "1::" : "1:*:*:*:*:*:*:*", "1::%1%1/16", null, "1%1", 16);
		testHostAddress("1.2.3.4/16", !isAllSubnets ? "1.2.3.4" : "1.2.*.*", "1.2.3.4/16", null, null, 16);
		testHostAddress("1.2.0.0/16", isNoAutoSubnets ? "1.2.0.0" : "1.2.*.*", "1.2.0.0/16", null, null, 16);
		testHost("a.b.com/24", "a.b.com", null, null, null, null, 24);

		testHostAddress("[fe80::%2]/64", isNoAutoSubnets ? "fe80::" : "fe80::*:*:*:*", "fe80::%2/64", null, "2", 64);//prefix outside the host (can be either inside or outside)
		testHostAddress("fe80::%2/64", isNoAutoSubnets ? "fe80::" : "fe80::*:*:*:*", "fe80::%2/64", null, "2", 64);

		testHostAddress("[::123%25%25%25aaa%25]", "::123", "::123%%%aaa%", null, "%%aaa%");
		testHostAddress("[::123%25%25%25%24aa%25]", "::123", "::123%%%$aa%", null, "%%$aa%");
		testHostAddress("[::123%25%24%25%24aa%25]", "::123", "::123%$%$aa%", null, "$%$aa%");
		testHostAddress("::123%%%", "::123", "::123%%%", null, "%%");

		testHostAddress("fe80:0:0:0:0:6a05:caff:fe3%x:123", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", 123, "x");
		
		testHost("fe80:0:0:0:0:6a05:caff:fe3%x:abc", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", null, "abc", "x", null);
		testHost("fe80:0:0:0:0:6a05:caff:fe3%x/64:abc", isAllSubnets ?  "fe80::*:*:*:*" : "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x/64", null, "abc", "x", 64);//that's right, zone, prefix and service
		testHost("[fe80:0:0:0:0:6a05:caff:fe3%x/64]:abc", isAllSubnets ?  "fe80::*:*:*:*" : "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x/64", null, "abc", "x", 64);//that's right, zone, prefix and service 
		testHostAddress("fe80::6a05:caff:fe3%x:123", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", 123, "x");
		testHost("fe80::6a05:caff:fe3%x:abc", "fe80::6a05:caff:fe3", "fe80::6a05:caff:fe3%x", null, "abc", "x", null);

		testHostAddress("fe80:0:0:0:0:6a05:caff:fe3", "fe80::6a05:caff:fe3", null, null);
		testHostAddressWithService("fe80:0:0:0:0:0:6a05:caff:fe3", "fe80::6a05:caff", "fe3", null);
		testHostAddress("fe80:0:0:0:0:6a05:caff:fe3:123", "fe80::6a05:caff:fe3", 123, null);
		testHostAddressWithService("fe80:0:0:0:0:6a05:caff:fe3:*", "fe80::6a05:caff:fe3", "*", null);
		testHostAddress("::1:8888", "::1:8888", null, null);
		testHostAddressWithService("::1:88g8", "::1", "88g8", null);
		testHostAddressWithService("::1:88a8", "::1:88a8", null, null);
		hostName = createHost("::1:88a8", expectPortParams);
		testHost(hostName, "::1", "::1", null, "88a8", null);
		testHostAddress("::1:48888", "::1", 48888, null);
		testHostAddressWithService("::1:nfs", "::1", "nfs", null);
		testHostAddressWithService(":::*", "::", "*", null);
		testHostAddress(":::1", "::", 1, null);
		testHostAddress(":::123", "::", 123, null);
		testHostAddress("[::]:123", "::", 123, null);
		
		hostTest(false, "::1:88888");//port too large, also too large to be ipv6 segment
		hostTest(false, "::1:88-8");//invalid because no letter in service name, nor is it a port
		hostTest(true, "::1:8888");
		hostTest(true, "::1:58888");
		hostTest(true, "::1:8a-8");
		hostTest(isLenient(), "::1:-8a88");//this passes if the second segment considered a range
		hostTest(false, "1.2.3.4:-8a8");//-8a8 can only be a port or service, but leading hyphen not allowed for a service
		hostTest(true, "1.2.3.4:8-a8");
		
		hostTest(isLenient(), "::1:8a8-:2");
		hostTest(isLenient(), "::1:-8a8:2");
		hostTest(isLenient(), "::1:8a8-");//this passes if the second segment considered a range, cannot be a service due to trailing hyphen
		hostTest(isLenient(), "::1:-8a8");//this passes if the second segment considered a range, cannot be a service due to leading hyphen
	}
}
