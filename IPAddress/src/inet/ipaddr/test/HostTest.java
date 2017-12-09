/*
 * Copyright 2017 Sean C Foley
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

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;

import java.util.Objects;

import inet.ipaddr.IncompatibleAddressException;
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
				if(!original.equals(host)) {
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
				HostName two = createHost(addr.toString());
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
	
	
	private void testNormalizedMatches(HostName h1) {
		String normalized;
		if(h1.isAddress() && h1.asAddress().isPrefixed() && h1.asAddress().isIPv6()) {
			normalized = '[' + h1.asAddress().getLower().removePrefixLength(false).toNormalizedString() + "]/" + h1.asAddress().getNetworkPrefixLength();
		} else if(h1.isAddress() && h1.asAddress().isIPv6()) {
			normalized = '[' + h1.asAddress().toNormalizedWildcardString() + "]";
		} else {
			normalized = h1.toNormalizedString();
		}
		String h1Bracketed = h1.toNormalizedString();
		if(!h1Bracketed.equals(normalized)) {
			addFailure(new Failure("failed: bracketed is " + normalized, h1));
		}
		incrementTestCount();
	}
	
	void testHost(String host, String addrExpected, Integer portExpected, String expectedZone) {
		testHost(host, addrExpected, addrExpected, portExpected, expectedZone);
	}
	
	void testHost(String host, String hostExpected, String addrExpected, Integer portExpected, String expectedZone) {
		HostName hostName = createHost(host);
		try {
			String h = hostName.getHost();
			IPAddress addressExpected = addrExpected == null ? null : createAddress(addrExpected).getAddress();
			IPAddress addrHost = hostName.asAddress();
			Integer port = hostName.getPort();
			String zone = null;
			if(addrHost != null && addrHost.isIPv6()) {
				zone = addrHost.toIPv6().getZone();
			}
			if(!h.equals(hostExpected)) {
				addFailure(new Failure("failed: host is " + h, hostName));
			} else if(!Objects.equals(port, portExpected)) {
				addFailure(new Failure("failed: port is " + port, hostName));
			} else if(!Objects.equals(zone, expectedZone)) {
				addFailure(new Failure("failed:  zone is " + zone, hostName));
			} else if(!Objects.equals(addrHost, addressExpected)) {
				addFailure(new Failure("failed: address is " + addrHost, hostName));
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
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%%", "1:2:3:4:5:6:102:304%%"); //we don't validate the zone itself, so the % reappearing as the zone itself is ok
		
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
		hostTest(true, "abc.com/1::1");
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
		
		
		testHost("aa-bb-cc-dd-ee-ff-aaaa-bbbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbbb", null, null);
		testHost("aa-bb-cc-dd-ee-ff-aaaa-bbbbseth0.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbbb", null, "eth0");
		testHost("aa-bb-cc-dd-ee-ff.ipv6-literal.net", "aa-bb-cc-dd-ee-ff.ipv6-literal.net", null, null);//not a valid address, too few segments
		testHost("aa-Bb-cc-dd-ee-FF.ipv6-literal.net", "aa-bb-cc-dd-ee-ff.ipv6-literal.net", null, null);//not a valid address, too few segments
		testHost("aa-bb-cc-dd-ee-ff-aaaa-bbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbb", null, null);
		testHost("aa-Bb-cc-dd-ee-FF-aaaa-bbb.ipv6-literal.net", "aa:bb:cc:dd:ee:ff:aaaa:bbb", null, null);
		testHost("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.arpa", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", null, null);
		testHost("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", null, null);
		testHost("f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int:45", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", 45, null);
		testHost("F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45", "cccc:bbbb:aaaa:bbbb:cccc:dddd:ee:ffff", 45, null);
		testHost("f.F.f.f.F.e.e.0.0.d.D.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.C.ip6.int:45", "f.f.f.f.f.e.e.0.0.d.d.d.d.c.c.c.c.b.b.b.b.a.a.a.a.b.b.b.b.c.c.c.c.ip6.int", 45, null);//not a valid address
		testHost("255.22.2.111.in-addr.arpa", "111.2.22.255", null, null);
		testHost("255.22.2.111.in-addr.arpa:35", "111.2.22.255", 35, null);
		testHost("255.22.2.111.3.in-addr.arpa:35", "255.22.2.111.3.in-addr.arpa", 35, null);
		testHost("1.2.2.1:33", "1.2.2.1", 33, null);
		testHost("[::1]:33", "0:0:0:0:0:0:0:1", 33, null);
		testHost("::1:33", "0:0:0:0:0:0:1:33", null, null);
		testHost("::1%eth0", "0:0:0:0:0:0:0:1", null, "eth0");
		testHost("[::1%eth0]:33", "0:0:0:0:0:0:0:1", 33, "eth0");
		testHost("bla.bla:33", "bla.bla", null, 33, null);
		testHost("blA:33", "bla", 33, null);
		testHost("f:33", "f", 33, null);
		testHost("f::33", "f:0:0:0:0:0:0:33", null, null);
		testHost("::1", "0:0:0:0:0:0:0:1", null, null);
		testHost("[::1]", "0:0:0:0:0:0:0:1", null, null);
		testHost("/16", "/16", null, null);
		testHost("/32", "/32", null, null);
		testHost("/64", isNoAutoSubnets ? "ffff:ffff:ffff:ffff:0:0:0:0" : "ffff:ffff:ffff:ffff:*:*:*:*", "ffff:ffff:ffff:ffff:0:0:0:0/64", null, null);
		
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
	}
}
