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
import inet.ipaddr.IPAddressTypeException;
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
		HostName origAddress = createHost(original);
		testResolved(origAddress, original, expectedResolved);
	}
	
	void testResolved(HostName original, String originalStr, String expectedResolved) {
		try {
			IPAddress resolvedAddress = original.resolve();
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
		} catch(IPAddressTypeException e) {
			addFailure(new Failure(e.toString(), original));
		} catch(RuntimeException e) {
			addFailure(new Failure(e.toString(), original));
		}
		incrementTestCount();
	}
	
	void testNormalized(boolean expectMatch, String original, String expected) {
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
			addFailure(new Failure("normalization was " + canonical, w));
		}
		incrementTestCount();
	}
	
	void hostTest_inet_aton(boolean pass, String x) {
		HostName addr = createHost_inet_aton(x);
		hostTestDouble(pass, addr);
	}
	
	void hostTest(boolean pass, String x) {
		HostName addr = createHost(x);
		hostTestDouble(pass, addr);
	}
	
	void hostTestDouble(boolean pass, HostName addr) {
		hostTest(pass, addr);
		//do it a second time to test the caching
		hostTest(pass, addr);
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
					String bracketed;
					if(h1.isAddress() && h1.asAddress().isPrefixed()) {
						bracketed = '[' + h1.asAddress().getLower().toNormalizedString() + "]/" + h1.asAddress().getNetworkPrefixLength();
					} else if(h1.isAddress()) {
						bracketed = '[' + h1.asAddress().toNormalizedWildcardString() + "]";
					} else {
						String h1String  = h1.toNormalizedString();
						bracketed = h1.isAddress() ? ('[' + h1String + ']') : h1String;
					}
					String h1Bracketed = h1.toURLString();
					if(!h1Bracketed.equals(bracketed)) {
						addFailure(new Failure("failed: bracketed is " + bracketed, h1));
					} else {
						if(h2.isAddress() && h2.asAddress().isPrefixed()) {
							bracketed = '[' + h2.asAddress().getLower().toNormalizedString() + "]/" + h2.asAddress().getNetworkPrefixLength();
						} else if(h2.isAddress()) {
							bracketed = '[' + h2.asAddress().toNormalizedWildcardString() + "]";
						} else {
							String h2String  = h2.toNormalizedString();
							bracketed = (h2.isAddress()) ? ('[' + h2String + ']') : h2String;
						}
						String h2Bracketed = h2.toURLString();
						if(!h2Bracketed.equals(bracketed.toLowerCase())) {
							addFailure(new Failure("failed: bracketed is " + bracketed, h2));
						}
					}
				}
			}
		}
		incrementTestCount();
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
		testMatches(true, "1.2.3.4/255.0.0.0", "1.0.0.0/255.0.0.0");
		
		testMatches(true, "[IPv6:1:2:3:4:5:6:7:8%y]", "1:2:3:4:5:6:7:8%y");
		testMatches(true, "[IPv6:1:2:3:4:5:6:7:8]", "1:2:3:4:5:6:7:8");
		testMatches(true, "[IPv6:1:2:3:4:5:6::]/32", "1:2:3:4:5:6::/32");
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
		
		testNormalized(true, "[A::b:c:d:1.2.03.4]", "a:0:0:b:c:d:102:304");//square brackets can enclose ipv6 in host names but not addresses
		testNormalized(true, "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "2001:0:1234:0:0:c1c0:abcd:876");//square brackets can enclose ipv6 in host names but not addresses
		testNormalized(true, "1.2.3.04", "1.2.3.4");
		
		testCanonical("[A:0::c:d:1.2.03.4]", "a::c:d:102:304");//square brackets can enclose ipv6 in host names but not addresses
		testCanonical("[2001:0000:1234:0000:0000:C1C0:ABCD:0876]", "2001:0:1234::c1c0:abcd:876");//square brackets can enclose ipv6 in host names but not addresses
		testCanonical("1.2.3.04", "1.2.3.4");
		
		testNormalized(true, "WWW.ABC.COM", "www.abc.com");
		testNormalized(true, "WWW.AB-C.COM", "www.ab-c.com");

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
		hostLabelsTest("", new String[0]);
		hostLabelsTest(" ", new String[0]);
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
	}
}