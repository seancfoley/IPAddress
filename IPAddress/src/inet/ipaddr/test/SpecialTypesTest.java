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

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressStringParameters.RangeParameters;
import inet.ipaddr.test.IPAddressTest.HostKey;


public class SpecialTypesTest extends TestBase {
	
	private static final HostNameParameters HOST_OPTIONS = TestBase.HOST_OPTIONS.toBuilder().
			allowEmpty(true).setEmptyAsLoopback(true).getAddressOptionsBuilder().allowEmpty(false).setRangeParameters(RangeParameters.WILDCARD_ONLY).allowAll(true).getParentBuilder().toOptions();
	
	private static final IPAddressStringParameters ADDRESS_OPTIONS = HOST_OPTIONS.toAddressOptionsBuilder().allowEmpty(true).setEmptyAsLoopback(true).toParams();
	
	private static final HostNameParameters EMPTY_ADDRESS_OPTIONS = TestBase.HOST_OPTIONS.toBuilder().
			getAddressOptionsBuilder().allowEmpty(true).setEmptyAsLoopback(true).getParentBuilder().toOptions();
	
	private static final HostNameParameters EMPTY_ADDRESS_NO_LOOPBACK_OPTIONS = EMPTY_ADDRESS_OPTIONS.toBuilder().
			getAddressOptionsBuilder().setEmptyAsLoopback(false).getParentBuilder().toOptions();
	
	SpecialTypesTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	protected HostName createHost(String x, HostNameParameters options) {
		HostKey key = new HostKey(x, options);
		return createHost(key);
	}
	
	void testIPv4Strings(String addr, boolean explicit, String normalizedString, String normalizedWildcardString, String sqlString, String fullString, String reverseDNSString) {
		IPAddressString w = createAddress(addr, ADDRESS_OPTIONS);
		IPAddress ipAddr;
		if(explicit) {
			ipAddr = w.getAddress(IPVersion.IPV4);
		} else {
			ipAddr = w.getAddress();
		}
		testStrings(w, ipAddr, normalizedString, normalizedWildcardString, normalizedWildcardString, sqlString, fullString, normalizedString, normalizedString, normalizedWildcardString, normalizedString, normalizedWildcardString, reverseDNSString, normalizedString);
	}
	
	void testIPv6Strings(String addr,
			boolean explicit,
			String normalizedString,
			String normalizedWildcardString, 
			String canonicalWildcardString, 
			String sqlString, 
			String fullString,
			String compressedString,
			String canonicalString,
			String subnetString,
			String compressedWildcardString,
			String mixedStringNoCompressMixed,
			String mixedStringNoCompressHost,
			String mixedStringCompressCoveredHost,
			String mixedString,
			String reverseDNSString,
			String uncHostString) {
		IPAddressString w = createAddress(addr, ADDRESS_OPTIONS);
		IPAddress ipAddr;
		if(explicit) {
			ipAddr = w.getAddress(IPVersion.IPV6);
		} else {
			ipAddr = w.getAddress();
		}
		testIPv6Strings(w,
				ipAddr,
				normalizedString,
				normalizedWildcardString,
				canonicalWildcardString,
				sqlString, 
				fullString,
				compressedString,
				canonicalString,
				subnetString,
				compressedWildcardString,
				mixedStringNoCompressMixed,
				mixedStringNoCompressHost,
				mixedStringCompressCoveredHost,
				mixedString,
				reverseDNSString,
				uncHostString);
	}
		
	void testAllValues(IPVersion version, BigInteger count) {
		HostName hostAll = createHost("*", HOST_OPTIONS);
		IPAddressString addressAllStr = createAddress("*", ADDRESS_OPTIONS);
		IPAddress addressAll = addressAllStr.getAddress(version);
		String address2Str = version.isIPv4() ? "*.*.*.*" : "*:*:*:*:*:*:*:*";
		IPAddress address = createAddress(address2Str, ADDRESS_OPTIONS).getAddress();
		if(!addressAll.equals(address)) {
			addFailure(new Failure("no match " + address, addressAll));
		} else if(addressAll.compareTo(address) != 0) {
			addFailure(new Failure("no match " + address, addressAll));
		} else if(!addressAll.getCount().equals(count)) {
			addFailure(new Failure("no count match ", addressAll));
		} else {
			addressAll = hostAll.asAddress(version);
			if(!addressAll.equals(address)) {
				addFailure(new Failure("no match " + address, addressAll));
			} else if(addressAll.compareTo(address) != 0) {
				addFailure(new Failure("no match " + address, addressAll));
			} else if(!addressAll.getCount().equals(count)) {
				addFailure(new Failure("no count match ", addressAll));
			}
		}
		incrementTestCount();
	}
	
	void testAllValues() {
		HostName hostAll = createHost("*", HOST_OPTIONS);
		IPAddressString addressAll = createAddress("*", ADDRESS_OPTIONS);
		if(addressAll.getAddress() != null) {
			addFailure(new Failure("non null", addressAll));
		} else if(hostAll.asAddress() != null) {
			addFailure(new Failure("non null", hostAll));
		} else if(hostAll.resolve() != null) {
			addFailure(new Failure("non null", hostAll));
		}
		incrementTestCount();
	}
	
	void testEmptyLoopbackValues(IPVersion version) {
		HostName hostEmpty = createHost("", HOST_OPTIONS);
		IPAddressString addressEmptyStr = createAddress("", ADDRESS_OPTIONS);
		IPAddress addressEmptyValue = addressEmptyStr.getAddress(version);
		try {
			InetAddress addr = InetAddress.getByName("");
			IPAddress addressFromInet = IPAddress.from(addr.getAddress());
			boolean versionMatchesLoopback = addressFromInet.getIPVersion().equals(version);
		
			IPAddress address = IPAddress.getLoopback(version);
			String address2Str = version.isIPv4() ? "127.0.0.1" : "::1";
			IPAddress address2 = createAddress(address2Str).getAddress();
			if(addressEmptyValue == null || !addressEmptyValue.equals(address)) {
				addFailure(new Failure("no space match " + address, addressEmptyValue));
			} else if(!addressEmptyValue.equals(address2)) {
				addFailure(new Failure("no space match " + address2, addressEmptyValue));
			} else if(addressEmptyValue.compareTo(address) != 0) {
				addFailure(new Failure("no space match " + address, addressEmptyValue));
			} else if(addressEmptyValue.compareTo(address2) != 0) {
				addFailure(new Failure("no space match " + address2, addressEmptyValue));
			} else if(!addressEmptyValue.getCount().equals(BigInteger.ONE)) {
				addFailure(new Failure("no space match " + address2, addressEmptyValue));
			} else {
				IPAddressString addressEmpty = hostEmpty.asAddressString();
				if(addressEmpty != null) {
					addFailure(new Failure("host treated as address " + address, addressEmpty));
				} else {
					addressEmpty = createHost("", EMPTY_ADDRESS_OPTIONS).asAddressString();//emptyAddressOptions treats empty hosts as an address
					if((addressEmpty != null && addressEmpty.getAddress().equals(address)) ? !versionMatchesLoopback : versionMatchesLoopback) {
						addFailure(new Failure("no space match " + address, addressEmpty));
					} else if((addressEmpty != null && addressEmpty.getAddress().equals(address2)) ? !versionMatchesLoopback : versionMatchesLoopback) {
						addFailure(new Failure("no space match " + address2, addressEmpty));
					} else if(addressEmpty == null || addressEmpty.getAddress() == null) {
						addFailure(new Failure("no default loopback" + address, addressEmpty));
					} else {
						addressEmptyValue = createHost("", EMPTY_ADDRESS_OPTIONS).asAddress(version);//emptyAddressOptions treats empty hosts as an address
						if(addressEmptyValue == null || !addressEmptyValue.equals(address)) {
							addFailure(new Failure("no space match " + address, addressEmptyValue));
						} else if(!addressEmptyValue.equals(address2)) {
							addFailure(new Failure("no space match " + address2, addressEmptyValue));
						} else if(addressEmptyValue.compareTo(address) != 0) {
							addFailure(new Failure("no space match " + address, addressEmptyValue));
						} else if(addressEmptyValue.compareTo(address2) != 0) {
							addFailure(new Failure("no space match " + address2, addressEmptyValue));
						} else if(!addressEmptyValue.getCount().equals(BigInteger.ONE)) {
							addFailure(new Failure("no space match " + address2, addressEmptyValue));
						}
					}
				}
			}
		} catch(UnknownHostException e) {
			addFailure(new Failure("unexpected unknown host", addressEmptyValue));
		}	
		incrementTestCount();
	}
	
	void testEmptyValues() {
		HostName hostEmpty = createHost("", HOST_OPTIONS);
		IPAddressString addressEmpty = createAddress("", ADDRESS_OPTIONS);
		try {
			InetAddress addr = InetAddress.getByName("");
			InetAddress addr2 = InetAddress.getByName(null);
			IPAddress address = IPAddress.from(addr.getAddress());
			IPAddress address2 = IPAddress.from(addr2.getAddress());
			
			if(!addressEmpty.getAddress().equals(address)) {
				addFailure(new Failure("no match " + addr, addressEmpty));
			} else if(!addressEmpty.getAddress().equals(address2)) {
				addFailure(new Failure("no match " + addr2, addressEmpty));
			} else if(addressEmpty.getAddress().compareTo(address) != 0) {
				addFailure(new Failure("no match " + addr, addressEmpty));
			} else if(addressEmpty.getAddress().compareTo(address2) != 0) {
				addFailure(new Failure("no match " + addr2, addressEmpty));
			} else if(!addressEmpty.getAddress().getCount().equals(BigInteger.ONE)) {
				addFailure(new Failure("no count match " + addr2, addressEmpty));
			} else {
				addressEmpty = hostEmpty.asAddressString();//note that hostEmpty allows empty strings and they resolve to loopbacks, but they are not treated as addresses
				if(addressEmpty != null) {
					addFailure(new Failure("host treated as address " + addr, addressEmpty));
				} else {
					addressEmpty = createHost("", EMPTY_ADDRESS_OPTIONS).asAddressString();
					if(addressEmpty == null || !addressEmpty.getAddress().equals(address)) {
						addFailure(new Failure("no match " + addr, addressEmpty));
					} else if(!addressEmpty.getAddress().equals(address2)) {
						addFailure(new Failure("no match " + addr2, addressEmpty));
					} else if(addressEmpty.getAddress().compareTo(address) != 0) {
						addFailure(new Failure("no match " + addr, addressEmpty));
					} else if(addressEmpty.getAddress().compareTo(address2) != 0) {
						addFailure(new Failure("no match " + addr2, addressEmpty));
					} else if(!addressEmpty.getAddress().getCount().equals(BigInteger.ONE)) {
						addFailure(new Failure("no count match " + addr2, addressEmpty));
					} else {
						IPAddress addressEmptyValue = hostEmpty.resolve();
						if(!addressEmptyValue.equals(address)) {
							addFailure(new Failure("no match " + addr, addressEmpty));
						} else if(!addressEmptyValue.equals(address2)) {
							addFailure(new Failure("no match " + addr2, addressEmpty));
						} else if(addressEmptyValue.compareTo(address) != 0) {
							addFailure(new Failure("no match " + addr, addressEmpty));
						} else if(addressEmptyValue.compareTo(address2) != 0) {
							addFailure(new Failure("no match " + addr2, addressEmpty));
						} else if(!addressEmptyValue.getCount().equals(BigInteger.ONE)) {
							addFailure(new Failure("no count match " + addr2, addressEmpty));
						}
					}
				}
			}
		} catch(UnknownHostException e) {
			addFailure(new Failure("unexpected unknown host", addressEmpty));
		}	
		incrementTestCount();
	}
	
	void testInvalidValues() {
		// invalid mask
		IPAddressString addressAll = createAddress("*/f0ff::", ADDRESS_OPTIONS);
		try {
			addressAll.getAddress();
			addFailure(new Failure("unexpectedly valid", addressAll));
		} catch(IPAddressTypeException e) {
			// valid mask
			addressAll = createAddress("*/fff0::", ADDRESS_OPTIONS);
			try {
				if(addressAll.getAddress() == null) {
					addFailure(new Failure("unexpectedly invalid", addressAll));
				} else {
					//ambiguous
					addressAll = createAddress("*", ADDRESS_OPTIONS);
					if(addressAll.getAddress() != null) {
						addFailure(new Failure("unexpectedly invalid", addressAll));
					} else {
						//ambiguous
						addressAll = createAddress("*/16", ADDRESS_OPTIONS);
						if(addressAll.getAddress() != null) {
							addFailure(new Failure("unexpectedly invalid", addressAll));
						}
						//unambiguous similar addresses tested with testStrings()
					}
				}
			} catch(IPAddressTypeException e2) {
				addFailure(new Failure("unexpectedly valid", addressAll));
			}
		}
	}
	
	void testValidity() {
		HostName hostEmpty = createHost("");
		HostName hostAll = createHost("*");
		HostName hostAllIPv4 = createHost("*.*.*.*");
		HostName hostAllIPv6 = createHost("*:*:*:*:*:*:*:*");
		IPAddressString addressEmpty = createAddress("");
		IPAddressString addressAll = createAddress("*");
		if(hostEmpty.isValid()) {
			addFailure(new Failure("unexpectedly valid", hostEmpty));
		} else if(hostAll.isValid()) {
			addFailure(new Failure("unexpectedly valid", hostAll));
		} else if(hostAllIPv4.isValid()) {
			addFailure(new Failure("unexpectedly valid", hostAllIPv4));
		} else if(hostAllIPv6.isValid()) {
			addFailure(new Failure("unexpectedly valid", hostAllIPv6));
		} else if(addressEmpty.isValid()) {
			addFailure(new Failure("unexpectedly valid", addressEmpty));
		} else if(addressAll.isValid()) {
			addFailure(new Failure("unexpectedly valid", addressAll));
		} else if(hostAll.resolve() != null) {
			addFailure(new Failure("unexpectedly valid", hostAll));
		} else if(hostEmpty.resolve() != null) {
			addFailure(new Failure("unexpectedly valid", hostEmpty));
		} else {
			hostEmpty = createHost("", HOST_OPTIONS);
			hostAll = createHost("*", HOST_OPTIONS);
			hostAllIPv4 = createHost("*.*.*.*", HOST_OPTIONS);
			hostAllIPv6 = createHost("*:*:*:*:*:*:*:*", HOST_OPTIONS);
			addressEmpty = createAddress("", ADDRESS_OPTIONS);
			addressAll = createAddress("*", ADDRESS_OPTIONS);
			if(!hostEmpty.isValid()) {
				addFailure(new Failure("unexpectedly invalid", hostEmpty));
			} else if(!hostAll.isValid()) {
				addFailure(new Failure("unexpectedly invalid", hostAll));
			} else if(!hostAllIPv4.isValid()) {
				addFailure(new Failure("unexpectedly invalid", hostAllIPv4));
			} else if(!hostAllIPv6.isValid()) {
				addFailure(new Failure("unexpectedly invalid", hostAllIPv6));
			} else if(!addressEmpty.isValid()) {
				addFailure(new Failure("unexpectedly invalid", addressEmpty));
			} else if(!addressAll.isValid()) {
				addFailure(new Failure("unexpectedly invalid", addressAll));
			} else if(hostEmpty.resolve() == null) {//loopback
				addFailure(new Failure("unexpectedly invalid", hostEmpty));
			} else if(hostAll.resolve() != null) {
				addFailure(new Failure("unexpectedly invalid", hostAll));
			} else {
				//With empty strings, if we wish to allow them, there are two options, 
				//we can either treat them as host names and we defer to the validation options for host names, as done above,
				//or we treat than as addresses and use the address options to control behaviour, as we do here.
				
				hostEmpty = createHost("", EMPTY_ADDRESS_OPTIONS);
				if(!hostEmpty.isValid()) {
					addFailure(new Failure("unexpectedly invalid", hostEmpty));
				} else if(hostEmpty.resolve() == null) {//loopback
					addFailure(new Failure("unexpectedly invalid", hostEmpty));
				} else {
					addressAll = createAddress("*.*/64", ADDRESS_OPTIONS);// invalid prefix
					if(addressAll.isValid()) {
						addFailure(new Failure("unexpectedly valid", addressAll));
					}
				}
			}
		}
		incrementTestCount();
	}
	
	void testEmptyIsSelf() {
		HostName w = createHost("", HOST_OPTIONS); 
		if(w.isSelf()) {
			addFailure(new Failure("failed: isSelf is " + w.isSelf(), w));
		}
		HostName w2 = createHost("", EMPTY_ADDRESS_OPTIONS);
		if(!w2.isSelf()) {
			addFailure(new Failure("failed: isSelf is " + w2.isSelf(), w2));
		}
		incrementTestCount();
	}
	
	void testSelf(String host, boolean isSelf) {
		HostName w = createHost(host, HOST_OPTIONS);
		if(isSelf != w.isSelf()) {
			addFailure(new Failure("failed: isSelf is " + isSelf, w));
		}
		incrementTestCount();
	}
	
	void testEmptyLoopback() {
		HostName w = createHost("", HOST_OPTIONS); 
		if(w.isLoopback()) {
			addFailure(new Failure("failed: isSelf is " + w.isSelf(), w));
		}
		IPAddress addressEmptyValue = w.resolve();
		if(!addressEmptyValue.isLoopback()) {
			addFailure(new Failure("failed: isSelf is " + addressEmptyValue.isLoopback(), w));
		}
		HostName w2 = createHost("", EMPTY_ADDRESS_OPTIONS);
		if(!w2.isLoopback()) {
			addFailure(new Failure("failed: isSelf is " + w2.isSelf(), w2));
		}
		incrementTestCount();
	}
	
	void testLoopback(String host, boolean isSelf) {
		HostName w = createHost(host, HOST_OPTIONS);
		if(isSelf != w.isLoopback()) {
			addFailure(new Failure("failed: isSelf is " + isSelf, w));
		}
		IPAddressString w2 = createAddress(host, ADDRESS_OPTIONS);
		if(isSelf != w2.isLoopback()) {
			addFailure(new Failure("failed: isSelf is " + isSelf, w));
		}
		incrementTestCount();
	}
	
	BigInteger getCount(int segmentMax, int segmentCount) {
		BigInteger segCount = BigInteger.valueOf(segmentMax + 1);
		return segCount.pow(segmentCount);
	}
	
	@Override
	void runTest()
	{
		
		testIPv4Strings("*", true, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa");
		testIPv4Strings("*.*", false, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa");
		testIPv4Strings("*/16", true, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa");
		testIPv4Strings("*/255.255.0.0", false, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa");
		testIPv4Strings("*/255.255.0.0", true, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa");
		testIPv4Strings("*.*/16", false, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa");
		testIPv4Strings("*.*/16", true, "*.*.0.0/16", "*.*.*.*", "%.%.%.%", "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa");
		testIPv4Strings("", false, "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.000.000.001", "1.0.0.127.in-addr.arpa");
		testIPv4Strings("", true, "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.000.000.001", "1.0.0.127.in-addr.arpa");
		
		testIPv6Strings("*", true, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net");
		testIPv6Strings("*:*", false, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net");
		testIPv6Strings("*:*", true, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net");
		testIPv6Strings("*/16", true, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16");
		testIPv6Strings("*:*/16", false, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16");
		testIPv6Strings("*:*/16", true, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16");
		testIPv6Strings("*/ffff::", false, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16");
		testIPv6Strings("*/ffff::", true, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16");
		testIPv6Strings("*/64", false, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64");
		testIPv6Strings("*/64", true, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64");
		testIPv6Strings("*:*/64", false, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64");
		testIPv6Strings("*:*/64", true, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64");
		testIPv6Strings("", true, "0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1", "::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "::1", "::1", "::1", "::1", "::0.0.0.1", "::0.0.0.1", "::0.0.0.1", "::0.0.0.1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "0-0-0-0-0-0-0-1.ipv6-literal.net");

		testInvalidValues();
				
		testValidity();
		
		testEmptyValues();
		
		testEmptyLoopbackValues(IPVersion.IPV4);
		testEmptyLoopbackValues(IPVersion.IPV6);
		
		testAllValues();
		testAllValues(IPVersion.IPV4, getCount(255, 4));
		testAllValues(IPVersion.IPV6, getCount(0xffff, 8));
		
		HostName addressEmpty = createHost("", EMPTY_ADDRESS_OPTIONS);
		hostLabelsTest(addressEmpty, new String[] {"127", "0", "0", "1"});
		HostName addressEmpty2 = createHost("", EMPTY_ADDRESS_NO_LOOPBACK_OPTIONS);
		hostLabelsTest(addressEmpty2, new String[0]);
		HostName hostEmpty = createHost("", HOST_OPTIONS);
		hostLabelsTest(hostEmpty, new String[0]);
		
		
		testEmptyIsSelf();
		testSelf("localhost", true);
		testSelf("127.0.0.1", true);
		testSelf("::1", true);
		testSelf("[::1]", true);
		testSelf("*", false);
		testSelf("sean.com", false);
		testSelf("1.2.3.4", false);
		testSelf("::", false);
		testSelf("[::]", false);
		testSelf("[1:2:3:4:1:2:3:4]", false);
		testSelf("1:2:3:4:1:2:3:4", false);

		testEmptyLoopback();
		testLoopback("127.0.0.1", true);
		testLoopback("::1", true);
		testLoopback("*", false);
		testLoopback("1.2.3.4", false);
		testLoopback("::", false);
		testLoopback("1:2:3:4:1:2:3:4", false);
	}
}