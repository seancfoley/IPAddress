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

import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddressStringParameters.IPAddressStringFormatParameters;
import inet.ipaddr.format.large.IPAddressLargeDivision;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.mac.MACAddress;


public class SpecialTypesTest extends TestBase {
	
	private static final HostNameParameters HOST_OPTIONS = TestBase.HOST_OPTIONS.toBuilder().
			allowEmpty(true).setEmptyAsLoopback(true).getAddressOptionsBuilder().allowEmpty(false).setRangeOptions(RangeParameters.WILDCARD_ONLY).allowAll(true).getParentBuilder().toParams();
	
	private static final IPAddressStringParameters ADDRESS_OPTIONS = HOST_OPTIONS.toAddressOptionsBuilder().allowEmpty(true).setEmptyAsLoopback(true).toParams();
	
	private static final MACAddressStringParameters MAC_OPTIONS = TestBase.MAC_ADDRESS_OPTIONS.toBuilder().allowEmpty(true).setRangeOptions(RangeParameters.WILDCARD_ONLY).allowAll(true).toParams();
	
	private static final HostNameParameters EMPTY_ADDRESS_OPTIONS = TestBase.HOST_OPTIONS.toBuilder().
			getAddressOptionsBuilder().allowEmpty(true).setEmptyAsLoopback(true).getParentBuilder().toParams();
	
	private static final HostNameParameters EMPTY_ADDRESS_NO_LOOPBACK_OPTIONS = EMPTY_ADDRESS_OPTIONS.toBuilder().
			getAddressOptionsBuilder().setEmptyAsLoopback(false).getParentBuilder().toParams();
	
	SpecialTypesTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	protected HostName createHost(String x, HostNameParameters options) {
		HostKey key = new HostKey(x, options);
		return createHost(key);
	}
	
	void testIPv4Strings(String addr, boolean explicit, String normalizedString, String normalizedWildcardString, String sqlString, String fullString, String reverseDNSString, String singleHex, String singleOctal) {
		IPAddressString w = createAddress(addr, ADDRESS_OPTIONS);
		IPAddress ipAddr;
		if(explicit) {
			ipAddr = w.getAddress(IPVersion.IPV4);
		} else {
			ipAddr = w.getAddress();
		}
		testStrings(w, ipAddr, normalizedString, normalizedWildcardString, normalizedWildcardString, sqlString, fullString, 
				normalizedString, normalizedString, normalizedWildcardString, normalizedString, normalizedWildcardString, reverseDNSString, normalizedString,
				singleHex, singleOctal);
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
			String uncHostString,
			String base85String,
			String singleHex,
			String singleOctal) {
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
				uncHostString,
				base85String,
				singleHex,
				singleOctal);
	}
		
	void testAllMACValues(BigInteger count1, BigInteger count2) {
		MACAddress macAll = createMACAddress("*", MAC_OPTIONS).getAddress();
		MACAddress macAll2 = createMACAddress("*:*:*:*:*:*:*", MAC_OPTIONS).getAddress();
		String address1Str = "*:*:*:*:*:*";
		String address2Str = "*:*:*:*:*:*:*:*";
		MACAddress mac1 = createMACAddress(address1Str, MAC_OPTIONS).getAddress();
		MACAddress mac2 = createMACAddress(address2Str, MAC_OPTIONS).getAddress();
		if(!macAll.equals(mac1)) {
			addFailure(new Failure("no match " + macAll, mac1));
		} else if(!macAll2.equals(mac2)) {
			addFailure(new Failure("no match " + macAll2, mac2));
		} else if(macAll.compareTo(mac1) != 0) {
			addFailure(new Failure("no match " + macAll, mac1));
		} else if(macAll2.compareTo(mac2) != 0) {
			addFailure(new Failure("no match " + macAll2, mac2));
		} else if(!macAll.getCount().equals(count1)) {
			addFailure(new Failure("no count match ", macAll));
		} else if(!macAll2.getCount().equals(count2)) {
			addFailure(new Failure("no count match ", macAll2));
		}
		incrementTestCount();
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
		MACAddressString macAll = createMACAddress("*", MAC_OPTIONS);
		if(addressAll.getAddress() != null) {
			addFailure(new Failure("non null", addressAll));
		} else if(hostAll.asAddress() != null) {
			addFailure(new Failure("non null", hostAll));
		} else if(hostAll.getAddress() != null) {
			addFailure(new Failure("non null", hostAll));
		} else if(macAll.getAddress() == null) {
			addFailure(new Failure("null", macAll));
		}
		incrementTestCount();
	}
	
	void testEmptyValues() {
		HostName hostEmpty = createHost("", HOST_OPTIONS);
		IPAddressString addressEmpty = createAddress("", ADDRESS_OPTIONS);
		try {
			InetAddress addr = InetAddress.getByName("");
			InetAddress addr2 = InetAddress.getByName(null);
			
			IPAddressStringFormatParameters params = addr instanceof Inet6Address ? ADDRESS_OPTIONS.getIPv6Parameters() : ADDRESS_OPTIONS.getIPv4Parameters();
			IPAddressNetwork<?, ?, ?, ?, ?> network = params.getNetwork();
			IPAddress address = network.getAddressCreator().createAddress(addr.getAddress());
			
			IPAddressStringFormatParameters params2 = addr2 instanceof Inet6Address ? ADDRESS_OPTIONS.getIPv6Parameters() : ADDRESS_OPTIONS.getIPv4Parameters();
			IPAddressNetwork<?, ?, ?, ?, ?> network2 = params2.getNetwork();
			IPAddress address2 = network2.getAddressCreator().createAddress(addr2.getAddress());
			
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
						IPAddress addressEmptyValue = hostEmpty.getAddress();
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
		} catch(IncompatibleAddressException e) {
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
			} catch(IncompatibleAddressException e2) {
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
		MACAddressString macEmpty = createMACAddress("");
		MACAddressString macAll = createMACAddress("*");
		
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
		} else if(macEmpty.isValid()) {
			addFailure(new Failure("unexpectedly valid", macEmpty));
		} else if(macAll.isValid()) {
			addFailure(new Failure("unexpectedly valid", macAll));
		} else if(hostAll.getAddress() != null) {
			addFailure(new Failure("unexpectedly valid", hostAll));
		} else if(hostEmpty.getAddress() != null) {
			addFailure(new Failure("unexpectedly valid", hostEmpty));
		} else {
			hostEmpty = createHost("", HOST_OPTIONS);
			hostAll = createHost("*", HOST_OPTIONS);
			hostAllIPv4 = createHost("*.*.*.*", HOST_OPTIONS);
			hostAllIPv6 = createHost("*:*:*:*:*:*:*:*", HOST_OPTIONS);
			addressEmpty = createAddress("", ADDRESS_OPTIONS);
			addressAll = createAddress("*", ADDRESS_OPTIONS);
			macEmpty = createMACAddress("", MAC_OPTIONS);
			macAll = createMACAddress("*", MAC_OPTIONS);
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
			} else if(!macEmpty.isValid()) {
				addFailure(new Failure("unexpectedly invalid", macEmpty));
			} else if(!macAll.isValid()) {
				addFailure(new Failure("unexpectedly invalid", macAll));
			} else if(hostEmpty.getAddress() == null) {//loopback
				addFailure(new Failure("unexpectedly invalid", hostEmpty));
			} else if(hostAll.getAddress() != null) {
				addFailure(new Failure("unexpectedly invalid", hostAll));
			} else {
				//With empty strings, if we wish to allow them, there are two options, 
				//we can either treat them as host names and we defer to the validation options for host names, as done above,
				//or we treat than as addresses and use the address options to control behaviour, as we do here.
				hostEmpty = createHost("", EMPTY_ADDRESS_OPTIONS);
				if(!hostEmpty.isValid()) {
					addFailure(new Failure("unexpectedly invalid", hostEmpty));
				} else if(hostEmpty.getAddress() == null) {//loopback
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
		IPAddress addressEmptyValue = w.getAddress();
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
		String allSingleHex = "0x00000000-0xffffffff";
		String allSingleOctal = "000000000000-037777777777";

		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		
		testIPv4Strings("*", true, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("***.***.***.***", true, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("*.*", false, "*.*.*.*", "*.*.*.*", "%.%.%.%", "000-255.000-255.000-255.000-255", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("*/16", true, isNoAutoSubnets ? "*.*.*.*/16" : "*.*.0.0/16", "*.*.*.*", "%.%.%.%", isNoAutoSubnets ? "000-255.000-255.000-255.000-255/16" : "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("*/255.255.0.0", false, isNoAutoSubnets ? "*.*.*.*/16" : "*.*.0.0/16", "*.*.*.*", "%.%.%.%", isNoAutoSubnets ? "000-255.000-255.000-255.000-255/16" : "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("*/255.255.0.0", true, isNoAutoSubnets ? "*.*.*.*/16" : "*.*.0.0/16", "*.*.*.*", "%.%.%.%", isNoAutoSubnets ? "000-255.000-255.000-255.000-255/16" : "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("*.*/16", false, isNoAutoSubnets ? "*.*.*.*/16" : "*.*.0.0/16", "*.*.*.*", "%.%.%.%", isNoAutoSubnets ? "000-255.000-255.000-255.000-255/16" : "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("*.*/16", true, isNoAutoSubnets ? "*.*.*.*/16" : "*.*.0.0/16", "*.*.*.*", "%.%.%.%", isNoAutoSubnets ? "000-255.000-255.000-255.000-255/16" : "000-255.000-255.000.000/16", "*.*.*.*.in-addr.arpa", allSingleHex, allSingleOctal);
		testIPv4Strings("", false, "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.000.000.001", "1.0.0.127.in-addr.arpa", "0x7f000001", "017700000001");
		testIPv4Strings("", true, "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.000.000.001", "1.0.0.127.in-addr.arpa", "0x7f000001", "017700000001");
		
		String base85All = "00000000000000000000" + IPAddressLargeDivision.EXTENDED_DIGITS_RANGE_SEPARATOR + "=r54lj&NUUO~Hi%c2ym0";
		String base85AllPrefixed = base85All + "/16";
		String base85AllPrefixed64 = base85All + "/64";
		String base8516 = "00000000000000000000" + IPAddressLargeDivision.EXTENDED_DIGITS_RANGE_SEPARATOR + "=q{+M|w0(OeO5^EGP660" + "/16";
		String base8564 = "00000000000000000000" + IPAddressLargeDivision.EXTENDED_DIGITS_RANGE_SEPARATOR + "=r54lj&NUTUTif>jH#O0" + "/64";
		String allSingleHexIPv6 = "0x00000000000000000000000000000000-0xffffffffffffffffffffffffffffffff";
		String allSingleOctalIPv6 = "00000000000000000000000000000000000000000000-03777777777777777777777777777777777777777777";

		testIPv6Strings("*", true, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net", base85All, allSingleHexIPv6, allSingleOctalIPv6);
		testIPv6Strings("*:*", false, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net", base85All, allSingleHexIPv6, allSingleOctalIPv6);
		testIPv6Strings("*:*", true, "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*:*:*:*:*:*:*.*.*.*", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-*-*-*-*.ipv6-literal.net", base85All, allSingleHexIPv6, allSingleOctalIPv6);
		if(isNoAutoSubnets) {
			testIPv6Strings("*/16", true, 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/16", 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/16", 
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/16", 
					base85AllPrefixed, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/16", false, 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/16", 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/16", 
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/16", 
					base85AllPrefixed, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/16", true, 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/16", 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/16", 
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/16", 
					base85AllPrefixed, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/64", false, 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/64", 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/64", 
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/64", 
					base85AllPrefixed64, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/64", true, 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/64", 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/64", 
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/64", 
					base85AllPrefixed64, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/64", false, 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/64", 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/64", 
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/64", 
					base85AllPrefixed64, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/64", true, 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/64", 
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64",
					"*:*:*:*:*:*:*:*/64", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/64", 
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*:*:*:*:*:*:*.*.*.*/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/64", 
					base85AllPrefixed64, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/ffff::", false, "*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/16", 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/16", 
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/16", 
					base85AllPrefixed, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/ffff::", true, "*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*:*", 
					"%:%:%:%:%:%:%:%", 
					"0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff/16", 
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16",
					"*:*:*:*:*:*:*:*/16", 
					"*:*:*:*:*:*:*:*", 
					"*:*:*:*:*:*:*.*.*.*/16", 
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*:*:*:*:*:*:*.*.*.*/16",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
					"*-*-*-*-*-*-*-*.ipv6-literal.net/16", 
					base85AllPrefixed, allSingleHexIPv6, allSingleOctalIPv6);
		} else {
			testIPv6Strings("*/16", true, 
				"*:0:0:0:0:0:0:0/16",
				"*:*:*:*:*:*:*:*", 
				"*:*:*:*:*:*:*:*", 
				"%:%:%:%:%:%:%:%", 
				"0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", 
				"*::/16",
				"*::/16",
				"*::/16", 
				"*:*:*:*:*:*:*:*", 
				"*::0.0.0.0/16",
				"*::0.0.0.0/16",
				"*::/16",
				"*::/16", 
				"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", 
				"*-0-0-0-0-0-0-0.ipv6-literal.net/16", 
				base8516, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/16", false, 
					"*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/16", true, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/64", false, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/64", true, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/64", false, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*:*/64", true, "*:*:*:*:0:0:0:0/64", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000:0000:0000:0000/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*::/64", "*:*:*:*:*:*:*:*", "*:*:*:*::0.0.0.0/64", "*:*:*:*::0.0.0.0/64", "*:*:*:*::/64", "*:*:*:*::/64", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-*-*-*-0-0-0-0.ipv6-literal.net/64", base8564, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/ffff::", false, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6);
			testIPv6Strings("*/ffff::", true, "*:0:0:0:0:0:0:0/16", "*:*:*:*:*:*:*:*", "*:*:*:*:*:*:*:*", "%:%:%:%:%:%:%:%", "0000-ffff:0000:0000:0000:0000:0000:0000:0000/16", "*::/16", "*::/16", "*::/16", "*:*:*:*:*:*:*:*", "*::0.0.0.0/16", "*::0.0.0.0/16", "*::/16", "*::/16", "*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.ip6.arpa", "*-0-0-0-0-0-0-0.ipv6-literal.net/16", base8516, allSingleHexIPv6, allSingleOctalIPv6);
		}
		
		testIPv6Strings("", true, "0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1", "::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "::1", "::1", "::1", "::1", "::0.0.0.1", "::0.0.0.1", "::0.0.0.1", "::0.0.0.1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "0-0-0-0-0-0-0-1.ipv6-literal.net", "00000000000000000001", "0x00000000000000000000000000000001", "00000000000000000000000000000000000000000001");

		testInvalidValues();
				
		testValidity();
		
		testEmptyValues();
		
		testAllValues();
		testAllValues(IPVersion.IPV4, getCount(255, 4));
		testAllValues(IPVersion.IPV6, getCount(0xffff, 8));
		testAllMACValues(getCount(0xff, 6), getCount(0xff, 8));
		
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
