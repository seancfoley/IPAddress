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

import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.TreeSet;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.MACAddressStringParameters.AddressSize;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSection.MACStringOptions;
import inet.ipaddr.mac.MACAddressSegment;


public class MACAddressTest extends TestBase {

	MACAddressTest(AddressCreator creator) {
		super(creator);
	}

	static class MACAddressStringKey extends LookupKey<MACAddressStringParameters> {
	
		private static final long serialVersionUID = 4L;
		private static final Comparator<MACAddressStringParameters> comparator = new LookupKeyComparator<MACAddressStringParameters>();
		
		
		MACAddressStringKey(String x) {
			this(x, null);
		}
		
		MACAddressStringKey(String x, MACAddressStringParameters opts) {
			super(x, opts);
		}
		
		@Override
		int compareOptions(MACAddressStringParameters otherOptions){
			return Objects.compare(options, otherOptions, comparator);
		}
	}
	
	static class MACAddressLongKey implements Comparable<MACAddressLongKey>, Serializable {

		private static final long serialVersionUID = 4L;
		
		long val;
		boolean extended;
		
		MACAddressLongKey(long val, boolean extended) {
			this.val = val;
			this.extended = extended;
		}
		
		@Override
		public int compareTo(MACAddressLongKey o) {
			int res = Boolean.compare(extended, o.extended);
			if(res == 0) {
				res = Long.compare(val, o.val);
			}
			return res;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof MACAddressLongKey) {
				return val == ((MACAddressLongKey) o).val && extended == ((MACAddressLongKey) o).extended;
			}
			return false;
		}
		
		@Override
		public int hashCode() {
			return Long.hashCode(val);
		}
	}
	
	static class MACAddressKey implements Comparable<MACAddressKey>, Serializable {
		
		private static final long serialVersionUID = 4L;
		
		byte bytes[];
		
		MACAddressKey(byte bytes[]) {
			this.bytes = bytes;
		}
		
		@Override
		public int compareTo(MACAddressKey o) {
			int comparison = bytes.length - bytes.length;
			if(comparison == 0) {
				for(int i=0; i<bytes.length; i++) {
					comparison = bytes[i] = o.bytes[i];
					if(comparison != 0) {
						break;
					}
				}
			}
			return comparison;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof MACAddressKey) {
				return Arrays.equals(bytes, ((MACAddressKey) o).bytes);
			}
			return false;
		}
		
		@Override
		public int hashCode() {
			return Arrays.hashCode(bytes);
		}
	}
	
	void testNormalized(String original, String expected) {
		MACAddressString w = createMACAddress(original);
		MACAddress val = w.getAddress();
		if(val == null) {
			addFailure(new Failure("normalization was null", w));
		} else {
			String normalized = val.toNormalizedString();
			if(!expected.equals(normalized)) {
				addFailure(new Failure("mac normalization was " + normalized, w));
			}
		}
		incrementTestCount();
	}

	void testCanonical(String original, String expected) {
		MACAddressString w = createMACAddress(original);
		MACAddress val = w.getAddress();
		if(val == null) {
			addFailure(new Failure("normalization was null", w));
		} else {
			String normalized = val.toCanonicalString();
			if(!expected.equals(normalized)) {
				addFailure(new Failure("canonical was " + normalized, w));
			}
		}
		incrementTestCount();
	}
	
	void testRadices(String original, String expected, int radix) {
		MACAddressString w = createMACAddress(original);
		MACAddress val = w.getAddress();
		StringOptions options = new MACStringOptions.Builder().setRadix(radix).toOptions();
		String normalized = val.toNormalizedString(options);
		if(!normalized.equals(expected)) {
			addFailure(new Failure("string was " + normalized + " expected was " + expected, w));
		}
		incrementTestCount();
	}
	
	void testOUIPrefixed(String original, String expected, int expectedPref) {
		MACAddressString w = createMACAddress(original);
		MACAddress val = w.getAddress();
		MACAddressString w2 = createMACAddress(expected);
		MACAddress expectedAddress = w2.getAddress();
		MACAddress prefixed = val.toOUIPrefixBlock();
		if(!prefixed.equals(expectedAddress)) {
			addFailure(new Failure("oui prefixed was " + prefixed + " expected was " + expected, w));
		}
		if(expectedPref != prefixed.getPrefixLength().intValue()) {
			addFailure(new Failure("oui prefix was " + prefixed.getPrefixLength() + " expected was " + expectedPref, w));
		}
		incrementTestCount();
	}

	boolean mactest(boolean pass, MACAddressString addr, boolean isZero) {
		boolean failed = false;
		
		//notBoth means we validate as IPv4 or as IPv6, we don't validate as either one
		try {
			if(isNotExpected(pass, addr)) {
				failed = true;
				addFailure(new Failure(pass, addr));
			} else {
				boolean zeroPass = pass && !isZero;
				if(isNotExpectedNonZero(zeroPass, addr)) {
					failed = true;
					addFailure(new Failure(zeroPass, addr));
				} else {
					//test the bytes
					if(pass && addr.toString().length() > 0 && addr.getAddress() != null) {
						failed = !testBytes(addr.getAddress());
					}
				}
			} 
		} catch(IncompatibleAddressException e) {
			failed = true;
			addFailure(new Failure(e.toString(), addr));
		} catch(RuntimeException e) {
			failed = true;
			addFailure(new Failure(e.toString(), addr));
		}
		incrementTestCount();
		return !failed;
	}

	boolean testBytes(MACAddress addr) {
		boolean failed = false;
		byte bytes[] = addr.getBytes();
		MACAddress another = createMACAddress(bytes);
		if(!addr.equals(another)) {
			addFailure(new Failure(addr.toString(), addr));
		}
		
		StringBuilder builder = new StringBuilder();
		builder.append(addr.toColonDelimitedString());
		if(addr.getSegmentCount() < 8) {
			builder.append("::");
		}
		try {
			InetAddress inetAddress = InetAddress.getByName(builder.toString());
			byte[] ipv6Bytes = inetAddress.getAddress();
			byte[] macBytes = new byte[bytes.length];
			for(int i = 0; i < macBytes.length; i++) {
				macBytes[i] = ipv6Bytes[(i << 1) + 1];
			}
			if(!Arrays.equals(macBytes, bytes)) {
				failed = true;
				addFailure(new Failure("bytes on addr " + inetAddress, addr));
			}
		} catch(UnknownHostException e) {
			failed = true;
			addFailure(new Failure("bytes on addr " + e, addr));
		}
		return !failed;
	}
	
	void testFromBytes(byte bytes[], String expected) {
		MACAddress addr = createMACAddress(bytes);
		MACAddressString addr2 = createMACAddress(expected);
		boolean result = addr.equals(addr2.getAddress());
		if(!result) {
			addFailure(new Failure("created was " + addr + " expected was " + addr2, addr));
		} else {
			long val = 0;
			for(int i = 0; i < bytes.length; i++) {
				val <<= 8;
				val |= 0xff & bytes[i];
			}
			addr = createMACAddress(val, bytes.length > 6);
			result = addr.equals(addr2.getAddress());
			if(!result) {
				addFailure(new Failure("created was " + addr + " expected was " + addr2, addr));
			}
		}
		incrementTestCount();
	}
	
	boolean isNotExpected(boolean expectedPass, MACAddressString addr) {
		try {
			addr.validate();
			return !expectedPass;
		} catch(AddressStringException e) {
			return expectedPass;
		}
	}
	
	boolean isNotExpectedNonZero(boolean expectedPass, MACAddressString addr) {
		if(!addr.isValid()) {
			return expectedPass;
		}
		//if expectedPass is true, we are expecting a non-zero address
		//return true to indicate we have gotten something not expected
		if(addr.getAddress() != null && addr.getAddress().isZero()) {
			return expectedPass;
		}
		return !expectedPass;
	}
	
	void mactest(boolean pass, String x) {
		mactest(pass, x, false);
	}
	
	void mactest(boolean pass, String x, boolean isZero) {
		mactest(pass, createMACAddress(x), isZero);
	}
	
	void mactest(int pass, String x) {
		mactest(pass == 0 ? false : true, x);
	}
	
	void mactest(int pass, String x, boolean isZero) {
		mactest(pass == 0 ? false : true, x, isZero);
	}

	void testContains(String addr1, String addr2, boolean equal) {
		try {
			MACAddress w = createMACAddress(addr1).toAddress();
			MACAddress w2 = createMACAddress(addr2).toAddress();
			if(!w.contains(w2)) {
				addFailure(new Failure("failed " + w2, w));
			} else {
				if(equal ? !w2.contains(w) : w2.contains(w)) {
					addFailure(new Failure("failed " + w, w2));
					if(equal) {
						System.out.println("containment: " + !w2.contains(w));
					} else {
						System.out.println("containment: " + w2.contains(w));
					}
				}
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + e));
		}
		incrementTestCount();
	}
	
	void testNotContains(String cidr1, String cidr2) {
		try {
			MACAddress w = createMACAddress(cidr1).toAddress();
			MACAddress w2 = createMACAddress(cidr2).toAddress();
			if(w.contains(w2)) {
				addFailure(new Failure("failed " + w2, w));
			} else if(w2.contains(w)) {
				addFailure(new Failure("failed " + w, w2));
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + e, new MACAddressString(cidr1)));
		}
		incrementTestCount();
	}
	
	private static Integer prefixAdjust(Integer existing, int max, int adj) {
		if(existing == null) {
			return null;
		}
		if(existing > max) {
			return null;
		}
		return Math.max(0, existing + adj);
	}
	
	private static boolean allEquals(Object one, Object two) {
		return Objects.equals(one, two);
	}
	
	private static boolean allEquals(Object one, Object two, Object three) {
		return allEquals(one, two) && allEquals(one, three);
	}

	void testSections(String addrString) {
		MACAddressString w = createMACAddress(addrString);
		MACAddress v = w.getAddress();
		MACAddressSection odiSection = v.getODISection();
		MACAddressSection ouiSection = v.getOUISection();
		MACAddressSection front = v.getSection(0,  3);
		MACAddressSection back = v.getSection(front.getSegmentCount());
		boolean first;
		if((first = !ouiSection.equals(front)) || !allEquals(ouiSection.getPrefixLength(), front.getPrefixLength(), prefixAdjust(v.getPrefixLength(), 24, 0))) {
			if(first) {
				addFailure(new Failure("failed oui " + ouiSection + " expected " + front, w));
			} else {
				addFailure(new Failure("failed oui pref " + ouiSection.getPrefixLength() + " expected " + prefixAdjust(v.getPrefixLength(), 24, 0) + " for " + front, w));
			}
		} else if((first = !odiSection.equals(back)) || !allEquals(odiSection.getPrefixLength(), back.getPrefixLength(), prefixAdjust(v.getPrefixLength(), 64, -24))) {
			if(first) {
				addFailure(new Failure("failed odi " + odiSection + " expected " + back, w));
			} else {
				addFailure(new Failure("failed odi pref " + odiSection.getPrefixLength() + " expected " + prefixAdjust(v.getPrefixLength(), 64, -24) + " for " + back, w));
			}
		} else {
			MACAddressSection middle = v.getSection(1, 5);
			MACAddressSection odiSection2 = odiSection.getSection(0, 5 - ouiSection.getSegmentCount());
			MACAddressSection ouiSection2 = ouiSection.getSection(1);
			odiSection = middle.getODISection();
			ouiSection = middle.getOUISection();
			if(!ouiSection.equals(ouiSection2) || !allEquals(ouiSection.getPrefixLength(), ouiSection2.getPrefixLength())) {
				addFailure(new Failure("failed odi " + ouiSection + " expected " + ouiSection2, w));
			} else if(!odiSection.equals(odiSection2) || !allEquals(odiSection.getPrefixLength(), odiSection2.getPrefixLength())) {
				addFailure(new Failure("failed odi " + odiSection + " expected " + odiSection2, w));
			} else if(ouiSection.getSegmentCount() != 2 || ouiSection2.getSegmentCount() != 2) {
				addFailure(new Failure("failed oui count " + ouiSection.getSegmentCount() + " expected " + 2, w));
			} else if(odiSection.getSegmentCount() != 2 || odiSection2.getSegmentCount() != 2) {
				addFailure(new Failure("failed oui count " + odiSection.getSegmentCount() + " expected " + 2, w));
			} else {
				MACAddressSection odiEmpty = odiSection.getSection(0, 0);
				MACAddressSection ouiEmpty = ouiSection.getSection(0, 0);
				if(odiEmpty.equals(ouiEmpty) || odiEmpty.getSegmentCount() > 0 || ouiEmpty.getSegmentCount() > 0) {
					addFailure(new Failure("failed odi empty " + odiEmpty + " oui empty " + ouiEmpty, w));
				} else {
					MACAddressSection midEmpty = middle.getSection(0, 0);
					if(!ouiEmpty.equals(midEmpty)|| midEmpty.getSegmentCount() != 0) {
						addFailure(new Failure("failed odi empty " + midEmpty + " expected " + ouiEmpty, w));
					} else {
						MACAddressSection midEmpty2 = middle.getSection(1, 1);
						if(ouiEmpty.equals(midEmpty2) || midEmpty2.getSegmentCount() != 0) {
							addFailure(new Failure("failed odi empty " + midEmpty2 + " expected " + ouiEmpty, w));
						}
					}
				}
			}
		}
		incrementTestCount();
	}
	
	void testMatches(boolean matches, String host1Str, String host2Str) {
		MACAddressString h1 = createMACAddress(host1Str);
		MACAddressString h2 = createMACAddress(host2Str);
		if(matches != h1.equals(h2)) {
			addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h2, h1));
		} else {
			if(matches != h2.equals(h1)) {
				addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h1, h2));
			} else {
				if(matches ? (h1.compareTo(h2) != 0) : (h1.compareTo(h2) == 0)) {
					addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h1, h2));
				} else {
					if(matches ? (h2.compareTo(h1) != 0) : (h2.compareTo(h1) == 0)) {
						addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h2, h1));
					} 
				}
			}
		}
		incrementTestCount();
	}
	
	void testReverse(String addressStr, boolean bitsReversedIsSame, boolean bitsReversedPerByteIsSame) {
		MACAddressString str = createMACAddress(addressStr);
		try {
			testReverse(str.getAddress(), bitsReversedIsSame, bitsReversedPerByteIsSame);
		} catch(RuntimeException e) {
			addFailure(new Failure("reversal: " + addressStr));
		}
		incrementTestCount();
	}
	
	void testPrefixes(String original, 
			int prefix, int adjustment,
			String next,
			String previous,
			String adjusted,
			String prefixSet,
			String prefixApplied) {
		testPrefixes(createMACAddress(original).getAddress(),
				prefix, adjustment, 
				createMACAddress(next).getAddress(),
				createMACAddress(previous).getAddress(),
				createMACAddress(adjusted).getAddress(),
				createMACAddress(prefixSet).getAddress(),
				createMACAddress(prefixApplied).getAddress());
		incrementTestCount();
	}
	
	void testPrefix(String original, Integer prefixLength, Integer equivalentPrefix) {
		MACAddress mac = createMACAddress(original).getAddress();
		testPrefix(mac, prefixLength, prefixLength == null ? mac.getBitCount() : prefixLength, equivalentPrefix);
		incrementTestCount();
	}
	
	void testDelimitedCount(String str, int expectedCount) {
		Iterator<String> strings = MACAddressString.parseDelimitedSegments(str);
		HashSet<MACAddress> set = new HashSet<MACAddress>();
		int count = 0;
		try {
			while(strings.hasNext()) {
				set.add(createMACAddress(strings.next()).toAddress());
				count++;
			}
			if(count != expectedCount || set.size() != count || count != MACAddressString.countDelimitedAddresses(str)) {
				addFailure(new Failure("count mismatch, count: " + count + " set count: " + set.size() + " calculated count: " + IPAddressString.countDelimitedAddresses(str) + " expected: " + expectedCount));
			}
		} catch (AddressStringException | IncompatibleAddressException e) {
			addFailure(new Failure("threw unexpectedly " + str));
		}
		incrementTestCount();
	}
	
	void testLongShort(String longAddr, String shortAddr) {
		testLongShort(longAddr, shortAddr, false);
	}
	
	void testLongShort(String longAddr, String shortAddr, boolean shortCanBeLong) {
		MACAddressStringParameters params = new MACAddressStringParameters.Builder().setAllAddresses(AddressSize.MAC).toParams();
		MACAddressString longString = new MACAddressString(longAddr, params);
		MACAddressString shortString = new MACAddressString(shortAddr, params);
		if(!shortString.isValid()) {
			addFailure(new Failure("short not valid " + shortString, shortString));
		}
		if(longString.isValid()) {
			addFailure(new Failure("long valid " + longString, longString));
		}
		params = new MACAddressStringParameters.Builder().setAllAddresses(AddressSize.EUI64).toParams();
		longString = new MACAddressString(longAddr, params);
		shortString = new MACAddressString(shortAddr, params);
		if(shortCanBeLong ? !shortString.isValid() : shortString.isValid()) {
			addFailure(new Failure("short valid " + shortString, shortString));
		}
		if(!longString.isValid()) {
			addFailure(new Failure("long not valid " + longString, longString));
		}
		if(longString.getAddress().getSegmentCount() != MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			addFailure(new Failure("long not enough segments " + longString, longString));
		}
		if(shortCanBeLong && shortString.getAddress().getSegmentCount() != MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			addFailure(new Failure("also not enough segments " + shortString, shortString));
		}
		params = new MACAddressStringParameters.Builder().setAllAddresses(AddressSize.ANY).toParams();
		longString = new MACAddressString(longAddr, params);
		shortString = new MACAddressString(shortAddr, params);
		if(!shortString.isValid()) {
			addFailure(new Failure("short not valid " + shortString, shortString));
		}
		if(!longString.isValid()) {
			addFailure(new Failure("long not valid " + longString, longString));
		}
		incrementTestCount();
	}
	
	void testMACStrings(String addr, 
			String normalizedString, //toColonDelimitedString
			String compressedString,
			String canonicalString, //toDashedString
			String dottedString,
			String spaceDelimitedString,
			String singleHex) {
		MACAddressString w = createMACAddress(addr);
		MACAddress ipAddr = w.getAddress();
		testMACStrings(w, ipAddr, normalizedString, compressedString, canonicalString, dottedString, spaceDelimitedString, singleHex);
	}
	
	void testStrings() {

		testMACStrings("a:b:c:d:e:f:a:b",
				"0a:0b:0c:0d:0e:0f:0a:0b",//normalizedString, //toColonDelimitedString
				"a:b:c:d:e:f:a:b",//compressedString,
				"0a-0b-0c-0d-0e-0f-0a-0b",//canonicalString, //toDashedString
				"0a0b.0c0d.0e0f.0a0b",//dottedString,
				"0a 0b 0c 0d 0e 0f 0a 0b",//spaceDelimitedString,
				"0a0b0c0d0e0f0a0b");//singleHex
		
		testMACStrings("ab:ab:bc:cd:De:ef",
				"ab:ab:bc:cd:de:ef",//normalizedString, //toColonDelimitedString
				"ab:ab:bc:cd:de:ef",//compressedString,
				"ab-ab-bc-cd-de-ef",//canonicalString, //toDashedString
				"abab.bccd.deef",//dottedString,
				"ab ab bc cd de ef",//spaceDelimitedString,
				"ababbccddeef");//singleHex
		
		testMACStrings("ab:AB:bc:cd:de:ef:aB:aB",
				"ab:ab:bc:cd:de:ef:ab:ab",//normalizedString, //toColonDelimitedString
				"ab:ab:bc:cd:de:ef:ab:ab",//compressedString,
				"ab-ab-bc-cd-de-ef-ab-ab",//canonicalString, //toDashedString
				"abab.bccd.deef.abab",//dottedString,
				"ab ab bc cd de ef ab ab",//spaceDelimitedString,
				"ababbccddeefabab");//singleHex
		

		testMACStrings("a:b:c:d:0:0",
				"0a:0b:0c:0d:00:00",//normalizedString, //toColonDelimitedString
				"a:b:c:d:0:0",//compressedString,
				"0a-0b-0c-0d-00-00",//canonicalString, //toDashedString
				"0a0b.0c0d.0000",//dottedString,
				"0a 0b 0c 0d 00 00",//spaceDelimitedString,
				"0a0b0c0d0000");//singleHex
		
		testMACStrings("ff:00:10:01:10:11",
				"ff:00:10:01:10:11",//normalizedString, //toColonDelimitedString
				"ff:0:10:1:10:11",//compressedString,
				"ff-00-10-01-10-11",//canonicalString, //toDashedString
				"ff00.1001.1011",//dottedString,
				"ff 00 10 01 10 11",//spaceDelimitedString,
				"ff0010011011");//singleHex
		
		testMACStrings("0aa0bbb00cff",
				"0a:a0:bb:b0:0c:ff",
				"a:a0:bb:b0:c:ff",
				"0a-a0-bb-b0-0c-ff",
				"0aa0.bbb0.0cff",
				"0a a0 bb b0 0c ff",
				"0aa0bbb00cff");
		
		testMACStrings("0aa0bb-b00cff",
				"0a:a0:bb:b0:0c:ff",
				"a:a0:bb:b0:c:ff",
				"0a-a0-bb-b0-0c-ff",
				"0aa0.bbb0.0cff",
				"0a a0 bb b0 0c ff",
				"0aa0bbb00cff");
	}
	
	void testMACIPv6(String ipv6, String mac) {
		IPAddressString ipv6Str = createAddress(ipv6);
		MACAddressString macStr = createMACAddress(mac);
		IPv6Address addr = ipv6Str.getAddress().toIPv6();
		IPv6AddressSection back = addr.getHostSection(64);
		
		
		if(!back.isEUI64()) {
			addFailure(new Failure("eui 64 check " + back, back));
		} else {
			MACAddress macAddr = macStr.getAddress();
			IPv6AddressSection macBack = macAddr.toEUI64IPv6();
			IPv6Address linkLocal = macAddr.toLinkLocalIPv6();
			if(!linkLocal.isLinkLocal()) {
				addFailure(new Failure("eui 64 conv link local " + macAddr, linkLocal));
			} else {
				if(!macBack.equals(back)) {
					addFailure(new Failure("eui 64 conv " + back, macBack));
				} else {
					MACAddress macAddr64 = macAddr.toEUI64(false);
					if(macAddr.isEUI64(true) || macAddr.isEUI64(false) || !macAddr64.isEUI64(false)) {
						addFailure(new Failure("mac eui test " + macAddr64, macAddr));
					} else {
						IPv6AddressSection backFromMac64 = new IPv6AddressSection(macAddr64);
						if(!backFromMac64.equals(back)) {
							addFailure(new Failure("eui 64 conv 2" + back, backFromMac64));
						} else {
							IPv6AddressSection backFromMac = new IPv6AddressSection(macAddr);
							if(!backFromMac.equals(back)) {
								addFailure(new Failure("eui 64 conv 3" + back, backFromMac));
							} else {
								boolean withPrefix = false;//we do the loop twice, once with prefixes, the other without
								do {
									IPv6AddressSection frontIpv6 = addr.getNetworkSection(64, withPrefix);
									if(withPrefix) {
										addr = addr.setPrefixLength(64, false);
									}
									IPv6AddressSection backLinkLocal = linkLocal.getHostSection(64);
									IPv6AddressSection backIpv6 = addr.getHostSection(64);
									IPv6Address splitJoined1 = new IPv6Address(frontIpv6, backIpv6.toEUI(true));
									IPv6Address splitJoined2 = new IPv6Address(frontIpv6, backIpv6.toEUI(false));
									IPv6Address splitJoined3 = new IPv6Address(frontIpv6.append(backIpv6));
									MACAddressSection other = new MACAddressSection(new MACAddressSegment(0xee));
									for(int j = 0; j < 2; j++) {
										MACAddress m;
										if(j == 0) {
											m = macAddr64;
										} else {
											m = macAddr;
										}
										for(int i = 0; i <= m.getSegmentCount(); i++) {
											MACAddressSection backSec = m.getSection(i, m.getSegmentCount());
											MACAddressSection frontSec = m.getSection(0, i);
											
											if(j == 1) {
												if(backSec.isEUI64(true) || backSec.isEUI64(false) || frontSec.isEUI64(true) || frontSec.isEUI64(false)) {
													addFailure(new Failure("eui 64 test " + backSec, frontSec));
												}
												if(i >= 3) {
													MACAddressSection frontSec2 = frontSec.toEUI64(false);
													if(!frontSec2.isEUI64(false)) {
														addFailure(new Failure("eui 64 test " + backSec, frontSec));
													}
												}
												if(i <= 3) {
													MACAddressSection backSec2 = backSec.toEUI64(false);
													if(!backSec2.isEUI64(false)) {
														addFailure(new Failure("eui 64 test " + backSec, frontSec));
													}
												}
												
											} else {
												if(i < 4) {
													if(backSec.isEUI64(true) || !backSec.isEUI64(false) || frontSec.isEUI64(true) || frontSec.isEUI64(false)) {
														addFailure(new Failure("eui 64 test " + backSec, frontSec));
													} else {
														MACAddressSection backSec2 = backSec.replace(3 - i, other);
														if(backSec2.isEUI64(false)) {
															addFailure(new Failure("eui 64 test " + backSec2, backSec2));
														}
													}
												} else if(i == 4) {
													if(backSec.isEUI64(true) || 
															backSec.isEUI64(false) || !backSec.isEUI64(false, true) ||
															frontSec.isEUI64(true) ||
															frontSec.isEUI64(false) || !frontSec.isEUI64(false, true)) {
														addFailure(new Failure("eui 64 test " + backSec, frontSec));
													} else {
														backSec = backSec.toEUI64(false);
														frontSec = frontSec.toEUI64(false);
														if(!backSec.isEUI64(false, true) || backSec.isEUI64(false) || !frontSec.isEUI64(false, true) || frontSec.isEUI64(false)) {
															addFailure(new Failure("eui 64 test " + backSec, frontSec));
														} else {
															MACAddressSection frontSec2 = frontSec.replace(3, other);//take backSec and frontSec, stick something else in the middle other than fffe
															MACAddressSection backSec2 = backSec.replace(4 - i, other);
															if(backSec2.isEUI64(false, true) || frontSec2.isEUI64(false, true)) {
																addFailure(new Failure("eui 64 test " + backSec2, frontSec2));
															}
														}
													}
												} else {
													if(backSec.isEUI64(true) || backSec.isEUI64(false) || frontSec.isEUI64(true) || !frontSec.isEUI64(false)) {
														addFailure(new Failure("eui 64 test " + backSec, backSec));
													} else {
														MACAddressSection frontSec2 = frontSec.replace(4, other);
														if(frontSec2.isEUI64(false)) {
															addFailure(new Failure("eui 64 test " + frontSec2, frontSec2));
														}
													}
												}
											}
											IPv6AddressSection backIpv6Sec = new IPv6AddressSection(backSec);
											IPv6AddressSection frontIpv6Sec = new IPv6AddressSection(frontSec);
											IPv6AddressSection both1, both2;
											
											//For the blocks below...
											//i is the index where we split the mac address
											//j==1 means mac address is 48 bits, i == 3 is the middle index
											//
											//Start with MAC ff:ff:fa:bf:ff:ff
											//Split at even index like 2: ff:ff  fa:bf:ff:ff
											//Convert each to IPv6: ffff faff:febf:ffff
											//Then we can just append to get the ipv6 segs: ffff:faff:febf:ffff
											//
											//Split at odd index like 1: ff  ff:fa:bf:ff:ff
											//Convert each to IPv6: ff00 00ff:faff:febf:ffff
											//We cannot just append.
											//Instead we must merge with bitwiseOr the segments where we split: ff00 00ff into ffff
											//Then we can append ffff with faff:febf:ffff to get: ffff:faff:febf:ffff
											//
											//Also, if we split at index 3 we get ff:ff:fa  bf:ff:ff
											//Convert each to IPv6: ffff:faff  febf:ffff
											//In this case there are no extra segments and we can just append: ffff:faff:febf:ffff
											if((i % 2 == 0) || ((j == 1) && (i == 3))) {
												//no merging of segments required, see comment below
												//either the MAC segments are split at an even index so the ipv6 conversion segment count is just right,
												//or we split the mac address at i == 3 and the resultant IPv6 will have the ff:ff or ff:fe stuck in there and we will not have extra bits to be merged
												both1 = frontIpv6Sec.append(backIpv6Sec);
												both2 = frontIpv6Sec.append(backIpv6Sec);
											} else {
												//When we are splitting up our MAC address at an odd index, 
												//and then we convert each side to IPv6, then we will have 0 bits at the back of the front IPv6 section,
												//and we will have 0 bits at the front of the back IPv6 section,
												//so we can just merge the two segments with a bitWise or back to a single segment (merged)
												int frontCount = frontIpv6Sec.getSegmentCount();
												IPv6AddressSection lastFront = frontIpv6Sec.getSection(frontCount - 1, frontCount);
												IPv6AddressSection frontBack = backIpv6Sec.getSection(0, 1);
												if(frontBack.isMultiple()) {
													//the technique of bitwiseOr won't work when dealing with multiple
													continue;
												}
												if(i == 1 && frontSec.getSegment(0).matchesWithMask(0x2, 0x2)) {
													//the back section will have flipped on the toggle bit since it has the first segment but not the first half of the segment
													//so it will be flipped on when it should remain off
													frontBack = frontBack.mask(new IPv6AddressSection(new IPv6AddressSegment(0xfdff)));
												}
												IPv6AddressSection merged = lastFront.bitwiseOr(frontBack);//frontback has bit flipped on here and it should not
												IPv6AddressSection mergedAll = frontIpv6Sec.replace(frontCount - 1, merged);
												IPv6AddressSection backRes = backIpv6Sec.getSection(1, backIpv6Sec.getSegmentCount());
												both1 = mergedAll.append(backRes);
												both2 = mergedAll.append(backRes);
											}
											IPv6AddressSection both3 = backFromMac;
											IPv6Address all[] = new IPv6Address[14];
											all[0] = new IPv6Address(addr.getSection().replace(4, both1));
											all[1] = new IPv6Address(addr.getSection().replace(4, both2));
											all[2] = new IPv6Address(addr.getSection().replace(4, both3));
											all[3] = new IPv6Address(frontIpv6.append(both1));
											all[4] = new IPv6Address(frontIpv6.append(both2));
											all[5] = new IPv6Address(frontIpv6.append(both3));
											all[6] = new IPv6Address(frontIpv6.append(both1));
											all[7] = new IPv6Address(frontIpv6.append(both2));
											all[8] = new IPv6Address(frontIpv6.append(both3));
											all[9] = splitJoined1;
											all[10] = splitJoined2;
											all[11] = splitJoined3;
											all[12] = new IPv6Address(addr.getSection().replace(4, backLinkLocal));
											all[13] = new IPv6Address(frontIpv6.append(backLinkLocal));
											
											//All of these should be equal!
											HashSet<IPv6Address> set = new HashSet<IPv6Address>();
											Integer prefix = all[0].getNetworkPrefixLength();
											for(IPv6Address one : all) {
												if(!Objects.equals(prefix, one.getNetworkPrefixLength())) {
													addFailure(new Failure("eui 64 conv set prefix is " + one.getNetworkPrefixLength() + " previous was " + prefix, one));
												}
												set.add(one);
											}
											if(set.size() != 1) {
												addFailure(new Failure("eui 64 conv set " + set.size() + ' ' + set.toString()));
											}
											TreeSet<IPv6Address> treeSet = new TreeSet<IPv6Address>();
											for(IPv6Address one : all) {
												treeSet.add(one);
											}
											if(treeSet.size() != 1) {
												addFailure(new Failure("eui 64 conv set " + treeSet.size() + ' ' + treeSet.toString()));
											}
										}
									}
									if(withPrefix || addr.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
										break;
									}
									withPrefix = true;
								} while(true);
							}
						}
					}
				}
			}
		}
		incrementTestCount();
	}
	
	void testInsertAndAppend(String front, String back, int expectedPref[]) {
		Integer is[] = new Integer[expectedPref.length];
		for(int i = 0; i < expectedPref.length; i++) {
			is[i] = expectedPref[i];
		}
		testInsertAndAppend(front, back, is);
	}
	
	void testInsertAndAppend(String front, String back, Integer expectedPref[]) {
		MACAddress f = createMACAddress(front).getAddress();
		MACAddress b = createMACAddress(back).getAddress();
		testAppendAndInsert(f, b, f.getSegmentStrings(), b.getSegmentStrings(), 
				MACAddress.COLON_SEGMENT_SEPARATOR, expectedPref, true);
	}
	
	void testReplace(String front, String back) {
		MACAddress f = createMACAddress(front).getAddress();
		MACAddress b = createMACAddress(back).getAddress();
		testReplace(f, b, f.getSegmentStrings(), b.getSegmentStrings(), 
				MACAddress.COLON_SEGMENT_SEPARATOR, true);
	}
	
	void testInvalidMACValues() {
		try {
			byte bytes[] = new byte[9];
			bytes[0] = 1;
			MACAddress addr = new MACAddress(bytes);
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			new MACAddress(new byte[9]);
			//addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new MACAddress(new byte[8]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new MACAddress(new byte[7]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new MACAddress(new byte[6]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new MACAddress(new byte[5]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			MACAddress addr = new MACAddress(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return 256;
				}
			});
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			MACAddress addr = new MACAddress(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return -1;
				}
			});
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			new MACAddress(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return 255;
				}
			});
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
	}
	
	void testMACValues(int segs[], String decimal) {
		testMACValues(segs, decimal, null);
	}
	
	void testMACValues(int segs[], String decimal, String negativeDecimal) {
		byte vals[] = new byte[segs.length];
		StringBuilder strb = new StringBuilder();
		long longval = 0;
		BigInteger bigInteger = BigInteger.ZERO;
		int bitsPerSegment = MACAddress.BITS_PER_SEGMENT;
		for(int i = 0; i < segs.length; i++) {
			int seg = segs[i];
			if(strb.length() > 0) {
				strb.append(':');
			}
			strb.append(Integer.toHexString(seg));
			vals[i] = (byte) seg;
			longval = (longval << bitsPerSegment) | seg;
			bigInteger = bigInteger.shiftLeft(bitsPerSegment).add(BigInteger.valueOf(seg));
		}
		MACAddress addr[] = new MACAddress[3];
		int i = 0;
		addr[i++] = createMACAddress(vals);
		addr[i++] = createMACAddress(strb.toString()).getAddress();
		addr[i++] = createMACAddress(longval, segs.length == 8);
		for(int j = 0; j < addr.length; j++) {
			for(int k = j; k < addr.length; k++) {
				if(!addr[k].equals(addr[j]) || !addr[j].equals(addr[k])) {
					addFailure(new Failure("failed equals: " + addr[k] + " and " + addr[j]));
				}
			}
		}
		if(decimal != null) {
			for(i = 0; i < addr.length; i++) {
				if(!decimal.equals(addr[i].getValue().toString())) {
					addFailure(new Failure("failed equals: " + addr[i].getValue() + " and " + decimal));
				}
				long longVal = addr[i].longValue();
				if(longVal < 0) {
					if(!String.valueOf(longVal).equals(negativeDecimal)) {
						addFailure(new Failure("failed equals: " + addr[i].longValue() + " and " + decimal));
					}
				} else if(!decimal.equals(String.valueOf(longVal))) {
					addFailure(new Failure("failed equals: " + addr[i].longValue() + " and " + decimal));
				}
			}
		}
	}
	
	void testIncrement(String originalStr, long increment, String resultStr) {
		testIncrement(createMACAddress(originalStr).getAddress(), increment, resultStr == null ? null : createMACAddress(resultStr).getAddress());
	}
	
	//returns true if this testing class allows inet_aton, leading zeros extending to extra digits, empty addresses, and basically allows everything
	boolean isLenient() {
		return false;
	}
	
	boolean allowsRange() {
		return false;
	}
	
	@Override
	void runTest() {
		//space del
		//dashed
		//double seg dashed
		//dotted
		//single seg
		mactest(true, "aa:b:cc:d:ee:f");
		mactest(false, "aaa:b:cc:d:ee:f");
		mactest(false, "aa:bbb:cc:d:ee:f");
		mactest(false, "aa:bb:ccc:d:ee:f");
		mactest(false, "aa:bb:cc:ddd:ee:f");
		mactest(false, "aa:bb:cc:dd:eee:f");
		mactest(false, "aa:bb:cc:dd:ee:fff");
		mactest(false, "aa:bb:cc:dd:ee:ff:eee:aa");
		mactest(false, "aa:bb:cc:dd:ee:ff:ee:aaa");
		mactest(true, "aa:bb:cc:dd:ee:ff:ee:aa");
		mactest(false, "0xaa:b:cc:d:ee:f");
		mactest(false, "aa:0xb:cc:d:ee:f");
		mactest(false, "aa:b:0xcc:d:ee:f");
		mactest(false, "aa:b:cx:d:ee:f");
		mactest(false, "aa:b:cx:d:ee:fg");
		
		mactest(true, "aa-b-cc-d-ee-f");
		mactest(false, "aaa-b-cc-d-ee-f");
		mactest(false, "aa-bbb-cc-d-ee-f");
		mactest(false, "aa-bb-ccc-d-ee-f");
		mactest(false, "aa-bb-cc-ddd-ee-f");
		mactest(false, "aa-bb-cc-dd-eee-f");
		mactest(false, "aa-bb-cc-dd-ee-fff");
		mactest(false, "aa-bb-cc-dd-ee-ff-eee-aa");
		mactest(false, "aa-bb-cc-dd-ee-ff-ee-aaa");
		mactest(true, "aa-bb-cc-dd-ee-ff-ee-aa");
		mactest(false, "0xaa-b-cc-d-ee-f");
		mactest(false, "xaa-b-cc-d-ee-f");
		mactest(false, "aa-b-cc-d-ee-0xf");
		mactest(false, "aa-b-cc-d-ee-0xff");
		mactest(false, "aa-0xb-cc-d-ee-f");
		mactest(false, "aa-b-cx-d-ee-f");
		mactest(false, "aa-b-0xc-d-ee-f");
		mactest(false, "aa-b-cx-d-ee-fg");
		
		mactest(true, "aabb.ccdd.eeff");
		mactest(false, "aabbc.ccdd.eeff");
		mactest(false, "aabb.ccddc.eeff");
		mactest(false, "aabb.ccdd.eeffc");
		mactest(false, "aabb.ccdd.eeff.ccdde");
		mactest(true, "aabb.ccdd.eeff.ccde");
		mactest(false, "aabb.ccdd.eeff.0xccdd");
		mactest(false, "0xaabb.ccdd.eeff.ccdd");
		mactest(false, "aabb.0xccdd.eeff.ccdd");
		mactest(false, "aabb.ccgd.eeff.ccdd");
		
		mactest(true, "1:2:3:4:5:6");
		mactest(true, "11:22:33:44:55:66");
		mactest(false, "11:22:33:444:55:66");
		mactest(false, "aa:x:cc:d:ee:f");
		mactest(false, "aa:g:cc:d:ee:f");
		mactest(allowsRange(), "aa:-1:cc:d:ee:f");//same as "aa:0-1:cc:d:ee:f"
		mactest(allowsRange(), "aa:-dd:cc:d:ee:f");//same as "aa:0-dd:cc:d:ee:f"
		mactest(allowsRange(), "aa:1-:cc:d:ee:f");//same as "aa:1-ff:cc:d:ee:f"
		mactest(allowsRange(), "-1:aa:cc:d:ee:f");//same as "aa:0-1:cc:d:ee:f"
		mactest(allowsRange(), "1-:aa:cc:d:ee:f");//same as "aa:0-1:cc:d:ee:f"
		mactest(allowsRange(), "aa:cc:d:ee:f:1-");
		mactest(allowsRange(), "aa:0-1:cc:d:ee:f");
		mactest(allowsRange(), "aa:1-ff:cc:d:ee:f");
		mactest(allowsRange(), "aa-|1-cc-d-ee-f");
		mactest(allowsRange(), "|1-aa-cc-d-ee-f");
		mactest(allowsRange(), "aa-1|-cc-d-ee-f");
		mactest(allowsRange(), "1|-aa-cc-d-ee-f");
		mactest(allowsRange(), "aa-0|1-cc-d-ee-f");
		mactest(allowsRange(), "aa-1|ff-cc-d-ee-f");
		mactest(allowsRange(), "aa-ff-cc|dd-d-ee-f");
		mactest(false, "aa-||1-cc-d-ee-f");
		mactest(false, "aa-1||-cc-d-ee-f");
		mactest(true, "a:bb:c:dd:e:ff");
		mactest(true, "aa:bb:cc:dd:ee:ff");
		mactest(false, "aa:bb:cc:dd::ee:ff");
		mactest(false, "aa:bb::dd:ee:ff");
		mactest(false, "aa:bb-cc:dd:ee:ff");
		mactest(true, "aabbcc-ddeeff");
		mactest(false, "aaabbcc-ddeeff");
		mactest(false, "aabbcc-ddeefff");
		mactest(false, "aabbcc-ddeeffff");
		mactest(false, "aabbcc-ddeefffff");
		mactest(true, "aabbcc-ddeeffffff");
		mactest(false, "aaabbcc-ddeeffffff");
		mactest(false, "aaaabbcc-ddeeffffff");
		mactest(false, "aaaaaabbcc-ddeeffffff");
		mactest(false, "aaabbcc-ddeeffff");
		mactest(false, "aabbcc.ddeeff");
		mactest(false, "aabbcc:ddeeff");
		mactest(false, "aabbcc ddeeff");
		mactest(false, "aa-bb-cc dd-ee-ff");
		mactest(false, "aa bb cc dd ee-ff");
		mactest(false, "aa:bb:cc dd:ee:ff");
		mactest(false, "aa bb cc dd ee:ff");
		mactest(false, "aa-bb-cc:dd-ee-ff");
		mactest(false, "aa.b.cc.d.ee.f");
		mactest(false, "aa.bb.cc.dd.ee.ff");
		mactest(false, "aa.bb.cc dd.ee.ff");
		
		mactest(false, "aa-bb-cc-dd:ee-ff");
		mactest(false, "aa-bb-cc-dd-ee:-ff");
		mactest(false, "aa-bb-cc-dd-ee--ff");
		mactest(false, "aa-bb-cc-dd--ee");
		mactest(false, "aa:bb:cc:dd:ee:ff:");
		mactest(false, "aa:bb:cc:dd:ee:ff:aa");
		mactest(false, "ff:aa:bb:cc:dd:ee:ff");
		mactest(true, "aa:bb:cc:dd:ee:ff:aa:bb");
		mactest(true, "ee:ff:aa:bb:cc:dd:ee:ff");
		mactest(false, ":aa:bb:cc:dd:ee:ff:aa:bb");
		mactest(false, "ee:ff:aa:bb:cc:dd:ee:ff:");
		mactest(false, "aa:aa:bb:cc:dd:ee:ff:aa:bb");
		mactest(false, "ee:ff:aa:bb:cc:dd:ee:ff:ee");
		mactest(false, ":aa:bb:cc:dd:ee:ff");
		mactest(false, "aa:bb cc:dd:ee:ff");
		mactest(false, "aa:bb:cc:dd.ee:ff");
		mactest(false, "aaa:bb:cc:dd:ee:ff");
		mactest(false, "aa:bbb:cc:dd:ee:ff");
		mactest(false, "aa:bb:ccc:dd:ee:ff");
		mactest(false, "aa:bb:cc:ddd:ee:ff");
		mactest(false, "aa:bb:cc:dd:eee:ff");
		mactest(false, "aa:bb:cc:dd:ee:fff");
		
		testNormalized("A:B:C:D:E:F:A:B", "0a:0b:0c:0d:0e:0f:0a:0b");
		testNormalized("AB:AB:CC:Dd:Ee:fF:aA:Bb", "ab:ab:cc:dd:ee:ff:aa:bb");
		
		testNormalized("12:CD:CC:dd:Ee:fF:AA:Bb", "12:cd:cc:dd:ee:ff:aa:bb");
		testNormalized("12:CD:CC:dd:Ee:fF", "12:cd:cc:dd:ee:ff");
		
		testNormalized("0:0:0:0:0:0:0:0", "00:00:00:00:00:00:00:00");
		testNormalized("0:0:0:0:0:0", "00:00:00:00:00:00");
		
		testNormalized("0:1:0:2:0:3:0:0", "00:01:00:02:00:03:00:00");
		testNormalized("0:1:0:2:0:3", "00:01:00:02:00:03");
		
		
		
		testNormalized("A-B-C-D-E-F-A-B", "0a:0b:0c:0d:0e:0f:0a:0b");
		testNormalized("AB-AB-CC-Dd-Ee-fF-aA-Bb", "ab:ab:cc:dd:ee:ff:aa:bb");
		
		testNormalized("12-CD-CC-dd-Ee-fF-AA-Bb", "12:cd:cc:dd:ee:ff:aa:bb");
		testNormalized("12-CD-CC-dd-Ee-fF", "12:cd:cc:dd:ee:ff");
		
		testNormalized("0-0-0-0-0-0-0-0", "00:00:00:00:00:00:00:00");
		testNormalized("0-0-0-0-0-0", "00:00:00:00:00:00");
		
		testNormalized("0-1-0-2-0-3-0-0", "00:01:00:02:00:03:00:00");
		testNormalized("0-1-0-2-0-3", "00:01:00:02:00:03");

		testNormalized("A B C D E F A B", "0a:0b:0c:0d:0e:0f:0a:0b");
		testNormalized("AB AB CC Dd Ee fF aA Bb", "ab:ab:cc:dd:ee:ff:aa:bb");
		
		testNormalized("12 CD CC dd Ee fF AA Bb", "12:cd:cc:dd:ee:ff:aa:bb");
		testNormalized("12 CD CC dd Ee fF", "12:cd:cc:dd:ee:ff");
		
		testNormalized("0 0 0 0 0 0 0 0", "00:00:00:00:00:00:00:00");
		testNormalized("0 0 0 0 0 0", "00:00:00:00:00:00");
		
		testNormalized("0 1 0 2 0 3 0 0", "00:01:00:02:00:03:00:00");
		testNormalized("0 1 0 2 0 3", "00:01:00:02:00:03");
		
		testNormalized("0A0B.0C0D.0E0F", "0a:0b:0c:0d:0e:0f");
		testNormalized("A0B.C0D.E0F", "0a:0b:0c:0d:0e:0f");
		testNormalized("AB.C00.DE0F", "00:ab:0c:00:de:0f");
		testNormalized("A0.B00.c00d", "00:a0:0b:00:c0:0d");
		
		testNormalized("0A0B.0C0D.0E0F.0a0b", "0a:0b:0c:0d:0e:0f:0a:0b");
		testNormalized("A0B.C0D.E0F.1234", "0a:0b:0c:0d:0e:0f:12:34");
		testNormalized("AB.C00.DE0F.123", "00:ab:0c:00:de:0f:01:23");
		testNormalized("A0.B00.c00d.4", "00:a0:0b:00:c0:0d:00:04");
		
		testNormalized("12CD.CCdd.EefF", "12:cd:cc:dd:ee:ff");
		testNormalized("0000.0000.0000", "00:00:00:00:00:00");
		testNormalized("0002.0003.0003", "00:02:00:03:00:03");

		testNormalized("0A0B0C-0D0E0F", "0a:0b:0c:0d:0e:0f");
		testNormalized("0A0B0C-0D0E0F", "0a:0b:0c:0d:0e:0f");
		testNormalized("0A0B0C-0D0E0F0A0B", "0a:0b:0c:0d:0e:0f:0a:0b");
		testNormalized("ABABCC-DdEefFaABb", "ab:ab:cc:dd:ee:ff:aa:bb");
		
		testNormalized("12CDCC-ddEefFAABb", "12:cd:cc:dd:ee:ff:aa:bb");
		testNormalized("12CDCC-ddEefF", "12:cd:cc:dd:ee:ff");
		testNormalized("aaaabb-bbcccc", "aa:aa:bb:bb:cc:cc");
		testNormalized("010233045506", "01:02:33:04:55:06");
		
		testNormalized("000000-0000000000", "00:00:00:00:00:00:00:00");
		testNormalized("000000-000000", "00:00:00:00:00:00");
		
		testNormalized("000100-0200030000", "00:01:00:02:00:03:00:00");
		testNormalized("000100-020003", "00:01:00:02:00:03");
		
		
		
		testNormalized("0A0B0C0D0E0F", "0a:0b:0c:0d:0e:0f");
		testNormalized("0x0A0B0C0D0E0F", "0a:0b:0c:0d:0e:0f");
		testNormalized("0A0B0C0D0E0F0A0B", "0a:0b:0c:0d:0e:0f:0a:0b");
		testNormalized("ABABCCDdEefFaABb", "ab:ab:cc:dd:ee:ff:aa:bb");
		
		testNormalized("12CDCCddEefFAABb", "12:cd:cc:dd:ee:ff:aa:bb");
		testNormalized("12CDCCddEefF", "12:cd:cc:dd:ee:ff");
		
		testNormalized("0000000000000000", "00:00:00:00:00:00:00:00");
		testNormalized("000000000000", "00:00:00:00:00:00");
		
		testNormalized("0001000200030000", "00:01:00:02:00:03:00:00");
		testNormalized("000100020003", "00:01:00:02:00:03");
		


		testCanonical("A:B:C:D:E:F:A:B", "0a-0b-0c-0d-0e-0f-0a-0b");
		testCanonical("AB:AB:CC:Dd:Ee:fF:aA:Bb", "ab-ab-cc-dd-ee-ff-aa-bb");
		
		testCanonical("12:CD:CC:dd:Ee:fF:AA:Bb", "12-cd-cc-dd-ee-ff-aa-bb");
		testCanonical("12:CD:CC:dd:Ee:fF", "12-cd-cc-dd-ee-ff");
		
		testCanonical("0:0:0:0:0:0:0:0", "00-00-00-00-00-00-00-00");
		testCanonical("0:0:0:0:0:0", "00-00-00-00-00-00");
		
		testCanonical("0:1:0:2:0:3:0:0", "00-01-00-02-00-03-00-00");
		testCanonical("0:1:0:2:0:3", "00-01-00-02-00-03");
		
		
		
		testCanonical("A-B-C-D-E-F-A-B", "0a-0b-0c-0d-0e-0f-0a-0b");
		testCanonical("AB-AB-CC-Dd-Ee-fF-aA-Bb", "ab-ab-cc-dd-ee-ff-aa-bb");
		
		testCanonical("12-CD-CC-dd-Ee-fF-AA-Bb", "12-cd-cc-dd-ee-ff-aa-bb");
		testCanonical("12-CD-CC-dd-Ee-fF", "12-cd-cc-dd-ee-ff");
		
		testCanonical("0-0-0-0-0-0-0-0", "00-00-00-00-00-00-00-00");
		testCanonical("0-0-0-0-0-0", "00-00-00-00-00-00");
		
		testCanonical("0-1-0-2-0-3-0-0", "00-01-00-02-00-03-00-00");
		testCanonical("0-1-0-2-0-3", "00-01-00-02-00-03");
		
		
		
		testCanonical("A B C D E F A B", "0a-0b-0c-0d-0e-0f-0a-0b");
		testCanonical("AB AB CC Dd Ee fF aA Bb", "ab-ab-cc-dd-ee-ff-aa-bb");
		
		testCanonical("12 CD CC dd Ee fF AA Bb", "12-cd-cc-dd-ee-ff-aa-bb");
		testCanonical("12 CD CC dd Ee fF", "12-cd-cc-dd-ee-ff");
		
		testCanonical("0 0 0 0 0 0 0 0", "00-00-00-00-00-00-00-00");
		testCanonical("0 0 0 0 0 0", "00-00-00-00-00-00");
		
		testCanonical("0 1 0 2 0 3 0 0", "00-01-00-02-00-03-00-00");
		testCanonical("0 1 0 2 0 3", "00-01-00-02-00-03");
		
		testCanonical("0A0B.0C0D.0E0F", "0a-0b-0c-0d-0e-0f");
		testCanonical("BA0B.DC0D.FE0F", "ba-0b-dc-0d-fe-0f");
		testCanonical("A0B.C0D.E0F", "0a-0b-0c-0d-0e-0f");
		testCanonical("AB.C00.DE0F", "00-ab-0c-00-de-0f");
		testCanonical("A.B.c", "00-0a-00-0b-00-0c");
		
		testCanonical("12CD.CCdd.EefF", "12-cd-cc-dd-ee-ff");
		testCanonical("0000.0000.0000", "00-00-00-00-00-00");
		testCanonical("0002.0003.0003", "00-02-00-03-00-03");
		testCanonical("0020.0030.0030", "00-20-00-30-00-30");
		
		
		
		testCanonical("0A0B0C-0D0E0F", "0a-0b-0c-0d-0e-0f");
		testCanonical("0A0B0C-0D0E0F0A0B", "0a-0b-0c-0d-0e-0f-0a-0b");
		testCanonical("ABABCC-DdEefFaABb", "ab-ab-cc-dd-ee-ff-aa-bb");
		
		testCanonical("12CDCC-ddEefFAABb", "12-cd-cc-dd-ee-ff-aa-bb");
		testCanonical("12CDCC-ddEefF", "12-cd-cc-dd-ee-ff");
		
		testCanonical("000000-0000000000", "00-00-00-00-00-00-00-00");
		testCanonical("000000-000000", "00-00-00-00-00-00");
		
		testCanonical("000100-0200030000", "00-01-00-02-00-03-00-00");
		testCanonical("000100-020003", "00-01-00-02-00-03");
		
		
		
		testCanonical("0A0B0C0D0E0F", "0a-0b-0c-0d-0e-0f");
		testCanonical("0A0B0C0D0E0F0A0B", "0a-0b-0c-0d-0e-0f-0a-0b");
		testCanonical("ABABCCDdEefFaABb", "ab-ab-cc-dd-ee-ff-aa-bb");
		
		testCanonical("12CDCCddEefFAABb", "12-cd-cc-dd-ee-ff-aa-bb");
		testCanonical("12CDCCddEefF", "12-cd-cc-dd-ee-ff");
		
		testCanonical("0000000000000000", "00-00-00-00-00-00-00-00");
		testCanonical("000000000000", "00-00-00-00-00-00");
		
		testCanonical("0001000200030000", "00-01-00-02-00-03-00-00");
		testCanonical("000100020003", "00-01-00-02-00-03");

		testMatches(true, "0A0B0C0D0E0F", "0a0b0c-0d0e0f");
		testMatches(true, "0A0B0C0D0E0F", "0a:0b:0c:0d:0e:0f");
		testMatches(true, "0A 0B 0C 0D 0E 0F", "0a:0b:0c:0d:0e:0f");
		testMatches(true, "0A 0B 0C 0D 0E 0F", "0a-0b-0c-0d-0e-0f");
		testMatches(true, "0A 0B 0C 0D 0E 0F", "a-b-c-d-e-f");
		testMatches(false, "0A 0B 0C 0D 0E 0F", "a-b-c-d-e-f-a-b");
		
		testMatches(true, "0A0B.0C0D.0E0F", "0a:0b:0c:0d:0e:0f");
		testMatches(false, "0A0B.1C0D.0E0F", "0a:0b:0c:0d:0e:0f");
		testMatches(false, "0A0B.1C0D.0E0F", "aa:bb:0a:0b:0c:0d:0e:0f");

		testReverse("1:2:3:4:5:6", false, false);
		testReverse("1:1:2:2:3:3", false, false);
		testReverse("1:1:1:1:1:1", false, false);
		testReverse("0:0:0:0:0:0", true, true);
		
		testReverse("ff:ff:ff:ff:ff:ff", true, true);
		testReverse("ff:ff:ff:ff:ff:ff:ff:ff", true, true);

		testReverse("ff:80:ff:ff:01:ff", true, false);
		testReverse("ff:81:ff:ff:ff:ff", false, true);
		testReverse("ff:81:c3:42:24:ff", false, true);
		testReverse("ff:1:ff:ff:ff:ff", false, false);
		
		testReverse("11:22:33:44:55:66", false, false);
		testReverse("11:11:22:22:33:33", false, false);
		testReverse("11:11:22:22:33:33:44:55", false, false);
		testReverse("11:11:11:11:11:11:11:11", false, false);
		testReverse("0:0:0:0:0:0:00:00", true, true);
		
		testDelimitedCount("1,2-3-4,5-6-7-8", 4); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1,2-3,6-7-8-4,5-6,8", 16); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1:2:3:6:4:5", 1); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1:2,3,4:3:6:4:5,ff,7,8,99", 15); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		
		testLongShort("ff:ff:ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff");
		testLongShort("12-cd-cc-dd-ee-ff-aa-bb", "12-cd-cc-dd-ee-ff");
		testLongShort("12CD.CCdd.EefF.a", "12CD.EefF.a");
		testLongShort("0A0B0C-0D0E0F0A0B", "0A0B0C-0D0E0F");
		testLongShort("ee:ff:aa:bb:cc:dd:ee:ff", "ee:ff:aa:bb:cc:dd");
		testLongShort("e:f:a:b:c:d:e:f", "e:f:a:b:c:d");
		
		
		mactest(true, "0:0:0:0:0:0", true);
		mactest(true, "00:0:0:0:0:0", true);
		mactest(true, "0:00:0:0:0:0", true);
		mactest(true, "0:0:00:0:0:0", true);
		mactest(true, "0:0:0:00:0:0", true);
		mactest(true, "0:0:0:0:00:0", true);
		mactest(true, "0:0:0:0:0:00", true);
		mactest(isLenient(), "000:0:0:0:0:0", true);
		mactest(isLenient(), "0:000:0:0:0:0", true);
		mactest(isLenient(), "0:0:000:0:0:0", true);
		mactest(isLenient(), "0:0:0:000:0:0", true);
		mactest(isLenient(), "0:0:0:0:000:0", true);
		mactest(isLenient(), "0:0:0:0:0:000", true);
		mactest(isLenient(), "0:0:0:0:0:0:000:0", true);
		mactest(isLenient(), "0:0:0:0:0:0:0:000", true);
		mactest(isLenient(), "000:000:000:000", true);
		
		mactest(true, "00.0.0", true);
		mactest(true, "0.00.0", true);
		mactest(true, "0.0.00", true);
		mactest(true, "0.0.0.00", true);
		mactest(true, "000.0.0", true);
		mactest(true, "0.000.0", true);
		mactest(true, "0.00.000", true);
		mactest(true, "0000.0.0", true);
		mactest(true, "0.0000.0", true);
		mactest(true, "0.00.0000", true);
		mactest(isLenient(), "00000.0.0", true);
		mactest(isLenient(), "0.00000.0", true);
		mactest(isLenient(), "0.0.00000", true);
		mactest(isLenient(), "00000.00000.00000", true);
		mactest(isLenient(), "00000.00000.00000.00000", true);
		
		mactest(true, "3:3:3:3:3:3", false);
		mactest(true, "33:3:3:3:3:3", false);
		mactest(true, "3:33:3:3:3:3", false);
		mactest(true, "3:3:33:3:3:3", false);
		mactest(true, "3:3:3:33:3:3", false);
		mactest(true, "3:3:3:3:33:3", false);
		mactest(true, "3:3:3:3:3:33", false);
		mactest(isLenient(), "033:3:3:3:3:3", false);
		mactest(isLenient(), "3:033:3:3:3:3", false);
		mactest(isLenient(), "3:3:033:3:3:3", false);
		mactest(isLenient(), "3:3:3:033:3:3", false);
		mactest(isLenient(), "3:3:3:3:033:3", false);
		mactest(isLenient(), "3:3:3:3:3:033", false);
		mactest(isLenient(), "3:3:3:3:3:3:033:3", false);
		mactest(isLenient(), "3:3:3:3:3:3:3:033", false);
		mactest(isLenient(), "033:033:033:033", false);
		
		mactest(true, "33.3.3", false);
		mactest(true, "3.33.3", false);
		mactest(true, "3.3.33", false);
		mactest(true, "3.3.3.33", false);
		mactest(true, "333.3.3", false);
		mactest(true, "3.333.3", false);
		mactest(true, "3.33.333", false);
		mactest(true, "3333.3.3", false);
		mactest(true, "3.3333.3", false);
		mactest(true, "3.33.3333", false);
		mactest(isLenient(), "03333.3.3", false);
		mactest(isLenient(), "3.03333.3", false);
		mactest(isLenient(), "3.3.03333", false);
		mactest(isLenient(), "03333.03333.03333", false);
		mactest(isLenient(), "03333.03333.03333.03333", false);

		testMACIPv6("aaaa:bbbb:cccc:dddd:0221:2fff:feb5:6e10", "00:21:2f:b5:6e:10");
		testMACIPv6("fe80::0e3a:bbff:fe2a:cd23", "0c:3a:bb:2a:cd:23");
		testMACIPv6("ffff:ffff:ffff:ffff:3BA7:94FF:FE07:CBD0","39-A7-94-07-CB-D0");
		testMACIPv6("FE80::212:7FFF:FEEB:6B40","0012.7feb.6b40");
		testMACIPv6("2001:DB8::212:7FFF:FEEB:6B40","0012.7feb.6b40");

		testContains("1.2.3.4", "1.2.3.4", true);
		testContains("1111.2222.3333", "1111.2222.3333", true);
		testNotContains("1111.2222.3333", "1111.2222.3233");
		testContains("a:b:c:d:e:f:a:b", "a:b:c:d:e:f:a:b", true);

		testFromBytes(new byte[] {-1, -1, -1, -1, -1, -1}, "ff:ff:ff:ff:ff:ff");
		testFromBytes(new byte[] {1, 2, 3, 4, 5, 6}, "1:2:3:4:5:6");
		testFromBytes(new byte[] {0x12, 127, 0xf, 0x7f, 0x7a, 0x7b}, "12:7f:f:7f:7a:7b");
		testFromBytes(new byte[8], "0-0-0-0-0-0-0-0");
		testFromBytes(new byte[] {0, 0, 0, 1, 0, 0, 0, 1}, "0-0-0-1-0-0-0-1");
		testFromBytes(new byte[] {10, 11, 12, 13, 14, 15, 1, 2}, "a:b:c:d:e:f:1:2");

		testSections("00:21:2f:b5:6e:10");
		testSections("39-A7-94-07-CB-D0");
		testSections("0012.7feb.6b40");
		testSections("fe:ef:00:21:2f:b5:6e:10");
		testSections("fe-ef-39-A7-94-07-CB-D0");
		testSections("1234.0012.7feb.6b40");
		
		testRadices("11:10:ff:7f:f3:2", "10001:10000:11111111:1111111:11110011:10", 2);
		testRadices("2:fe:7f:ff:10:11", "10:11111110:1111111:11111111:10000:10001", 2);
		testRadices("5:10:5:10:5:10", "101:10000:101:10000:101:10000", 2);
		testRadices("0:1:0:1:0:1:0:1", "0:1:0:1:0:1:0:1", 2);
		testRadices("1:0:1:0:1:0:1:0", "1:0:1:0:1:0:1:0", 2);
		testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 2);
		testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 2);

		testRadices("ff:7f:fe:2:7f:fe", "ff:7f:fe:2:7f:fe", 16);
		testRadices("2:fe:7f:ff:7f:fe", "2:fe:7f:ff:7f:fe", 16);
		testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 16);
		testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 16);
		
		testRadices("ff:7f:fe:2:7f:fe", "255:127:254:2:127:254", 10);
		testRadices("2:fe:7f:ff:7f:fe", "2:254:127:255:127:254", 10);
		testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 10);
		testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 10);
		
		testRadices("ff:7f:fe:2:7f:fe", "513:241:512:2:241:512", 7);
		testRadices("2:fe:7f:ff:7f:fe", "2:512:241:513:241:512", 7);
		testRadices("0:1:0:1:0:1:0:1", "0:1:0:1:0:1:0:1", 7);
		testRadices("1:0:1:0:1:0:1:0", "1:0:1:0:1:0:1:0", 7);
		testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 7);
		testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 7);
		
		testRadices("ff:7f:fe:2:7f:fe", "377:177:376:2:177:376", 8);
		testRadices("2:fe:7f:ff:7f:fe", "2:376:177:377:177:376", 8);
		testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 8);
		testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 8);
		
		testRadices("ff:7f:fe:2:7f:fe", "120:87:11e:2:87:11e", 15);
		testRadices("2:fe:7f:ff:7f:fe", "2:11e:87:120:87:11e", 15);
		testRadices("0:1:0:1:0:1", "0:1:0:1:0:1", 15);
		testRadices("1:0:1:0:1:0", "1:0:1:0:1:0", 15);
		
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8", new Integer[9]);
		testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8");
		
		testStrings();
		
		testInvalidMACValues();

		testMACValues(new int[] {1, 2, 3, 4, 5, 6}, "1108152157446");
		testMACValues(new int[] {1, 2, 3, 4, 5, 6, 7, 8}, "72623859790382856");
		testMACValues(new int[8], "0");
		testMACValues(new int[6], "0");
		testMACValues(new int[] {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, String.valueOf(0xffffffffffffL));
		
		BigInteger thirtyTwo = BigInteger.valueOf(0xffffffffL);
		BigInteger sixty4 = thirtyTwo.shiftLeft(32).or(thirtyTwo);
		testMACValues(new int[] {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, sixty4.toString(), String.valueOf(-1));
		
		testIncrement("ff:ff:ff:ff:f0:0:0:0", 1, "ff:ff:ff:ff:f0:0:0:1");
		testIncrement("ff:ff:ff:ff:f0:0:0:0", -1, "ff:ff:ff:ff:ef:ff:ff:ff");
		testIncrement("ff:ff:f0:0:0:0", 1, "ff:ff:f0:0:0:1");
		testIncrement("ff:ff:f0:0:0:0", -1, "ff:ff:ef:ff:ff:ff");
	    
		testIncrement("80:0:0:0:0:0:0:0", Long.MIN_VALUE, "0:0:0:0:0:0:0:0");
		testIncrement("7f:ff:ff:ff:ff:ff:ff:ff", Long.MIN_VALUE, null);
		testIncrement("7f:ff:ff:ff:ff:ff:ff:fe", Long.MIN_VALUE, null);
		testIncrement("0:0:0:0:80:0:0:0", Long.MIN_VALUE, null);
		testIncrement("80:0:0:0:0:0:0:0", Long.MAX_VALUE, "ff:ff:ff:ff:ff:ff:ff:ff");
		testIncrement("80:0:0:0:0:0:0:1", Long.MAX_VALUE, null);

		testIncrement("ff:ff:ff:ff:80:0:0:0",-0x80000000L, "ff:ff:ff:ff:0:0:0:0");
		testIncrement("ff:ff:ff:ff:7f:ff:ff:ff", -0x80000000L, "ff:ff:ff:fe:ff:ff:ff:ff");
		testIncrement("ff:ff:ff:ff:7f:ff:ff:fe", -0x80000000L, "ff:ff:ff:fe:ff:ff:ff:fe");
		testIncrement("0:0:0:0:80:0:0:0", -0x80000000L, "0:0:0:0:0:0:0:0");
		testIncrement("0:0:0:0:7f:ff:ff:ff", -0x80000000L, null);
		testIncrement("0:0:0:0:7f:ff:ff:ff", -0x80000000L, null);
		testIncrement("0:0:0:0:7f:ff:ff:fe", -0x80000000L, null);
		testIncrement("ff:ff:ff:ff:80:0:0:0", 0x7fffffffL, "ff:ff:ff:ff:ff:ff:ff:ff");
		testIncrement("ff:ff:ff:ff:80:0:0:1", 0x7fffffffL, null);

		testIncrement("ff:ff:80:0:0:0",-0x80000000L, "ff:ff:0:0:0:0");
		testIncrement("ff:ff:7f:ff:ff:ff", -0x80000000L, "ff:fe:ff:ff:ff:ff");
		testIncrement("ff:ff:7f:ff:ff:fe", -0x80000000L, "ff:fe:ff:ff:ff:fe");
		testIncrement("0:0:80:0:0:0", -0x80000000L, "0:0:0:0:0:0");
		testIncrement("0:0:7f:ff:ff:ff", -0x80000000L, null);
		testIncrement("0:0:7f:ff:ff:ff", -0x80000000L, null);
		testIncrement("0:0:7f:ff:ff:fe", -0x80000000L, null);
		testIncrement("ff:ff:80:0:0:0", 0x7fffffffL, "ff:ff:ff:ff:ff:ff");
		testIncrement("ff:ff:80:0:0:1", 0x7fffffffL, null);

		testIncrement("0:0:0:0:0:0:0:1", 1, "0:0:0:0:0:0:0:2");
		testIncrement("0:0:0:0:0:0:0:1", 0, "0:0:0:0:0:0:0:1");
		testIncrement("0:0:0:0:0:0:0:1", -1, "0:0:0:0:0:0:0:0");
		testIncrement("0:0:0:0:0:0:0:1", -2, null);
		testIncrement("0:0:0:0:0:0:0:2", 1, "0:0:0:0:0:0:0:3");
		testIncrement("0:0:0:0:0:0:0:2", -1, "0:0:0:0:0:0:0:1");
		testIncrement("0:0:0:0:0:0:0:2", -2, "0:0:0:0:0:0:0:0");
		testIncrement("0:0:0:0:0:0:0:2", -3, null);
		
		testIncrement("0:0:0:0:0:1", 1, "0:0:0:0:0:2");
		testIncrement("0:0:0:0:0:1", 0, "0:0:0:0:0:1");
		testIncrement("0:0:0:0:0:1", -1, "0:0:0:0:0:0");
		testIncrement("0:0:0:0:0:1", -2, null);
		testIncrement("0:0:0:0:0:2", 1, "0:0:0:0:0:3");
		testIncrement("0:0:0:0:0:2", -1, "0:0:0:0:0:1");
		testIncrement("0:0:0:0:0:2", -2, "0:0:0:0:0:0");
		testIncrement("0:0:0:0:0:2", -3, null);

		testIncrement("1:0:0:0:0:0:0:1", 0, "1:0:0:0:0:0:0:1");
		testIncrement("1:0:0:0:0:0:0:1", 1, "1:0:0:0:0:0:0:2");
		testIncrement("1:0:0:0:0:0:0:1", -1, "1:0:0:0:0:0:0:0");
		testIncrement("1:0:0:0:0:0:0:1", -2, "0:ff:ff:ff:ff:ff:ff:ff");
		testIncrement("1:0:0:0:0:0:0:2", 1, "1:0:0:0:0:0:0:3");
		testIncrement("1:0:0:0:0:0:0:2", -1, "1:0:0:0:0:0:0:1");
		testIncrement("1:0:0:0:0:0:0:2", -2, "1:0:0:0:0:0:0:0");
		testIncrement("1:0:0:0:0:0:0:2", -3, "0:ff:ff:ff:ff:ff:ff:ff");
		
		testIncrement("1:0:0:0:0:1", 0, "1:0:0:0:0:1");
		testIncrement("1:0:0:0:0:1", 1, "1:0:0:0:0:2");
		testIncrement("1:0:0:0:0:1", -1, "1:0:0:0:0:0");
		testIncrement("1:0:0:0:0:1", -2, "0:ff:ff:ff:ff:ff");
		testIncrement("1:0:0:0:0:2", 1, "1:0:0:0:0:3");
		testIncrement("1:0:0:0:0:2", -1, "1:0:0:0:0:1");
		testIncrement("1:0:0:0:0:2", -2, "1:0:0:0:0:0");
		testIncrement("1:0:0:0:0:2", -3, "0:ff:ff:ff:ff:ff");
		
		testIncrement("0:0:0:0:0:0:0:fe", 2, "0:0:0:0:0:0:1:0");
		testIncrement("0:0:0:0:0:0:0:ff", 2, "0:0:0:0:0:0:1:1");
		testIncrement("0:0:0:0:0:0:1:ff", 2, "0:0:0:0:0:0:2:1");
		testIncrement("0:0:0:0:0:0:1:ff", -2, "0:0:0:0:0:0:1:fd");
		testIncrement("0:0:0:0:0:0:1:ff", -0x100, "0:0:0:0:0:0:0:ff");
		testIncrement("0:0:0:0:0:0:1:ff", -0x101, "0:0:0:0:0:0:0:fe");
		
		testIncrement("0:0:0:0:0:fe", 2, "0:0:0:0:1:0");
		testIncrement("0:0:0:0:0:ff", 2, "0:0:0:0:1:1");
		testIncrement("0:0:0:0:1:ff", 2, "0:0:0:0:2:1");
		testIncrement("0:0:0:0:1:ff", -2, "0:0:0:0:1:fd");
		testIncrement("0:0:0:0:1:ff", -0x100, "0:0:0:0:0:ff");
		testIncrement("0:0:0:0:1:ff", -0x101, "0:0:0:0:0:fe");
	}
}
