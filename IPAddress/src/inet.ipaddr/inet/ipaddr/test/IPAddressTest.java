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
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressNetwork.IPAddressCreator;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddressStringParameters.IPAddressStringFormatParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.large.IPAddressLargeDivision;
import inet.ipaddr.format.large.IPAddressLargeDivisionGrouping;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.sql.MySQLTranslator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringOptions;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSection.CompressOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.ipv6.IPv6AddressSegment;


public class IPAddressTest extends TestBase {

	IPAddressTest(AddressCreator creator) {
		super(creator);
	}

	void testResolved(String original, String expected) {
		IPAddressString origAddress = createAddress(original);
		IPAddress resolvedAddress = origAddress.isIPAddress() ? origAddress.getAddress() : createHost(original).getAddress();
		IPAddressString expectedAddress = createAddress(expected);
		boolean result = (resolvedAddress == null) ? (expected == null) : resolvedAddress.equals(expectedAddress.getAddress());
		if(!result) {
			addFailure(new Failure("resolved was " + resolvedAddress + " original was " + original, origAddress));
		}
		incrementTestCount();
	}
	
	void testNormalized(String original, String expected) {
		testNormalized(original, expected, false, true);
	}
	
	void testMask(String original, String mask, String expected) {
		IPAddressString w = createAddress(original);
		IPAddress orig = w.getAddress();
		IPAddressString maskString = createAddress(mask);
		IPAddress maskAddr = maskString.getAddress();
		IPAddress masked = orig.mask(maskAddr);
		IPAddressString expectedStr = createAddress(expected);
		IPAddress expectedAddr = expectedStr.getAddress();
		if(!masked.equals(expectedAddr)) {
			addFailure(new Failure("mask was " + mask + " and masked was " + masked, w));
		}
		incrementTestCount();
	}
	
	void testNormalized(String original, String expected, boolean keepMixed, boolean compress) {
		IPAddressString w = createAddress(original);
		String normalized;
		if(w.isIPv6()) {
			IPv6Address val = (IPv6Address) w.getAddress();
			IPv6StringOptions params;
			if(compress) {
				CompressOptions opts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST);
				params = new IPv6StringOptions.Builder().setCompressOptions(opts).toOptions();
			} else {
				params = new IPv6StringOptions.Builder().toOptions();
			}
			normalized = val.toNormalizedString(keepMixed, params);
			if(!normalized.equals(expected)) {
				addFailure(new Failure("normalization 1 was " + normalized, w));
			}
		} else if(w.isIPv4()) {
			IPv4Address val = (IPv4Address) w.getAddress();
			normalized = val.toNormalizedString();
			if(!normalized.equals(expected)) {
				addFailure(new Failure("normalization 2 was " + normalized, w));
			}
		} else {
			addFailure(new Failure("normalization failed on " + original, w));
		}
		incrementTestCount();
	}
	
	void testCompressed(String original, String expected) {
		IPAddressString w = createAddress(original);
		String normalized;
		if(w.isIPAddress()) {
			IPAddress val = w.getAddress();
			normalized = val.toCompressedString();
		} else {
			normalized = w.toString();
		}
		if(!normalized.equals(expected)) {
			addFailure(new Failure("canonical was " + normalized, w));
		}
		incrementTestCount();
	}
	
	void testCanonical(String original, String expected) {
		IPAddressString w = createAddress(original);
		IPAddress addr = w.getAddress();
		String normalized = addr.toCanonicalString();
		if(!normalized.equals(expected)) {
			addFailure(new Failure("canonical was " + normalized, w));
		}
		incrementTestCount();
	}
	
	void testMixed(String original, String expected) {
		testMixed(original, expected, expected);
	}
	
	void testMixed(String original, String expected, String expectedNoCompression) {
		IPAddressString w = createAddress(original);
		IPv6Address val = (IPv6Address) w.getAddress();
		String normalized = val.toMixedString();
		if(!normalized.equals(expected)) {
			addFailure(new Failure("mixed was " + normalized + " expected was " + expected, w));
		} else {
			CompressOptions opts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.NO);
			normalized = val.toNormalizedString(false, new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(opts).toOptions());
			if(!normalized.equals(expectedNoCompression)) {
				addFailure(new Failure("mixed was " + normalized + " expected was " + expectedNoCompression, w));
			}
		}
		incrementTestCount();
	}
	
	void testRadices(String original, String expected, int radix) {
		IPAddressString w = createAddress(original);
		IPAddress val = w.getAddress();
		IPStringOptions options = new IPv4StringOptions.Builder().setRadix(radix).toOptions();
		String normalized = val.toNormalizedString(options);
		if(!normalized.equals(expected)) {
			addFailure(new Failure("string was " + normalized + " expected was " + expected, w));
		}
		incrementTestCount();
	}
	
	void prefixtest(boolean pass, String x, boolean isZero) {
		IPAddressString addr = createAddress(x);
		if(prefixtest(pass, addr, isZero)) {
			//do it a second time to test the caching
			prefixtest(pass, addr, isZero);
		}
	}
	
	int evenOdd = 0;
	
	boolean prefixtest(boolean pass, IPAddressString addr, boolean isZero) {
		boolean failed = false;
		boolean isNotExpected;
		boolean oneWay = ((evenOdd & 1) == 0);
		if(oneWay) {
			isNotExpected = isNotExpectedForPrefix(pass, addr) || isNotExpectedForPrefixConversion(pass, addr);
		} else {
			isNotExpected = isNotExpectedForPrefixConversion(pass, addr) || isNotExpectedForPrefix(pass, addr);
		}
		evenOdd++;
		if(isNotExpected) {
			failed = true;
			addFailure(new Failure(pass, addr));
			
			//this part just for debugging
			if(isNotExpectedForPrefix(pass, addr)) {
				isNotExpectedForPrefix(pass, addr);
			} else {
				isNotExpectedForPrefixConversion(pass, addr);
			}
		} else {
			boolean zeroPass = pass && !isZero;

			if(isNotExpectedNonZeroPrefix(zeroPass, addr)) {
				failed = true;
				addFailure(new Failure(zeroPass, addr));
				
				//this part just for debugging
				//boolean val = isNotExpectedNonZeroPrefix(zeroPass, addr);
				//val = isNotExpectedNonZeroPrefix(zeroPass, addr);
			}
		} 
		incrementTestCount();
		return !failed;
	}
	
	boolean iptest(boolean pass, IPAddressString addr, boolean isZero, boolean notBothTheSame, boolean ipv4Test) {
		boolean failed = false;
		boolean pass2 = notBothTheSame ? !pass : pass;
		
		//notBoth means we validate as IPv4 or as IPv6, we don't validate as either one
		try {
			if(isNotExpected(pass, addr, ipv4Test, !ipv4Test) || isNotExpected(pass2, addr)) {
				failed = true;
				addFailure(new Failure(pass, addr));
				
				//this part just for debugging
				if(isNotExpected(pass, addr, ipv4Test, !ipv4Test)) {
					isNotExpected(pass, addr, ipv4Test, !ipv4Test);
				} else {
					isNotExpected(pass2, addr);
				}
			} else {
				boolean zeroPass;
				if(notBothTheSame) {
					zeroPass = !isZero;
				} else {
					zeroPass = pass && !isZero;
				}
				if(isNotExpectedNonZero(zeroPass, addr)) {
					failed = true;
					addFailure(new Failure(zeroPass, addr));
					
					//this part just for debugging
					//boolean val = isNotExpectedNonZero(zeroPass, addr);
					//val = isNotExpectedNonZero(zeroPass, addr);
				} else {
					//test the bytes
					if(pass && addr.toString().length() > 0 && addr.getAddress() != null && !(addr.getAddress().isIPv6() && addr.getAddress().toIPv6().hasZone()) && !addr.isPrefixed()) { //only for valid addresses
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

	boolean testBytes(IPAddress addr) {
		boolean failed = false;
		try {
			String addrString = addr.toString();
			int index = addrString.indexOf('/');
			if(index >= 0) {
				addrString = addrString.substring(0, index);
			}
			InetAddress inetAddress = InetAddress.getByName(addrString);
			byte[] b = inetAddress.getAddress();
			byte[] b2 = addr.getBytes();
			if(!Arrays.equals(b, b2)) {
				byte[] b3 = addr.isIPv4() ? addr.getSection().getBytes() : addr.toIPv6().toMappedIPv4Segments().getBytes();
				if(!Arrays.equals(b, b3)) {
					failed = true;
					addFailure(new Failure("bytes on addr " + inetAddress, addr));
				}
			}
		} catch(UnknownHostException e) {
			failed = true;
			addFailure(new Failure("bytes on addr " + e, addr));
		}
		return !failed;
	}
	
	void testMaskBytes(String cidr2, IPAddressString w2)
			throws AddressStringException {
		int index = cidr2.indexOf('/');
		if(index < 0) {
			index = cidr2.length();
		}
		IPAddressString w3 = createAddress(cidr2.substring(0, index));
		try {
			InetAddress inetAddress = null;
			inetAddress = InetAddress.getByName(w3.toString());//no wildcards allowed here
			byte[] b = inetAddress.getAddress();
			byte[] b2 = w3.toAddress().getBytes();
			if(!Arrays.equals(b, b2)) {
				addFailure(new Failure("bytes on addr " + inetAddress, w3));
			} else {
				byte b3[] = w2.toAddress().getBytes();
				if(!Arrays.equals(b3, b2)) {
					addFailure(new Failure("bytes on addr " + w3, w2));
				}
			}
		} catch(UnknownHostException e) {
			addFailure(new Failure("bytes on addr " + w3, w3));
		}
	}
	
	void testFromBytes(byte bytes[], String expected) {
		IPAddress addr = createAddress(bytes);
		IPAddressString addr2 = createAddress(expected);
		boolean result = addr.equals(addr2.getAddress());
		if(!result) {
			addFailure(new Failure("created was " + addr + " expected was " + addr2, addr));
		} else {
			if(addr.isIPv4()) {
				int val = 0;
				for(int i = 0; i < bytes.length; i++) {
					val <<= 8;
					val |= 0xff & bytes[i];
				}
				addr = createAddress(val);
				result = addr.equals(addr2.getAddress());
				if(!result) {
					addFailure(new Failure("created was " + addr + " expected was " + addr2, addr));
				}
			}
		}
		incrementTestCount();
	}
	
	private byte[][][] createSets(byte bytes[], int segmentByteSize) {
		//break into two, and three
		int segmentLength = bytes.length / segmentByteSize;
		byte sets[][][] = {
				{
					new byte[(segmentLength / 2) * segmentByteSize], new byte[(segmentLength - segmentLength / 2) * segmentByteSize]
				},
				{
					new byte[(segmentLength / 3) * segmentByteSize], new byte[(segmentLength / 3) * segmentByteSize], new byte[(segmentLength - 2 * (segmentLength / 3)) * segmentByteSize]
				}
		};
		for(byte set[][] : sets) {
			for(int i = 0, ind = 0; i < set.length; i++) {
				byte part[] = set[i];
				System.arraycopy(bytes, ind, part, 0, part.length);
				ind += part.length;
			}
		}
		return sets;
	}
	
	void testSplitBytes(String addressStr) {
		IPAddress addr = createAddress(addressStr).getAddress();
		testSplitBytes(addr);
	}
	
	void testSplitBytes(IPAddress addr) {
		byte bytes[] = addr.getBytes();
		List<IPAddress> addresses = reconstitute(addr, bytes, addr.getBytesPerSegment());
		if(addr.isMultiple()) {
			for(IPAddress addrNext : addresses) {
				if(!addr.getLower().equals(addrNext)) {
					addFailure(new Failure("lower reconstitute failure: " + addrNext, addr));
				}
			}
			bytes = addr.getUpperBytes();
			addresses = reconstitute(addr, bytes, addr.getBytesPerSegment());
			for(IPAddress addrNext : addresses) {
				if(!addr.getUpper().equals(addrNext)) {
					addFailure(new Failure("upper reconstitute failure: " + addrNext, addr));
				}
			}
		} else {
			for(IPAddress addrNext : addresses) {
				if(!addr.equals(addrNext)) {
					addFailure(new Failure("reconstitute failure: " + addrNext, addr));
				}
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	<S extends IPAddressSegment> List<IPAddress> reconstitute(IPAddress originalAddress, byte bytes[], int segmentByteSize) {
		IPAddressCreator<?, ?, ?, S, ?> creator = (IPAddressCreator<?, ?, ?, S, ?>) originalAddress.getNetwork().getAddressCreator();
		ArrayList<IPAddress> addresses = new ArrayList<IPAddress>();
		byte sets[][][] = createSets(bytes, segmentByteSize);
		for(byte set[][] : sets) {
			ArrayList<S> segments = new ArrayList<S>();
			ArrayList<S> segments2 = new ArrayList<S>();
			for(int i = 0, ind = 0; i < set.length; i++) {
				byte setBytes[] = set[i];
				S[] segs = (S[]) creator.createSection(setBytes, null).getSegments();
				S[] segs2 = (S[]) creator.createSection(bytes, ind, ind + setBytes.length, null).getSegments();
				S[] one, two;
				if(i % 2 == 0) {
					one = segs;
					two = segs2;
				} else {
					one = segs2;
					two = segs;
				}
				ind += setBytes.length;
				segments.addAll(Arrays.asList(one));
				segments2.addAll(Arrays.asList(two));
			}
			S segs[] = creator.createSegmentArray(segments.size());
			IPAddress addr1 = creator.createAddress(segments.toArray(segs));
			IPAddress addr2 = creator.createAddress(segments2.toArray(segs));
			addresses.add(addr1);
			addresses.add(addr2);
		}
		return addresses;
	}

	boolean isNotExpected(boolean expectedPass, IPAddressString addr) {
		return isNotExpected(expectedPass, addr, false, false);
	}
	
	boolean isNotExpected(boolean expectedPass, IPAddressString addr, boolean isIPv4, boolean isIPv6) {
		try {
			if(isIPv4) {
				addr.validateIPv4();
				addr.toAddress(IPVersion.IPV4);
			} else if(isIPv6) {
				addr.validateIPv6();
				addr.toAddress(IPVersion.IPV6);
			} else {
				addr.validate();
			}
			return !expectedPass;
		} catch(AddressStringException e) {
			return expectedPass;
		}
	}
	
	boolean isNotExpectedForPrefix(boolean expectedPass, IPAddressString addr) {
		try {
			addr.validate();
			return !expectedPass;
		} catch(AddressStringException e) {
			return expectedPass;
		}
	}
	
	public String convertToMask(IPAddressString str, IPVersion version) throws AddressStringException {
		IPAddress address =str.toAddress(version);
		if(address != null) {
			return address.toNormalizedString();
		}
		return null;
	}
	
	boolean isNotExpectedForPrefixConversion(boolean expectedPass, IPAddressString addr) {
		try {
			IPAddress ip1 = addr.toAddress(IPVersion.IPV6);
			String str1 = convertToMask(addr, IPVersion.IPV6);
			if(ip1 == null || !ip1.isIPv6() || str1 == null) {
				return expectedPass;
			}
			Integer integ = ip1.getNetworkPrefixLength();
			if(integ != null && integ.intValue() > 32 && expectedPass) {
				expectedPass = false;
			}
			IPAddress ip2 = addr.toAddress(IPVersion.IPV4);
			String str2 = convertToMask(addr, IPVersion.IPV4);
			if(ip2 == null || !ip2.isIPv4() || str2 == null) {
				return expectedPass;
			}
			return !expectedPass;
		} catch(AddressStringException | PrefixLenException e) {
			return expectedPass;
		}
	}
	
	boolean isNotExpectedNonZero(boolean expectedPass, IPAddressString addr) {
		if(!addr.isIPAddress() && !addr.isPrefixOnly() && !addr.isAllAddresses()) {
			return expectedPass;
		}
		//if expectedPass is true, we are expecting a non-zero address
		//return true to indicate we have gotten something not expected
		if(addr.getAddress() != null && addr.getAddress().isZero()) {
			return expectedPass;
		}
		return !expectedPass;
	}
	
	boolean isNotExpectedNonZeroPrefix(boolean expectedPass, IPAddressString addr) {
		if(!addr.isPrefixOnly()) {
			if(!addr.isValid()) {
				return expectedPass;
			}
			if(addr.getNetworkPrefixLength() <= IPv4Address.BIT_COUNT) {
				return expectedPass;
			}
		}
		//if expectedPass is true, we are expecting a non-zero address
		//return true to indicate we have gotten something not expected
		if(addr.getAddress() != null && addr.getAddress().isZero()) {
			return expectedPass;
		}
		return !expectedPass;
	}
	
	void ipv4testOnly(boolean pass, String x) {
		iptest(pass, createAddress(x), false, true, true);
	}
	
	void ipv4test(boolean pass, String x) {
		ipv4test(pass, x, false);
	}
	
	void ipv4_inet_aton_test(boolean pass, String x) {
		ipv4_inet_aton_test(pass, x, false);
	}
	
	void ipv4_inet_aton_test(boolean pass, String x, boolean isZero) {
		IPAddressString addr = createInetAtonAddress(x);
		ipv4test(pass, addr, isZero);
	}
	
	void ipv4test(boolean pass, String x, boolean isZero) {
		iptest(pass, createAddress(x), isZero, false, true);
	}
	
	void ipv4test(boolean pass, IPAddressString x, boolean isZero) {
		iptest(pass, x, isZero, false, true);
	}
	
	void ipv4test(boolean pass, String x, boolean isZero, boolean notBothTheSame) {
		iptest(pass, createAddress(x), isZero, notBothTheSame, true);
	}
	
	void ipv4test(boolean pass, IPAddressString x, boolean isZero, boolean notBothTheSame) {
		iptest(pass, x, isZero, notBothTheSame, true);
	}
	
	void ipv6testOnly(int pass, String x) {
		iptest(pass == 0 ? false : true, createAddress(x), false, true, false);
	}
	
	void ipv6testWithZone(int pass, String x) {//only here so subclass can override
		ipv6test(pass, x);
	}
	
	void ipv6test(int pass, String x) {
		ipv6test(pass == 0 ? false : true, x);
	}
	
	void ipv6testWithZone(boolean pass, String x) {
		ipv6test(pass, x);
	}
	
	void prefixtest(boolean pass, String x) {
		prefixtest(pass, x, false);
	}
	
	void ipv6test(boolean pass, String x) {
		ipv6test(pass, x, false);
	}
	
	void ipv6test(int pass, String x, boolean isZero) {
		ipv6test(pass == 0 ? false : true, x, isZero);
	}
	
	void ipv6test(boolean pass, String x, boolean isZero) {
		iptest(pass, createAddress(x), isZero, false, false);
	}
	
	void ipv6test(boolean pass, String x, boolean isZero, boolean notBothTheSame) {
		iptest(pass, createAddress(x), isZero, notBothTheSame, false);
	}
	
	/**
	 * Returns just a few string representations:
	 * 
	 * <ul>
	 * <li>either compressed or not - when compressing it uses the canonical string representation or it compresses the leftmost zero-segment if the canonical representation has no compression.
	 * <li>either lower or upper case
	 * <li>combinations thereof
	 * </ul>
	 * 
	 * So the maximum number of strings returned for IPv6 is 4, while for IPv4 it is 1.
	 * 
	 * @return
	 */
	String[] getBasicStrings(IPAddress addr) {
		IPStringBuilderOptions opts;
		if(addr.isIPv6()) {
			opts = new IPv6StringBuilderOptions(
					IPStringBuilderOptions.BASIC | 
					IPv6StringBuilderOptions.UPPERCASE | 
					IPv6StringBuilderOptions.COMPRESSION_SINGLE);
		} else {
			opts = new IPStringBuilderOptions();
		}
		return addr.toStrings(opts);
	}
	
	void testVariantCounts(String addr, int expectedPartCount, int expectedBasic, int expectedStandard, int expectedAll, int expectedAllNoConverted, int expectedAllNoOctalHex) {
		IPAddressString address = createAddress(addr);
		IPAddress ad = address.getAddress();
		String basicStrs[] = getBasicStrings(ad);
		testStrings(basicStrs, expectedBasic, address);
		IPAddressPartStringCollection standardCollection = ad.toStandardStringCollection(); 
		String standardStrs[] = standardCollection.toStrings();
		testStrings(standardStrs, expectedStandard, address);
		
		IPAddressStringDivisionSeries parts[] = ad.getParts(ad.isIPv6() ? IPv6StringBuilderOptions.ALL_OPTS : IPv4StringBuilderOptions.ALL_OPTS);
		if(parts.length != expectedPartCount) {
			addFailure(new Failure("Part count " + parts.length + " does not match expected " + expectedPartCount, ad));
		}
		incrementTestCount();
		try {
			IPv4StringBuilderOptions convertIPv6Opts = new IPv4StringBuilderOptions(IPv4StringBuilderOptions.IPV6_CONVERSIONS);
			IPv6StringBuilderOptions convertIPv4Opts = new IPv6StringBuilderOptions(IPv6StringBuilderOptions.IPV4_CONVERSIONS);
			if(ad.isIPv4()) {
				IPAddressStringDivisionSeries partsConverted[] = ad.getParts(convertIPv6Opts);
				if(partsConverted.length == 0) {
					addFailure(new Failure("converted count does not match expected", ad));
				} else {
					IPv6AddressSection converted = (IPv6AddressSection) partsConverted[0];
					partsConverted = new IPv6Address(converted).getParts(convertIPv4Opts);
					IPv4AddressSection convertedBack = (IPv4AddressSection) partsConverted[0];
					if(!ad.getSection().equals(convertedBack)) {
						addFailure(new Failure("converted " + convertedBack + " does not match expected", ad));
					}
				}
			} else {
				if(ad.isIPv4Convertible()) {
					IPAddressStringDivisionSeries partsConverted[] = ad.getParts(convertIPv4Opts);
					if(partsConverted.length == 0) {
						addFailure(new Failure("converted count does not match expected", ad));
					} else {
						IPv4AddressSection converted = (IPv4AddressSection) partsConverted[0];
						partsConverted = new IPv4Address(converted).getParts(convertIPv6Opts);
						IPv6AddressSection convertedBack = (IPv6AddressSection) partsConverted[0];
						if(!ad.getSection().equals(convertedBack)) {
							addFailure(new Failure("converted " + convertedBack + " does not match expected", ad));
						}
					}
				} else {
					IPAddressStringDivisionSeries partsConverted[] = ad.getParts(convertIPv4Opts);
					if(partsConverted.length > 0) {
						addFailure(new Failure("converted count does not match expected", ad));
					}
				}
			}
		} catch(RuntimeException e) {
			addFailure(new Failure(e.toString()));
		}
		incrementTestCount();
		
		if(fullTest || expectedAll < 100) {
			IPAddressPartStringCollection allCollection = ad.toAllStringCollection();
			IPAddressStringDivisionSeries collParts[] = allCollection.getParts(new IPAddressStringDivisionSeries[allCollection.getPartCount()]);
			if(!new HashSet<IPAddressStringDivisionSeries>(Arrays.asList(parts)).equals(new HashSet<IPAddressStringDivisionSeries>(Arrays.asList(collParts)))) {
				addFailure(new Failure("Parts " + Arrays.asList(parts) + " and collection parts " + Arrays.asList(collParts) + " not the same ", ad));
			} else {
				incrementTestCount();
			}
			String allStrs[] = allCollection.toStrings();
			testStrings(allStrs, expectedAll, address);
		}
		if(fullTest || expectedAllNoConverted < 100) {
			String allStrs[];
			IPStringBuilderOptions opts;
			if(address.isIPv4()) {
				opts = new IPv4StringBuilderOptions(IPv4StringBuilderOptions.ALL_OPTS.options & ~IPv4StringBuilderOptions.IPV6_CONVERSIONS);
			} else {
				opts = new IPv6StringBuilderOptions(IPv6StringBuilderOptions.ALL_OPTS.options & ~IPv6StringBuilderOptions.IPV4_CONVERSIONS, IPv6StringBuilderOptions.ALL_OPTS.mixedOptions);
			}
			allStrs = address.getAddress().toStrings(opts);
			testStrings(allStrs, expectedAllNoConverted, address);
		}
		if(fullTest || expectedAllNoOctalHex < 100) {
			if(address.isIPv4()) {
				String allStrs[] = address.getAddress().toStrings(new IPv4StringBuilderOptions(
						IPv4StringBuilderOptions.ALL_OPTS.options & 
						~(IPv4StringBuilderOptions.IPV6_CONVERSIONS | 
						IPv4StringBuilderOptions.ALL_JOINS | 
						IPv4StringBuilderOptions.HEX  | 
						IPv4StringBuilderOptions.OCTAL)));
				testStrings(allStrs, expectedAllNoOctalHex, address);
			}
		}
	}
	
	void testVariantCounts(String addr, int expectedPartCount, int expectedBasic, int expectedStandard, int expectedAll, int expectedAllNoConverted) {
		testVariantCounts(addr, expectedPartCount, expectedBasic, expectedStandard, expectedAll, expectedAllNoConverted, expectedAllNoConverted);
	}
	
	void testVariantCounts(String addr, int expectedPartCount, int expectedBasic, int expectedStandard, int expectedAll) {
		testVariantCounts(addr, expectedPartCount, expectedBasic, expectedStandard, expectedAll, expectedAll);
	}

	private void testStrings(String[] strs, int expectedCount, IPAddressString addr) {
		testStrings(strs, expectedCount, addr, false);
	}
	
	private void testStrings(String[] strs, int expectedCount, IPAddressString addr, boolean writeList) {
		if(writeList) {
			listVariants(strs);
		}
		if(expectedCount != strs.length) {
			addFailure(new Failure("String count " + strs.length + " doesn't match expected count " + expectedCount, addr));
			incrementTestCount();
		}
		Set<String> set = new HashSet<String>();
		Collections.addAll(set, strs);
		if(set.size() != strs.length) {
			addFailure(new Failure((strs.length - set.size()) + " duplicates for " + addr, addr));
			set.clear();
			for(String str: strs) {
				if(set.contains(str)) {
					System.out.println("dup " + str);
				}
				set.add(str);
			}
		} else for(String str: strs) {
			if(str.length() > 45) {
				addFailure(new Failure("excessive length " + str + " for " + addr, addr));
				break;
			}
		}
		incrementTestCount();
	}
	
	private void listVariants(String[] strs) {
		System.out.println("list count is " + strs.length);
		for(String str: strs) {
			System.out.println(str);
		}
		System.out.println();
	}
	
	private boolean checkNotMask(IPAddress address, boolean network) {
		Integer maskPrefix = address.getBlockMaskPrefixLength(network);
		Integer otherMaskPrefix = address.getBlockMaskPrefixLength(!network);
		if(maskPrefix != null || otherMaskPrefix != null) {
			addFailure(new Failure("failed not mask", address));
			return false;
		}
		incrementTestCount();
		return true;
	}
	
	private void checkNotMask(String addr) {
		IPAddressString addressStr = createAddress(addr);
		IPAddress address = addressStr.getAddress();
		boolean val = ((address.getBytes()[0] & 1) == 0);
		if(checkNotMask(address, val)) {
			checkNotMask(address, !val);
		}
	}
	
	boolean secondTry;
	
	private boolean checkMask(IPAddress address, int prefixBits, boolean network) {
		Integer maskPrefix = address.getBlockMaskPrefixLength(network);
		Integer otherMaskPrefix = address.getBlockMaskPrefixLength(!network);
		if(maskPrefix != Math.min(prefixBits, address.getBitCount()) || otherMaskPrefix != null) {
			addFailure(new Failure("failed mask", address));
			return false;
		}
		if(network) {
			try {
				String originalPrefixStr = "/" + prefixBits;
				String originalChoppedStr = prefixBits <= address.getBitCount() ? originalPrefixStr : "/" + address.getBitCount();
				IPAddressString prefix = createAddress(originalPrefixStr);
				String maskStr = convertToMask(prefix, address.getIPVersion());
				
				String prefixExtra = originalPrefixStr;
				IPAddress addressWithNoPrefix;
				if(address.isPrefixed()){
					addressWithNoPrefix = address.mask(address.getNetwork().getNetworkMask(address.getNetworkPrefixLength()));
				} else {
					addressWithNoPrefix = address;
				}
				String ipForNormalizeMask = addressWithNoPrefix.toString();
				String maskStrx2 = normalizeMask(originalPrefixStr, ipForNormalizeMask) + prefixExtra;
				String maskStrx3 = normalizeMask("" + prefixBits, ipForNormalizeMask) + prefixExtra;
				String normalStr = address.toNormalizedString();
				if(!maskStr.equals(normalStr) || !maskStrx2.equals(normalStr) || !maskStrx3.equals(normalStr)) {
					addFailure(new Failure("failed prefix conversion " + maskStr, prefix));
					return false;
				} else {
					IPAddressString maskStr2 = createAddress(maskStr);
					String prefixStr = maskStr2.convertToPrefixLength();
					if(prefixStr == null || !prefixStr.equals(originalChoppedStr)) {
						maskStr2 = createAddress(maskStr);
						maskStr2.convertToPrefixLength();
						addFailure(new Failure("failed mask converstion " + prefixStr, maskStr2));
						return false;
					}
				}
			} catch(AddressStringException | RuntimeException e) {
				addFailure(new Failure("failed conversion: " + e.getMessage(), address));
				return false;
			}
		}
		
		incrementTestCount();
		if(!secondTry) {
			secondTry = true;
			byte bytes[] = address.getBytes();
			IPAddressStringFormatParameters params = address.isIPv4() ? ADDRESS_OPTIONS.getIPv4Parameters() : ADDRESS_OPTIONS.getIPv6Parameters();
			IPAddressNetwork<?, ?, ?, ?, ?> addressNetwork = params.getNetwork();
			IPAddressCreator<?, ?, ?, ?, ?> creator = addressNetwork.getAddressCreator();
			IPAddress another = network ? creator.createAddress(bytes, prefixBits) : creator.createAddress(bytes);
			
			boolean result = checkMask(another, prefixBits, network);
			secondTry = false;
			
			//now check the prefix in the mask
			if(result) {
				boolean prefixBitsMismatch = false;
				Integer addrPrefixBits = address.getNetworkPrefixLength();
				if(!network) {
					prefixBitsMismatch = addrPrefixBits != null;
				} else {
					prefixBitsMismatch = addrPrefixBits == null || (prefixBits != addrPrefixBits);
				}
				if(prefixBitsMismatch) {
					addFailure(new Failure("prefix incorrect", address));
					return false;
				}
			}
		}
		return true;
	}
	
	public static String normalizeMask(String maskString, String ipString) {
		if(ipString != null && ipString.trim().length() > 0 && maskString != null && maskString.trim().length() > 0) {
			maskString = maskString.trim();
			if(maskString.startsWith("/")) {
				maskString = maskString.substring(1);
			}
			IPAddressString addressString = new IPAddressString(ipString);
			if(addressString.isIPAddress()) {
				try {
					IPVersion version = addressString.getIPVersion();
					int prefix = IPAddressString.validateNetworkPrefixLength(version, maskString);
					IPAddress maskAddress = addressString.getAddress().getNetwork().getNetworkMask(prefix, false);
					return maskAddress.toNormalizedString();
				} catch(PrefixLenException e) {
					//if validation vails, fall through and return mask string
				}
			}
		}
		//Note that here I could normalize the mask to be a full one with an else
		return maskString;
	}
	
	void testMasksAndPrefixes() {
		for(int i = 0; i <= 128; i++) {
			IPv6AddressNetwork network = ADDRESS_OPTIONS.getIPv6Parameters().getNetwork();
			IPv6Address ipv6HostMask = network.getHostMask(i);
			if(checkMask(ipv6HostMask, i, false)) {
				IPv6Address ipv6NetworkMask = network.getNetworkMask(i);
				if(checkMask(ipv6NetworkMask, i, true)) {
					if(i <= 32) {
						IPv4AddressNetwork ipv4network = ADDRESS_OPTIONS.getIPv4Parameters().getNetwork();
						IPv4Address ipv4HostMask = ipv4network.getHostMask(i);
						if(checkMask(ipv4HostMask, i, false)) {
							IPv4Address ipv4NetworkMask = ipv4network.getNetworkMask(i);
							checkMask(ipv4NetworkMask, i, true);		
						}
					}
				}
			}
		}
	}
	
	void testCIDRSubnets(String cidr1, String normalizedString) {
		testCIDRSubnets(cidr1, normalizedString, true);
	}
	
	void testCIDRSubnets(String cidr1, String normalizedString, boolean testString) {
		IPAddressString w = createAddress(cidr1);
		IPAddressString w2 = createAddress(normalizedString);
		try {
			boolean first = w.equals(w2);
			IPAddress v = w.toAddress();
			IPAddress v2 = w2.toAddress();
			boolean second = v.equals(v2);
			if(!first || !second) {
				addFailure(new Failure("failed " + w2, w));
			} else {
				String str = v2.toNormalizedString();
				if(!normalizedString.equals(str)) {
					addFailure(new Failure("failed " + str, w2));
				} else {
					testMaskBytes(normalizedString, w2);
				}
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + w2, w));
		}
		incrementTestCount();
	}
	
	static boolean conversionContains(IPAddress h1, IPAddress h2) {
		if(h1.isIPv4()) {
			if(!h2.isIPv4()) {
				if(h2.isIPv4Convertible()) {
					return h1.contains(h2.toIPv4());
				}
			}
		} else if(h1.isIPv6()) {
			if(!h2.isIPv6()) {
				if(h2.isIPv6Convertible()) {
					return h1.contains(h2.toIPv6());
				}
			}
		}
		return false;
	}
	
	void testContains(String cidr1, String cidr2, boolean equal) {
		testContains(cidr1, cidr2, true, equal);
	}
	
	void testContains(String cidr1, String cidr2, boolean result, boolean equal) {
		try {
			IPAddressString wstr = createAddress(cidr1);
			IPAddressString w2str = createAddress(cidr2);
			IPAddress w = wstr.toAddress();
			IPAddress w2 = w2str.toAddress();
			boolean firstContains;
			boolean convCont = false;
			if(!(firstContains = w.contains(w2)) && !(convCont = conversionContains(w, w2))) {
				if(result) {
					addFailure(new Failure("containment failed " + w2, w));
				}
			} else {
				if(!result && firstContains) {
					addFailure(new Failure("containment passed " + w2, w));
				} else if(!result) {
					addFailure(new Failure("conv containment passed " + w2, w));
				} else if(equal ? !(w2.contains(w) || conversionContains(w2, w)) : (w2.contains(w) || conversionContains(w2, w))) {
					addFailure(new Failure("failed " + w, w2));
				}
			}
			if(!convCont) {
				testStringContains(result, equal, wstr, w2str);
				//compare again, this tests the string-based optimization (which is skipped if we validated already)
				testStringContains(result, equal, createAddress(cidr1), createAddress(cidr2));
				
			}
			boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
			if(allPrefixesAreSubnets) {
				wstr = createAddress(cidr1);
				w2str = createAddress(cidr2);
				boolean prefixMatches = wstr.prefixEquals(w2str);
				if(prefixMatches && !result) {
					addFailure(new Failure("expected containment due to same prefix 1" + w2, w));
				}
				wstr.isValid();
				w2str.isValid();
				prefixMatches = wstr.prefixEquals(w2str);
				if(prefixMatches && !result) {
					addFailure(new Failure("expected containment due to same prefix 2" + w2, w));
				}
				w = wstr.toAddress();
				w2 = w2str.toAddress();
				prefixMatches = wstr.prefixEquals(w2str);
				if(prefixMatches && !result) {
					addFailure(new Failure("expected containment due to same prefix 3 " + w2, w));
				}
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + e));
		}
		incrementTestCount();
	}

	protected void testStringContains(boolean result, boolean equal, IPAddressString wstr, IPAddressString w2str) {
		if(!wstr.contains(w2str)) {
			if(result) {
				addFailure(new Failure("containment failed " + w2str, wstr));
			}
		} else {
			if(!result) {
				addFailure(new Failure("containment passed " + w2str, wstr));
			} else if(equal ? !w2str.contains(wstr) : w2str.contains(wstr)) {
				addFailure(new Failure("failed " + wstr, w2str));
			}
		}
	}
	
	void testNotContains(String cidr1, String cidr2) {
		testNotContains(cidr1, cidr2, false);
	}
	
	void testNotContains(String cidr1, String cidr2, boolean skipReverse) {
		try {
			IPAddress w = createAddress(cidr1).toAddress();
			IPAddress w2 = createAddress(cidr2).toAddress();
			if(w.contains(w2)) {
				addFailure(new Failure("failed " + w2, w));
			} else if(!skipReverse && w2.contains(w)) {
				addFailure(new Failure("failed " + w, w2));
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + e));
		}
		testContains(cidr1, cidr2, false, false);
		incrementTestCount();
	}
	
	void printStrings(IPAddressSection section) {
		String strs[] = section.toStandardStringCollection().toStrings();
		int count = 0;
		System.out.println("listing strings for " + section);
		for(String str: strs) {
			System.out.println("\t" + ++count + ": " + str);
		}
		
	}

	void testSplit(String address, int bits, String network, String networkNoRange, String networkWithPrefix, int networkStringCount, String host, int hostStringCount) {
		try {
			IPAddressString w = createAddress(address);
			IPAddress v = w.getAddress();
			IPAddressSection section = v.getNetworkSection(bits, false);
			String sectionStr = section.toNormalizedString();
			//printStrings(section);
			if(!sectionStr.equals(network)) {
				addFailure(new Failure("failed got " + sectionStr + " expected " + network, w));
			} else {
				IPAddressSection sectionWithPrefix = v.getNetworkSection(bits);
				String sectionStrWithPrefix = sectionWithPrefix.toNormalizedString();
				if(!sectionStrWithPrefix.equals(networkWithPrefix)) {
					addFailure(new Failure("failed got " + sectionStrWithPrefix + " expected " + networkWithPrefix, w));
				} else {
					IPAddressSection s = section.isPrefixed() ? section.removePrefixLength() : section.getLower();
					String sectionStrNoRange = s.toNormalizedString();
					if(!sectionStrNoRange.equals(networkNoRange) || s.getCount().intValue() != 1) {
						addFailure(new Failure("failed got " + sectionStrNoRange + " expected " + networkNoRange, w));
					} else {
						IPAddressPartStringCollection coll = sectionWithPrefix.toStandardStringCollection();
						String standards[] = coll.toStrings();
						if(standards.length != networkStringCount) {
							addFailure(new Failure("failed " + section + " expected count " + networkStringCount + " was " + standards.length, w));
						} else {
							section = v.getHostSection(bits);
							//printStrings(section);
							sectionStr = section.toNormalizedString();
							if(!sectionStr.equals(host)) {
								addFailure(new Failure("failed " + section + " expected " + host, w));
							} else {
								String standardStrs[] = section.toStandardStringCollection().toStrings();
								if(standardStrs.length != hostStringCount) {
									addFailure(new Failure("failed " + section + " expected count " + hostStringCount + " was " + standardStrs.length, w));
									//standardStrs = section.toStandardStringCollection().toStrings();
								}
							}
						}
					}
				}
			}
		} catch(RuntimeException e) {
			addFailure(new Failure("unexpected throw: " + e));
		}
		incrementTestCount();
	}
	
	private static boolean isSameAllAround(IPAddress supplied, IPAddress internal) {
		return 
				supplied.equals(internal)
				&& internal.equals(supplied)
				&& Objects.equals(internal.getNetworkPrefixLength(), supplied.getNetworkPrefixLength())
				&& internal.getMinPrefixLengthForBlock() == supplied.getMinPrefixLengthForBlock()
				&& Objects.equals(internal.getPrefixLengthForSingleBlock(), supplied.getPrefixLengthForSingleBlock())
				&& internal.getCount().equals(supplied.getCount());
	}
	
	void testNetmasks(int prefix, String ipv4NetworkAddress, String ipv4NetworkAddressNoPrefix, String ipv4HostAddress, String ipv6NetworkAddress, String ipv6NetworkAddressNoPrefix, String ipv6HostAddress) {
		IPAddressString ipv6Addr = createAddress(ipv6NetworkAddress);
		IPAddressString ipv4Addr = createAddress(ipv4NetworkAddress);
		if (prefix <= IPv6Address.BIT_COUNT) {
			IPAddressString w2NoPrefix = createAddress(ipv6NetworkAddressNoPrefix);
			try {
				//these calls should not throw
				IPAddressString.validateNetworkPrefixLength(IPVersion.IPV6, "" + prefix);
				IPAddress ipv6AddrValue = ipv6Addr.toAddress();
				IPAddressNetwork<?, ?, ?, ?, ?> ipv6network = ipv6AddrValue.getNetwork();
				IPAddress addr6 = ipv6network.getNetworkMask(prefix);
				IPAddress addr6NoPrefix = ipv6network.getNetworkMask(prefix, false);
				IPAddress w2ValueNoPrefix = w2NoPrefix.toAddress();
				boolean one;
				if((one = !isSameAllAround(ipv6AddrValue, addr6)) || !isSameAllAround(w2ValueNoPrefix, addr6NoPrefix)) {
					one = !isSameAllAround(ipv6AddrValue, addr6);//min prefix is 0 vs 128
					isSameAllAround(w2ValueNoPrefix, addr6NoPrefix);
					addFailure(one ? new Failure("failed " + addr6, ipv6AddrValue) : new Failure("failed " + addr6NoPrefix, w2ValueNoPrefix));
				} else {
					addr6 = ipv6network.getHostMask(prefix);
					ipv6Addr = createAddress(ipv6HostAddress);
					try {
						ipv6AddrValue = ipv6Addr.toAddress();
						if(!isSameAllAround(ipv6AddrValue, addr6)) {
							addFailure(new Failure("failed " + addr6, ipv6Addr));
						} else if (prefix <= IPv4Address.BIT_COUNT) {
							IPAddressString wNoPrefix = createAddress(ipv4NetworkAddressNoPrefix);
							try {
								IPAddressString.validateNetworkPrefixLength(IPVersion.IPV4, "" + prefix);
								IPAddress wValue = ipv4Addr.toAddress();
								IPAddressNetwork<?, ?, ?, ?, ?> ipv4network = wValue.getNetwork();
								IPAddress addr4 = ipv4network.getNetworkMask(prefix);
								IPAddress addr4NoPrefix = ipv4network.getNetworkMask(prefix, false);
								IPAddress wValueNoPrefix = wNoPrefix.toAddress();
								if((one = !isSameAllAround(wValue, addr4)) || !isSameAllAround(wValueNoPrefix, addr4NoPrefix)) {
									addFailure(one ? new Failure("failed " + addr4, wValue) : new Failure("failed " + addr4NoPrefix, wValueNoPrefix));
								} else {
									addr4 = ipv4network.getHostMask(prefix);
									ipv4Addr = createAddress(ipv4HostAddress);
									try {
										wValue = ipv4Addr.toAddress();
										if(!isSameAllAround(wValue, addr4)) {
											addFailure(new Failure("failed " + addr4, ipv4Addr));
										} 
									} catch(AddressStringException e) {
										addFailure(new Failure("failed " + addr4, ipv4Addr));
									}
								}
							} catch(AddressStringException | IncompatibleAddressException e) {
								addFailure(new Failure("failed prefix val", ipv4Addr));
							}
						} else { //prefix > IPv4Address.BIT_COUNT
							try {
								ipv4Addr.toAddress(); //this should throw
								addFailure(new Failure("succeeded with invalid prefix", ipv4Addr));
							} catch(AddressStringException e) {}
						}
					} catch(AddressStringException e) {
						addFailure(new Failure("failed " + addr6, ipv6Addr));
					}
				}
			} catch(AddressStringException | IncompatibleAddressException e) {
				addFailure(new Failure("failed prefix val", ipv6Addr));
			}
		} else {
			try {
				ipv6Addr.toAddress();
				addFailure(new Failure("succeeded with invalid prefix", ipv6Addr));
			} catch(AddressStringException e) {
				try {
					ipv4Addr.toAddress();
					addFailure(new Failure("succeeded with invalid prefix", ipv4Addr));
				} catch(AddressStringException e4) {}
			}
		}
		incrementTestCount();
	}
	
	static int count(String str, String match) {
		int count = 0;
		for(int index = -1; (index = str.indexOf(match, index + 1)) >= 0; count++);
		return count;
	}
	
	void testURL(String url) {
		IPAddressString w = createAddress(url);
		try {
			w.toAddress();
			addFailure(new Failure("failed: " + "URL " + url, w));
		} catch(AddressStringException e) {
			//pass
			e.getMessage();
		}
	}
	
	void testSections(String address, int bits, int count) {
		IPAddressString w = createAddress(address);
		IPAddress v = w.getAddress();
		IPAddressSection section = v.getNetworkSection(bits, false);
		StringBuilder builder = new StringBuilder();
		section.getStartsWithSQLClause(builder, "XXX");
		String clause = builder.toString();
		int found = count(clause, "OR") + 1;
		if(found != count) {
			addFailure(new Failure("failed: " + "Finding first " + (bits / v.getBitsPerSegment()) + " segments of " + v, w));
		}
		incrementTestCount();
	}
	
	static int conversionCompare(IPAddressString h1, IPAddressString h2) {
		if(h1.isIPv4()) {
			if(!h2.isIPv4()) {
				if(h2.getAddress() != null && h2.getAddress().isIPv4Convertible()) {
					return h1.getAddress().compareTo(h2.getAddress().toIPv4());
				}
			}
		} else if(h1.isIPv6()) {
			if(!h2.isIPv6()) {
				if(h2.getAddress() != null && h2.getAddress().isIPv6Convertible()) {
					return h1.getAddress().compareTo(h2.getAddress().toIPv6());
				}
			}
		}
		return -1;
	}
	
	static boolean conversionMatches(IPAddressString h1, IPAddressString h2) {
		if(h1.isIPv4()) {
			if(!h2.isIPv4()) {
				if(h2.getAddress() != null && h2.getAddress().isIPv4Convertible()) {
					return h1.getAddress().equals(h2.getAddress().toIPv4());
				}
			}
		} else if(h1.isIPv6()) {
			if(!h2.isIPv6()) {
				if(h2.getAddress() != null && h2.getAddress().isIPv6Convertible()) {
					return h1.getAddress().equals(h2.getAddress().toIPv6());
				}
			}
		}
		return false;
	}
	
	void testMatches(boolean matches, String host1Str, String host2Str) {
		testMatches(matches, host1Str, host2Str, false);
	}
	
	void testMatches(boolean matches, String host1Str, String host2Str, boolean inet_aton) {
		IPAddressString h1 = inet_aton ? createInetAtonAddress(host1Str) : createAddress(host1Str);
		IPAddressString h2 = inet_aton ? createInetAtonAddress(host2Str) : createAddress(host2Str);
		boolean straightMatch = h1.equals(h2);
		if(matches != straightMatch && matches != conversionMatches(h1, h2)) {
			addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h2, h1));
		} else {
			if(matches != h2.equals(h1) && matches != conversionMatches(h2, h1)) {
				addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h1, h2));
			} else {
				if(matches ? (h1.compareTo(h2) != 0 && conversionCompare(h1, h2) != 0) : (h1.compareTo(h2) == 0)) {
					addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h1, h2));
				} else {
					if(matches ? (h2.compareTo(h1) != 0 && conversionCompare(h2, h1) != 0) : (h2.compareTo(h1) == 0)) {
						addFailure(new Failure("failed: match " + (matches ? "fails" : "passes") + " with " + h2, h1));
					} else if(straightMatch) {
						if(h1.getNetworkPrefixLength() != null) {
							if(h1.isPrefixOnly() && h1.getNetworkPrefixLength() <= IPv4Address.BIT_COUNT) {
								if(h1.prefixEquals(h2)) {
									addFailure(new Failure("failed: prefix only match fail with " + h1, h2));
								} else {
									//this three step test is done so we try it before validation, and then try again before address creation, due to optimizations in IPAddressString
									h1 = inet_aton ? createInetAtonAddress(host1Str) : createAddress(host1Str);
									h2 = inet_aton ? createInetAtonAddress(host2Str) : createAddress(host2Str);
									if(h1.prefixEquals(h2)) {
										addFailure(new Failure("failed: prefix only match fail with " + h1, h2));
									}
									h1.isValid();
									h2.isValid();
									if(h1.prefixEquals(h2)) {
										addFailure(new Failure("failed: 2 prefix only match fail with " + h1, h2));
									}
									h1.getAddress();
									h2.getAddress();
									if(h1.prefixEquals(h2)) {
										addFailure(new Failure("failed: 3 prefix only match fail with " + h1, h2));
									}
								}
							} else {
								if(!h1.prefixEquals(h2)) {
									addFailure(new Failure("failed: prefix match fail with " + h1, h2));
								} else {
									//this three step test is done so we try it before validation, and then try again before address creation, due to optimizations in IPAddressString
									h1 = inet_aton ? createInetAtonAddress(host1Str) : createAddress(host1Str);
									h2 = inet_aton ? createInetAtonAddress(host2Str) : createAddress(host2Str);
									if(!h1.prefixEquals(h2)) {
										addFailure(new Failure("failed: prefix match fail with " + h1, h2));
									}
									h1.isValid();
									h2.isValid();
									if(!h1.prefixEquals(h2)) {
										addFailure(new Failure("failed: 2 prefix match fail with " + h1, h2));
									}
									h1.getAddress();
									h2.getAddress();
									if(!h1.prefixEquals(h2)) {
										addFailure(new Failure("failed: 3 prefix match fail with " + h1, h2));
									}
								}
							}
						}
					} else {
						boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
						//if two are not equal, they can still have equal prefix.  Only if host the same can we conclude otherwise.
						//So here we first check that host is the same (ie full range host)
						if(allPrefixesAreSubnets && h2.getNetworkPrefixLength() != null && h1.getNetworkPrefixLength() != null && h1.getNetworkPrefixLength() >= h2.getNetworkPrefixLength()) {
							if(h1.prefixEquals(h2)) {
								addFailure(new Failure("failed: prefix match succeeds with " + h1, h2));
							} else {
								h1 = inet_aton ? createInetAtonAddress(host1Str) : createAddress(host1Str);
								h2 = inet_aton ? createInetAtonAddress(host2Str) : createAddress(host2Str);
								if(h1.prefixEquals(h2)) {
									addFailure(new Failure("failed: prefix match succeeds with " + h1, h2));
								}
							}
						}
					}
				}
			}
		}
		incrementTestCount();
	}
	
	static class TestSQLTranslator extends MySQLTranslator {
		//linked hash map preserves ordering for iterating in same order as entries were added
		private LinkedHashMap<String, MatchConditions> networkStringMap = new LinkedHashMap<String, MatchConditions>();
		private MatchConditions currentConditions;
		
		boolean test(Map<String, MatchConditions> expectedConditions) {
			return networkStringMap.equals(expectedConditions);
		}
		
		String expected(String column, LinkedHashMap<String, MatchConditions> expectedConditions, boolean isIPv4) {
			char separator = isIPv4 ? IPv4Address.SEGMENT_SEPARATOR : IPv6Address.SEGMENT_SEPARATOR;
			StringBuilder builder = new StringBuilder();
			if(expectedConditions.size() > 1) {
				builder.append('(');
			}
			Set<Map.Entry<String, MatchConditions>> set = expectedConditions.entrySet();//the ordering here is consistent since I use LinkedHashMap
			boolean notFirstString = false;
			for(Map.Entry<String, MatchConditions> entry : set) {//the ordering here is consistent since I use LinkedHashMap
				if(notFirstString) {
					builder.append(" OR ");
				}
				notFirstString = true;
				
				//String networkString = entry.getKey();
				boolean notFirstCond = false;
				MatchConditions conds = entry.getValue();
				
				if(conds.getCount() > 1) {
					builder.append('(');
				}
				for(String match: conds.matches) {
					if(notFirstCond) {
						builder.append(" AND ");
					}
					notFirstCond = true;
					matchString(builder.append('('), column, match).append(')');
				}
				for(SubMatch match: conds.subMatches) {
					if(notFirstCond) {
						builder.append(" AND ");
					}
					notFirstCond = true;
					matchSubString(builder.append('('), column, separator, match.separatorCount, match.match).append(')');
				}
				for(Integer match: conds.separatorCountMatches) {
					if(notFirstCond) {
						builder.append(" AND ");
					}
					notFirstCond = true;
					matchSeparatorCount(builder.append('('), column, separator, match).append(')');
				}
				for(Integer match: conds.separatorBoundMatches) {
					if(notFirstCond) {
						builder.append(" AND ");
					}
					notFirstCond = true;
					boundSeparatorCount(builder.append('('), column, separator, match).append(')');
				}
				if(conds.getCount() > 1) {
					builder.append(')');
				}
			}
			if(expectedConditions.size() > 1) {
				builder.append(')');
			}
			return builder.toString();
		}
		
		@Override
		public void setNetwork(String networkString) {
			currentConditions = new MatchConditions();
			networkStringMap.put(networkString, currentConditions);
		}
		
		@Override
		public StringBuilder matchString(StringBuilder builder, String expression, String match) {
			currentConditions.matches.add(match);
			return super.matchString(builder, expression, match);
		}

		@Override
		public StringBuilder matchSubString(StringBuilder builder, String expression,
				char separator, int separatorCount, String match) {
			currentConditions.subMatches.add(new SubMatch(separatorCount, match));
			return super.matchSubString(builder, expression, separator, separatorCount, match);
		}

		@Override
		public StringBuilder matchSeparatorCount(StringBuilder builder,
				String expression, char separator, int separatorCount) {
			currentConditions.separatorCountMatches.add(separatorCount);
			return super.matchSeparatorCount(builder, expression, separator, separatorCount);
		}

		@Override
		public StringBuilder boundSeparatorCount(StringBuilder builder,
				String expression, char separator, int separatorCount) {
			currentConditions.separatorBoundMatches.add(separatorCount);
			return super.boundSeparatorCount(builder, expression, separator, separatorCount);
		}
	}
	
	static class ExpectedMatch {
		String networkString;
		MatchConditions conditions;
		
		ExpectedMatch(String networkString, MatchConditions conditions) {
			this.networkString = networkString;
			this.conditions = conditions;
		}
	}
	
	void testSQL(String addr, ExpectedMatch matches[]) {
		try {
			IPAddress w = createAddress(addr).toAddress();
			IPAddressSection network;
			if(w.isPrefixed()) {
				network = w.getNetworkSection(w.getNetworkPrefixLength(), false);
			} else {
				network = w.getSection();
			}
			TestSQLTranslator translator = new TestSQLTranslator();
			StringBuilder builder = new StringBuilder();
			network.getStartsWithSQLClause(builder, "COLUMN", translator);
			LinkedHashMap<String, MatchConditions> expectedConditions = new LinkedHashMap<String, MatchConditions>();
			for(ExpectedMatch match : matches) {
				expectedConditions.put(match.networkString, match.conditions);//linked hash map will preserve the array ordering
			}
			if(!translator.test(expectedConditions)) {
				addFailure(new Failure("failed got:\n" + builder + "\nexpected:\n" + translator.expected("COLUMN", expectedConditions, w.isIPv4()), w));
			} else {
				//because I preserve the ordering I can do a string comparison.  Remove this later if I relax the ordering.
				//HOwever, the ordering is actually important for the SQL performance, so don't relax it for no good reason.
				String actual = builder.toString();
				String expected = translator.expected("COLUMN", expectedConditions, w.isIPv4());
				if(!actual.equals(expected)) {
					addFailure(new Failure("failed got string:\n" + builder + "\nexpected:\n" + translator.expected("COLUMN", expectedConditions, w.isIPv4()), w));
				}
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + e));
		}
		incrementTestCount();
	}
	
	static class SubMatch {
		int separatorCount;
		String match;
		
		SubMatch(int separatorCount, String match) {
			this.separatorCount = separatorCount;
			this.match = match;
		}
		
		@Override
		public boolean equals(Object other) {
			if(other instanceof SubMatch) {
				SubMatch otherConds = (SubMatch) other;
				return Objects.equals(match, otherConds.match) &&
						separatorCount == otherConds.separatorCount;
			}
			return false;
		}
	}
	
	static class MatchConditions {
		//there should only really be at most one of each, but that is one of the things we are testing
		private ArrayList<String> matches = new ArrayList<String>();
		private ArrayList<SubMatch> subMatches = new ArrayList<SubMatch>();
		private ArrayList<Integer> separatorCountMatches = new ArrayList<Integer>();
		private ArrayList<Integer> separatorBoundMatches = new ArrayList<Integer>();
		
		MatchConditions() {}
		
		MatchConditions(String match) {
			this(match, null, null, null);
		}
		
		MatchConditions(SubMatch subMatch) {
			this(null, subMatch, null, null);
		}
		
		MatchConditions(SubMatch subMatch, Integer separatorCountMatch, Integer separatorBoundMatch) {
			this(null, subMatch, separatorCountMatch, separatorBoundMatch);
		}
		
		MatchConditions(String match, SubMatch subMatch, Integer separatorCountMatch, Integer separatorBoundMatch) {
			if(match != null) this.matches.add(match);
			if(subMatch != null) this.subMatches.add(subMatch);
			if(separatorCountMatch != null) this.separatorCountMatches.add(separatorCountMatch);
			if(separatorBoundMatch != null) this.separatorBoundMatches.add(separatorBoundMatch);
		}
		
		int getCount() {
			return matches.size() + subMatches.size() + separatorCountMatches.size() + separatorBoundMatches.size();
		}
		@Override
		public boolean equals(Object other) {
			if(other instanceof MatchConditions) {
				MatchConditions otherConds = (MatchConditions) other;
				return Objects.equals(matches, otherConds.matches) &&
						Objects.equals(subMatches, otherConds.subMatches) &&
						Objects.equals(separatorCountMatches, otherConds.separatorCountMatches) &&
						Objects.equals(separatorBoundMatches, otherConds.separatorBoundMatches);
			}
			return false;
		}
	}
	
	void testSQLMatching() {

		//How does this test work?
		//Firstly, we must identify what are the various network strings we expect.
		//Then for each such string, we identify the ways which we will match with a string in the SQL.
			//1. one way is a direct full string match, matching the SQL string with a given string
			//2. another way is to match a part of the SQL string.  We create a substring up to a certain number of separators and match that to a given string.
			//3. another way is to ensure the number separators in the SQL string match a given number.
			//4. another way is to ensure the number separators in the SQL string do not exceed a given number.
		//For each test we can therefore validate and verify that we match in the ways we expect, a combination of the methods listed above on each possibly network string we expect.
		//If any of these tests fail, it will show the SQL we are matching with and we can compare that to what we expected.
		//These tests are complicated but it's really the only automated way to ensure the expected behaviour does not break.
		
		//So, in this first example, there is just the one network string "1.2"
			//For that one string, we do method 2.  From any SQL string we create a substring up to the first two separators and match that to "1.2"
		testSQL("1.2.3.4/16",
				new ExpectedMatch[] {
					//new MatchConditions(String match, SubMatch subMatch, Integer separatorCountMatch, Integer separatorBoundMatch)
					new ExpectedMatch("1.2", new MatchConditions(new SubMatch(2, "1.2"))) //(substring_index(COLUMN,'.',2) = '1.2')
				});
		testSQL("1.2.3.4/8",
				new ExpectedMatch[] {
					new ExpectedMatch("1", new MatchConditions(new SubMatch(1, "1"))) //1.2.3.4/8 (substring_index(COLUMN,'.',1) = '1')
				});
		testSQL("1.2.3.4",
				new ExpectedMatch[] {
					new ExpectedMatch("1.2.3.4", new MatchConditions("1.2.3.4"))//1.2.3.4 (COLUMN = '1.2.3.4')
			});
		
		//test cases in which the network portion ends with ::, 
		//the network portion contains but does not end with ::, 
		//and the network portion is the whole address
		testSQL("a::/64",
				new ExpectedMatch[] {//		a::/64 ((substring_index(COLUMN,':',4) = 'a:0:0:0') OR 
									//((substring_index(COLUMN,':',2) = 'a:') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) <= 5)))
					new ExpectedMatch("a:0:0:0", new MatchConditions(new SubMatch(4, "a:0:0:0"))),
					new ExpectedMatch("a::", new MatchConditions(new SubMatch(2, "a:"), null, 5))
			});//ends with ::
		testSQL("1:a::/32",
				new ExpectedMatch[] {//		1:a::/32 (substring_index(COLUMN,':',2) = '1:a')
					new ExpectedMatch("1:a", new MatchConditions(new SubMatch(2, "1:a")))
			});
		testSQL("0:a::/32",
				new ExpectedMatch[] {//		0:a::/32 ((substring_index(COLUMN,':',2) = '0:a') OR 
									//((substring_index(COLUMN,':',3) = '::a') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) = 8)))
					new ExpectedMatch("0:a", new MatchConditions(new SubMatch(2, "0:a"))),
					new ExpectedMatch("::a", new MatchConditions(new SubMatch(3, "::a"), 8, null))
			});//:: at the front
		testSQL("0:a::/48",
				new ExpectedMatch[] {//		0:a::/48 ((substring_index(COLUMN,':',3) = '0:a:0') OR 
									//((substring_index(COLUMN,':',4) = '::a:0') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) = 8)) OR 
									//((substring_index(COLUMN,':',3) = '0:a:') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) <= 7)))
					new ExpectedMatch("0:a:0", new MatchConditions(new SubMatch(3, "0:a:0"))),
					new ExpectedMatch("::a:0", new MatchConditions(new SubMatch(4, "::a:0"), 8, null)),
					new ExpectedMatch("0:a::", new MatchConditions(new SubMatch(3, "0:a:"), null, 7)),
			});//:: at the front
		testSQL("1:a::/48",
				new ExpectedMatch[] {//		1:a::/48 ((substring_index(COLUMN,':',3) = '1:a:0') OR 
									//((substring_index(COLUMN,':',3) = '1:a:') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) <= 7)))
					new ExpectedMatch("1:a:0", new MatchConditions(new SubMatch(3, "1:a:0"))),
					new ExpectedMatch("1:a::", new MatchConditions(new SubMatch(3, "1:a:"), null, 7))
			}); //ends with ::
		testSQL("1:a::/64",
				new ExpectedMatch[] {//		1:a::/64 ((substring_index(COLUMN,':',4) = '1:a:0:0') OR 
								//((substring_index(COLUMN,':',3) = '1:a:') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) <= 6)))
					new ExpectedMatch("1:a:0:0", new MatchConditions(new SubMatch(4, "1:a:0:0"))),
					new ExpectedMatch("1:a::", new MatchConditions(new SubMatch(3, "1:a:"), null, 6))
			}); //ends with ::
		testSQL("1:1:a::/48",
				new ExpectedMatch[] {//		1:1:a::/48 (substring_index(COLUMN,':',3) = '1:1:a')
					new ExpectedMatch("1:1:a", new MatchConditions(new SubMatch(3, "1:1:a")))
			});
		testSQL("0:0:a::/48",
				new ExpectedMatch[] {//		0:0:a::/48 ((substring_index(COLUMN,':',3) = '0:0:a') OR 
								//((substring_index(COLUMN,':',3) = '::a') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) = 7)))
					new ExpectedMatch("0:0:a", new MatchConditions(new SubMatch(3, "0:0:a"))),
					new ExpectedMatch("::a", new MatchConditions(new SubMatch(3, "::a"), 7, null))
			});//:: at the front
		testSQL("0:0:a::/64",
				new ExpectedMatch[] {//		0:0:a::/64 ((substring_index(COLUMN,':',4) = '0:0:a:0') OR 
									//((substring_index(COLUMN,':',4) = '::a:0') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) = 7)))
					new ExpectedMatch("0:0:a:0", new MatchConditions(new SubMatch(4, "0:0:a:0"))),
					new ExpectedMatch("::a:0", new MatchConditions(new SubMatch(4, "::a:0"), 7, null))
			});//:: at the front
		testSQL("0:0:a::/128",
				new ExpectedMatch[] {//				0:0:a::/128 ((COLUMN = '0:0:a:0:0:0:0:0') OR 
										//(COLUMN = '0:0:a::'))
				new ExpectedMatch("0:0:a:0:0:0:0:0", new MatchConditions("0:0:a:0:0:0:0:0")),
				new ExpectedMatch("0:0:a::", new MatchConditions("0:0:a::"))
			});//full address
		testSQL("0:0:a::",
				new ExpectedMatch[] {//				0:0:a:: ((COLUMN = '0:0:a:0:0:0:0:0') OR 
									//(COLUMN = '0:0:a::'))
					new ExpectedMatch("0:0:a:0:0:0:0:0", new MatchConditions("0:0:a:0:0:0:0:0")),
					new ExpectedMatch("0:0:a::", new MatchConditions("0:0:a::"))
			});//full address
		
		testSQL("1::3:b/0",
				new ExpectedMatch[] {//		1::3:b/0 
			});
		testSQL("1::3:b/16",
				new ExpectedMatch[] {//				1::3:b/16 (substring_index(COLUMN,':',1) = '1')
					new ExpectedMatch("1", new MatchConditions(new SubMatch(1, "1")))
			});
		testSQL("1::3:b/32",
				new ExpectedMatch[] {//				1::3:b/32 ((substring_index(COLUMN,':',2) = '1:0') OR 
									//((substring_index(COLUMN,':',2) = '1:') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) <= 7)))
					new ExpectedMatch("1:0", new MatchConditions(new SubMatch(2, "1:0"))),
					new ExpectedMatch("1::", new MatchConditions(new SubMatch(2, "1:"), null, 7))
			});
		testSQL("1::3:b/80",
				new ExpectedMatch[] {//				1::3:b/80 ((substring_index(COLUMN,':',5) = '1:0:0:0:0') OR 
									//((substring_index(COLUMN,':',2) = '1:') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) <= 4)))
					new ExpectedMatch("1:0:0:0:0", new MatchConditions(new SubMatch(5, "1:0:0:0:0"))),
					new ExpectedMatch("1::", new MatchConditions(new SubMatch(2, "1:"), null, 4))
			});
		testSQL("1::3:b/96",
				new ExpectedMatch[] {//		1::3:b/96 ((substring_index(COLUMN,':',6) = '1:0:0:0:0:0') OR 
									//((substring_index(COLUMN,':',2) = '1:') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) <= 3)))
					new ExpectedMatch("1:0:0:0:0:0", new MatchConditions(new SubMatch(6, "1:0:0:0:0:0"))),
					new ExpectedMatch("1::", new MatchConditions(new SubMatch(2, "1:"), null, 3))
			});
		testSQL("1::3:b/112",
				new ExpectedMatch[] {//		1::3:b/112 ((substring_index(COLUMN,':',7) = '1:0:0:0:0:0:3') OR 
									//((substring_index(COLUMN,':',3) = '1::3') AND (LENGTH (COLUMN) - LENGTH(REPLACE(COLUMN, ':', '')) = 3)))
				new ExpectedMatch("1:0:0:0:0:0:3", new MatchConditions(new SubMatch(7, "1:0:0:0:0:0:3"))),
				new ExpectedMatch("1::3", new MatchConditions(new SubMatch(3, "1::3"), 3, null))
			});
		testSQL("1::3:b/128",
				new ExpectedMatch[] {//		1::3:b/128 ((COLUMN = '1:0:0:0:0:0:3:b') OR 
								//(COLUMN = '1::3:b'))
					new ExpectedMatch("1:0:0:0:0:0:3:b", new MatchConditions("1:0:0:0:0:0:3:b")),
					new ExpectedMatch("1::3:b", new MatchConditions("1::3:b"))
			});
	}

	void testEquivalentPrefix(String host, int prefix) {
		testEquivalentPrefix(host, prefix, prefix);
	}
	
	void testEquivalentPrefix(String host, Integer equivPrefix, int minPrefix) {
		IPAddressString str = createAddress(host);
		try {
			IPAddress h1 = str.toAddress();
			Integer equiv = h1.getPrefixLengthForSingleBlock();
			if(equiv == null ? (equivPrefix != null) : (!equivPrefix.equals(equiv))) {
				equiv = h1.getPrefixLengthForSingleBlock();
				addFailure(new Failure("failed: prefix expected: " + equivPrefix + " prefix got: " + equiv, h1));
			} else {
				IPAddress prefixed = h1.assignPrefixForSingleBlock();
				String bareHost;
				int index = host.indexOf('/');
				if(index == -1) {
					bareHost = host;
				} else {
					bareHost = host.substring(0, index);
				}
				IPAddressString direct = createAddress(bareHost + '/' + equivPrefix);
				IPAddress directAddress = direct.getAddress();
				boolean zeroSubnets = prefixConfiguration.zeroHostsAreSubnets();
				if(equivPrefix != null && h1.isPrefixed() && zeroSubnets && h1.isPrefixBlock()) {
					directAddress = makePrefixSubnet(directAddress);
				}
				if(equiv == null ? prefixed != null : !directAddress.equals(prefixed)) {
					addFailure(new Failure("failed: prefix expected: " + direct, prefixed));
				} else {
					int minPref = h1.getMinPrefixLengthForBlock();
					if(minPref != minPrefix) {
						addFailure(new Failure("failed: prefix expected: " + minPrefix + " prefix got: " + minPref, h1));
					} else {
						IPAddress minPrefixed = h1.assignMinPrefixForBlock();
						index = host.indexOf('/');
						if(index == -1) {
							bareHost = host;
						} else {
							bareHost = host.substring(0, index);
						}
						direct = createAddress(bareHost + '/' + minPrefix);
						directAddress = direct.getAddress();
						if(h1.isPrefixed() && zeroSubnets && h1.isPrefixBlock()) {
							directAddress = makePrefixSubnet(directAddress);
						}
						if(!directAddress.equals(minPrefixed)) {
							addFailure(new Failure("failed: prefix expected: " + direct, minPrefixed));
						}
					}
				}
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("failed " + e, str));
		}
		incrementTestCount();
	}

	private IPAddress makePrefixSubnet(IPAddress directAddress) {
		IPAddressSegment segs[] = directAddress.getSegments();
		int pref = directAddress.getPrefixLength();
		final int prefSeg = pref / directAddress.getBitsPerSegment();
		if(prefSeg < segs.length) {
			IPAddressNetwork<?, ?, ?, ?, ?> network = directAddress.getNetwork();
			IPAddressCreator<?, ?, ?, ?, ?> creator = network.getAddressCreator();
			if(directAddress.getPrefixCount().equals(BigInteger.ONE)) {
				IPAddressSegment origSeg = segs[prefSeg];
				int mask = network.getSegmentNetworkMask(pref % directAddress.getBitsPerSegment());
				segs[prefSeg] = creator.createSegment(origSeg.getSegmentValue() & mask, origSeg.getUpperSegmentValue() & mask, origSeg.getSegmentPrefixLength());
				for(int ps = prefSeg + 1; ps < segs.length; ps++) {
					segs[ps] = creator.createSegment(0, 0);
				}
				byte bytes[] = new byte[directAddress.getByteCount()];
				int bytesPerSegment = directAddress.getBytesPerSegment();
				for(int i = 0, j = 0; i < segs.length; i++, j += bytesPerSegment) {
					segs[i].getBytes(bytes, j);
				}
				directAddress = creator.createAddress(bytes, pref);
			} else {
				//we could have used SegmentValueProvider in both blocks, but mixing it up to test everything
				IPAddressSegment origSeg = segs[prefSeg];
				int mask = network.getSegmentNetworkMask(pref % directAddress.getBitsPerSegment());
				int maxValue = directAddress.getMaxSegmentValue();
				directAddress = creator.createAddress(
						new SegmentValueProvider() {
							@Override
							public int getValue(int segmentIndex) {
								if(segmentIndex < prefSeg) {
									return segs[segmentIndex].getSegmentValue();
								} else if(segmentIndex == prefSeg) {
									return origSeg.getSegmentValue() & mask;
								} else {
									return 0;
								}
							}
						},
						new SegmentValueProvider() {
							@Override
							public int getValue(int segmentIndex) {
								if(segmentIndex < prefSeg) {
									return segs[segmentIndex].getUpperSegmentValue();
								} else if(segmentIndex == prefSeg) {
									return origSeg.getUpperSegmentValue() & mask;
								} else {
									return maxValue;
								}
							}
						}, 
						pref);
			}
		}
		return directAddress;
	}
	
	void testSubnet(String addressStr, String maskStr, int prefix, 
			String normalizedPrefixSubnetString,
			String normalizedSubnetString, 
			String normalizedPrefixString) {
		testHostAddress(addressStr);
		boolean isValidWithPrefix = normalizedPrefixSubnetString != null;
		boolean isValidMask = normalizedSubnetString != null;
		IPAddressString str = createAddress(addressStr);
		IPAddressString maskString = createAddress(maskStr);
		try {
			IPAddress value = str.toAddress();
			Integer originalPrefix = value.getNetworkPrefixLength();
			try {
				IPAddress mask = maskString.toAddress();
				IPAddress subnet3 = value.applyPrefixLength(prefix);
				String string3 = subnet3.toNormalizedString();
				if(!string3.equals(normalizedPrefixString)) {
					addFailure(new Failure("testSubnet failed normalizedPrefixString: " + string3 + " expected: " + normalizedPrefixString, subnet3));
				} else {
					try {
						IPAddress subnet = value.maskNetwork(mask, prefix);
						if(!isValidWithPrefix) {
							addFailure(new Failure("testSubnet failed to throw with mask " + mask + " and prefix " + prefix, value));
						} else {
							String string = subnet.toNormalizedString();
							if(!string.equals(normalizedPrefixSubnetString)) {
								addFailure(new Failure("testSubnet failed: " + string + " expected: " + normalizedPrefixSubnetString, subnet));
							} else {
								try {
									IPAddress subnet2 = value.mask(mask);
									if(!isValidMask) {
										addFailure(new Failure("testSubnet failed to throw with mask " + mask, value));
									} else {
										String string2 = subnet2.toNormalizedString();
										if(!string2.equals(normalizedSubnetString)) {
											addFailure(new Failure("testSubnet failed: " + string2 + " expected: " + normalizedSubnetString, subnet2));
										} else {
											if(subnet2.getNetworkPrefixLength() != null) {
												addFailure(new Failure("testSubnet failed, expected null prefix, got: " + subnet2.getNetworkPrefixLength(), subnet2));
											} else {
												IPAddress subnet4 = value.mask(mask, true);
												if(!Objects.equals(subnet4.getNetworkPrefixLength(), originalPrefix)) {
													addFailure(new Failure("testSubnet failed, expected " + originalPrefix + " prefix, got: " + subnet4.getNetworkPrefixLength(), subnet2));
												} else {
													if(originalPrefix != null) {
														//the prefix will be different, but the addresses will be the same, except for full subnets
														IPAddress addr = subnet2.setPrefixLength(originalPrefix, false);
														if(!subnet4.equals(addr)) {
															addFailure(new Failure("testSubnet failed: " + subnet4 + " expected: " + addr, subnet4));
														}
													} else {
														if(!subnet4.equals(subnet2)) {
															addFailure(new Failure("testSubnet failed: " + subnet4 + " expected: " + subnet2, subnet4));
														}
													}
												}
											}
										}
									}
								} catch(IncompatibleAddressException e) {
									if(isValidMask) {
										addFailure(new Failure("testSubnet failed with mask " + mask + " " + e, value));
									}
								}
							}
						}
					} catch(IncompatibleAddressException e) {
						if(isValidWithPrefix) {
							addFailure(new Failure("testSubnet failed with mask " + mask + " and prefix " + prefix + ": " + e, value));
						} else {
							try {
								IPAddress subnet2 = value.mask(mask);
								if(!isValidMask) {
									addFailure(new Failure("testSubnet failed to throw with mask " + mask, value));
								} else {
									String string2 = subnet2.toNormalizedString();
									if(!string2.equals(normalizedSubnetString)) {
										addFailure(new Failure("testSubnet failed: " + normalizedSubnetString + " expected: " + string2, subnet2));
									}
								}
							} catch(IncompatibleAddressException e2) {
								if(isValidMask) {
									addFailure(new Failure("testSubnet failed with mask " + mask + " " + e2, value));
								}
							}
						}
					}
				} 
			} catch(AddressStringException e) {
				addFailure(new Failure("testSubnet failed " + e, maskString));
			}
		} catch(AddressStringException e) {
			addFailure(new Failure("testSubnet failed " + e, str));
		}
		incrementTestCount();
	}
	
	void testReverse(String addressStr, boolean bitsReversedIsSame, boolean bitsReversedPerByteIsSame) {
		IPAddressString str = createAddress(addressStr);
		try {
			testReverse(str.getAddress(), bitsReversedIsSame, bitsReversedPerByteIsSame);
		} catch(RuntimeException e) {
			addFailure(new Failure("reversal: " + addressStr));
		}
		incrementTestCount();
	}
	
	void testPrefixes(
			String orig, 
			int prefix, int adjustment, 
			String next,
			String previous,
			String adjusted,
			String prefixSet,
			String prefixApplied) {
		IPAddress original = createAddress(orig).getAddress();
		if(original.isPrefixed()) {
			AddressSegmentSeries removed = original.withoutPrefixLength();
			for(int i = 0; i < removed.getSegmentCount(); i++) {
				if(!removed.getSegment(i).equals(original.getSegment(i))) {
					addFailure(new Failure("removed prefix: " + removed, original));
					break;
				}
			}
		}
		testPrefixes(original,
				prefix, adjustment, 
				createAddress(next).getAddress(),
				createAddress(previous).getAddress(),
				createAddress(adjusted).getAddress(),
				createAddress(prefixSet).getAddress(),
				createAddress(prefixApplied).getAddress());
		incrementTestCount();
	}
	
	void testPrefixBlocks(
			String orig, 
			boolean isPrefixBlock,
			boolean isSinglePrefixBlock) {
		IPAddress original = createAddress(orig).getAddress();
		if(isPrefixBlock != original.isPrefixBlock()) {
			addFailure(new Failure("is prefix block: " + original.isPrefixBlock() + " expected: " + isPrefixBlock, original));
		} else if(isSinglePrefixBlock != original.isSinglePrefixBlock()) {
			addFailure(new Failure("is single prefix block: " + original.isSinglePrefixBlock() + " expected: " + isSinglePrefixBlock, original));
		}
		incrementTestCount();
	}
	
	void testPrefixBlocks(
			String orig, 
			int prefix,
			boolean containsPrefixBlock,
			boolean containsSinglePrefixBlock) {
		IPAddress original = createAddress(orig).getAddress();
		if(containsPrefixBlock != original.containsPrefixBlock(prefix)) {
			addFailure(new Failure("contains prefix block: " + original.containsPrefixBlock(prefix) + " expected: " + containsPrefixBlock, original));
		} else if(containsSinglePrefixBlock != original.containsSinglePrefixBlock(prefix)) {
			addFailure(new Failure("contains single prefix block: " + original.containsSinglePrefixBlock(prefix) + " expected: " + containsPrefixBlock, original));
		}
		incrementTestCount();
	}
	
	void testBitwiseOr(String orig, Integer prefixAdjustment, String or, String expectedResult) {
		IPAddress original = createAddress(orig).getAddress();
		IPAddress orAddr = createAddress(or).getAddress();
		if(prefixAdjustment != null) {
			original = original.adjustPrefixLength(prefixAdjustment);
		}
		try {
			IPAddress result = original.bitwiseOr(orAddr);
			if(expectedResult == null) {
				original.bitwiseOr(orAddr);
				addFailure(new Failure("ored expected throw " + original + " orAddr: " + orAddr + " result: " + result, original));
			} else {
				IPAddress expectedResultAddr = createAddress(expectedResult).getAddress();
				if(!expectedResultAddr.equals(result)) {
					addFailure(new Failure("ored expected: " + expectedResultAddr + " actual: " + result, original));
				}
				if(result.getPrefixLength() != null) {
					addFailure(new Failure("ored expected null prefix: " + expectedResultAddr + " actual: " + result.getPrefixLength(), original));
				}
			}
		} catch(IncompatibleAddressException e) {
			if(expectedResult != null) {
				addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
			}
		}
		incrementTestCount();
	}
	
	void testPrefixBitwiseOr(String orig, Integer prefix, String or, String expectedNetworkResult) {
		testPrefixBitwiseOr(orig, prefix, or, expectedNetworkResult, null);
	}
	
	void testPrefixBitwiseOr(String orig, Integer prefix, String or, String expectedNetworkResult, String expectedFullResult) {
		IPAddress original = createAddress(orig).getAddress();
		IPAddress orAddr = createAddress(or).getAddress();
		try {
			IPAddress result = original.bitwiseOrNetwork(orAddr, prefix);
			if(expectedNetworkResult == null) {
				addFailure(new Failure("ored network expected throw " + original + " orAddr: " + orAddr + " result: " + result, original));
			} else {
				IPAddressString expected = createAddress(expectedNetworkResult);
				IPAddress expectedResultAddr = expected.getAddress();
				if(!expectedResultAddr.equals(result)  || !Objects.equals(expectedResultAddr.getPrefixLength(), result.getPrefixLength())) {
					result = original.bitwiseOrNetwork(orAddr, prefix);
					addFailure(new Failure("ored network expected: " + expectedResultAddr + " actual: " + result, original));
				}
			}
		} catch(IncompatibleAddressException e) {
			if(expectedNetworkResult != null) {
				addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
			}
		}
		try {
			IPAddress result = original.bitwiseOr(orAddr, true);
			if(expectedFullResult == null) {
				addFailure(new Failure("ored expected throw " + original + " orAddr: " + orAddr + " result: " + result, original));
			} else {
				IPAddressString expected = createAddress(expectedFullResult);
				IPAddress expectedResultAddr = expected.getAddress();
				if(!expectedResultAddr.equals(result) || !Objects.equals(expectedResultAddr.getPrefixLength(), result.getPrefixLength())) {
					result = original.bitwiseOr(orAddr, true);
					addFailure(new Failure("ored expected: " + expectedResultAddr + " actual: " + result, original));
				}
			}
		} catch(IncompatibleAddressException e) {
			if(expectedFullResult != null) {
				addFailure(new Failure("ored threw unexpectedly " + original + " orAddr: " + orAddr, original));
			}
		}
		incrementTestCount();
	}
	
	void testDelimitedCount(String str, int expectedCount) {
		Iterator<String> strings = IPAddressString.parseDelimitedSegments(str);
		HashSet<IPAddress> set = new HashSet<IPAddress>();
		int count = 0;
		try {
			while(strings.hasNext()) {
				set.add(createAddress(strings.next()).toAddress());
				count++;
			}
			if(count != expectedCount || set.size() != count || count != IPAddressString.countDelimitedAddresses(str)) {
				addFailure(new Failure("count mismatch, count: " + count + " set count: " + set.size() + " calculated count: " + IPAddressString.countDelimitedAddresses(str) + " expected: " + expectedCount));
			}
		} catch (AddressStringException | IncompatibleAddressException e) {
			addFailure(new Failure("threw unexpectedly " + str));
		}
		incrementTestCount();
	}
	
	void testReverseHostAddress(String str) {
		IPAddressString addrStr = createAddress(str);
		IPAddress addr = addrStr.getAddress();
		IPAddress hostAddr = addrStr.getHostAddress();
		IPAddress hostAddr2;
		if(addr.isIPv6()) {
			IPAddress newAddr = new IPv6Address(addr.toIPv6().getSection());
			IPAddressString newAddrString = newAddr.toAddressString();
			hostAddr2 = newAddrString.getHostAddress();
		} else {
			IPAddress newAddr = new IPv4Address(addr.toIPv4().getSection());
			IPAddressString newAddrString = newAddr.toAddressString();
			hostAddr2 = newAddrString.getHostAddress();
		}
		if(!hostAddr.equals(hostAddr2)) {
			addFailure(new Failure("expected " + hostAddr + " got " + hostAddr2, hostAddr2));
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
		IPAddress f = createAddress(front).getAddress();
		IPAddress b = createAddress(back).getAddress();
		testAppendAndInsert(f, b, f.getSegmentStrings(), b.getSegmentStrings(), 
				f.isIPv4() ? IPv4Address.SEGMENT_SEPARATOR : IPv6Address.SEGMENT_SEPARATOR, expectedPref, false);
	}
	
	void testReplace(String front, String back) {
		IPAddress f = createAddress(front).getAddress();
		IPAddress b = createAddress(back).getAddress();
		testReplace(f, b, f.getSegmentStrings(), b.getSegmentStrings(), 
				f.isIPv4() ? IPv4Address.SEGMENT_SEPARATOR : IPv6Address.SEGMENT_SEPARATOR, false);
	}
	
	void testInvalidIpv4Values() {
		try {
			byte bytes[] = new byte[5];
			bytes[0] = 1;
			IPv4Address addr = new IPv4Address(bytes);
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			new IPv4Address(new byte[5]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new IPv4Address(new byte[4]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new IPv4Address(new byte[3]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new IPv4Address(new byte[2]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			IPv4Address addr = new IPv4Address(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return 256;
				}
			});
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			IPv4Address addr = new IPv4Address(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return -1;
				}
			});
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			new IPv4Address(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return 255;
				}
			});
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
	}
	
	void testIPv4Values(int segs[], String decimal) {
		byte vals[] = new byte[segs.length];
		StringBuilder strb = new StringBuilder();
		long longval = 0;
		int intval = 0;
		BigInteger bigInteger = BigInteger.ZERO;
		int bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
		for(int i = 0; i < segs.length; i++) {
			int seg = segs[i];
			if(strb.length() > 0) {
				strb.append('.');
			}
			strb.append(seg);
			vals[i] = (byte) seg;
			longval = (longval << bitsPerSegment) | seg;
			intval = (intval << bitsPerSegment) | seg;
			bigInteger = bigInteger.shiftLeft(bitsPerSegment).add(BigInteger.valueOf(seg));
		}
		try {
			IPv4Address addr[] = new IPv4Address[7];
			int i = 0;
			addr[i++] = createAddress(vals).toIPv4();
			addr[i++] = createAddress(strb.toString()).getAddress().toIPv4();
			addr[i++] = createAddress(intval).toIPv4();
			InetAddress inetAddress1 = InetAddress.getByName(strb.toString());
			InetAddress inetAddress2 = InetAddress.getByAddress(vals);
			addr[i++] = new IPv4Address((Inet4Address) inetAddress1);
			addr[i++] = new IPv4Address((Inet4Address) inetAddress2);
			addr[i++] = new IPv4Address((int) longval);
			addr[i++] = new IPv4Address(bigInteger.intValue());
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
					if(!decimal.equals(String.valueOf(addr[i].longValue()))) {
						addFailure(new Failure("failed equals: " + addr[i].longValue() + " and " + decimal));
					}
				}
			}
		} catch(UnknownHostException e) {
			addFailure(new Failure("failed unexpected: " + e));
		}
	}
	
	void testIPv6Values(int segs[], String decimal) {
		byte vals[] = new byte[segs.length * IPv6Address.BYTES_PER_SEGMENT];
		StringBuilder strb = new StringBuilder();
		BigInteger bigInteger = BigInteger.ZERO;
		int bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
		for(int i = 0; i < segs.length; i++) {
			int seg = segs[i];
			if(strb.length() > 0) {
				strb.append(':');
			}
			strb.append(Integer.toHexString(seg));
			vals[i << 1] = (byte) (seg >>> 8);
			vals[(i << 1) + 1] = (byte) seg;
			bigInteger = bigInteger.shiftLeft(bitsPerSegment).add(BigInteger.valueOf(seg));
		}
		try {
			IPv6Address addr[] = new IPv6Address[5];
			int i = 0;
			addr[i++] = createAddress(vals).toIPv6();
			addr[i++] = createAddress(strb.toString()).getAddress().toIPv6();
			InetAddress inetAddress1 = InetAddress.getByName(strb.toString());
			InetAddress inetAddress2 = InetAddress.getByAddress(vals);
			addr[i++] = new IPv6Address((Inet6Address) inetAddress1);
			addr[i++] = new IPv6Address((Inet6Address) inetAddress2);
			addr[i++] = new IPv6Address(bigInteger);
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
				}
			}
		} catch(AddressValueException e) {
			addFailure(new Failure("failed unexpected: " + e));
		} catch(UnknownHostException e) {
			addFailure(new Failure("failed unexpected: " + e));
		}
	}
	
	void testInvalidIpv6Values() {
		try {
			byte bytes[] = new byte[17];
			bytes[0] = 1;
			IPv6Address addr = new IPv6Address(bytes);
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			new IPv6Address(new byte[17]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new IPv6Address(new byte[16]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}try {
			new IPv6Address(new byte[15]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new IPv6Address(new byte[14]);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			new IPv6Address(BigInteger.valueOf(-1));//-1 becomes [ff] which is sign extended to 16 bytes like [ff][ff]...[ff] 
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		BigInteger thirtyTwo = BigInteger.valueOf(0xffffffffL);
		BigInteger one28 = thirtyTwo.shiftLeft(96).or(thirtyTwo.shiftLeft(64).or(thirtyTwo.shiftLeft(32).or(thirtyTwo)));
		try {
			new IPv6Address(one28);
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
		try {
			IPv6Address addr = new IPv6Address(one28.add(BigInteger.ONE));
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			new IPv6Address(BigInteger.valueOf(0xffffffffL));//must make it a long so it is not negative
		} catch(AddressValueException e) {
			addFailure(new Failure("failed unexpected: " + e));
		}
		try {
			IPv6Address addr = new IPv6Address(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return 0x10000;
				}
			});
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			IPv6Address addr = new IPv6Address(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return -1;
				}
			});
			addFailure(new Failure("failed expected exception for " + addr, addr));
		} catch(AddressValueException e) {}
		try {
			new IPv6Address(new SegmentValueProvider() {
				@Override
				public int getValue(int segmentIndex) {
					return 0xffff;
				}
			});
		} catch(AddressValueException e) {
			addFailure(new Failure("unexpected exception " + e));
		}
	}

	public void testSub(String one, String two, String resultStrings[]) {
		IPAddressString string = createAddress(one);
		IPAddressString sub = createAddress(two);
		IPAddress addr = string.getAddress();
		IPAddress subAddr = sub.getAddress();
		try {
			IPAddress res[] = addr.subtract(subAddr);
			if(resultStrings == null) {
				if(res != null ) {	
					addFailure(new Failure("non-null subtraction with " + addr, subAddr));
				}
			} else {
				if(resultStrings.length != res.length) {
					addFailure(new Failure("length mismatch " + Arrays.toString(res) + " with " + Arrays.toString(resultStrings)));
				} else {
					IPAddress results[] = new IPAddress[resultStrings.length];
					for(int i = 0; i < resultStrings.length; i++) {
						results[i] = createAddress(resultStrings[i]).getAddress();
					}
					for(IPAddress r : res) {
						boolean found = false;
						for(IPAddress result : results) {
							if(r.equals(result) && Objects.equals(r.getNetworkPrefixLength(), result.getNetworkPrefixLength())) {
								found = true; 
								break;
							}
						}
						if(!found) {
							addFailure(new Failure("mismatch with " + Arrays.toString(resultStrings), r));
						}
					}
				}
			}
		} catch(IncompatibleAddressException e) {
			addFailure(new Failure("threw " + e + " when subtracting " + subAddr, addr));
		}
		incrementTestCount();
	}
	
	public void testIntersect(String one, String two, String resultString) {
		testIntersect(one, two, resultString, false);
	}
		
	public void testIntersect(String one, String two, String resultString, boolean lowest) {
		IPAddressString string = createAddress(one);
		IPAddressString string2 = createAddress(two);
		IPAddress addr = string.getAddress();
		IPAddress addr2 = string2.getAddress();
		IPAddress r = addr.intersect(addr2);
		if(resultString == null) {
			if(r != null) {	
				addFailure(new Failure("non-null intersection with " + addr, addr2));
			}
		} else {
			IPAddress result = createAddress(resultString).getAddress();
			if(lowest) {
				result = result.getLower();
			}
			if(!r.equals(result) || !Objects.equals(r.getNetworkPrefixLength(), result.getNetworkPrefixLength())) {	
				addFailure(new Failure("mismatch with " + result, r));
			}
		}
		incrementTestCount();
	}
	
	public void testToPrefixBlock(String addrString, String subnetString) {
		IPAddressString string = createAddress(addrString);
		IPAddressString string2 = createAddress(subnetString);
		IPAddress addr = string.getAddress();
		IPAddress subnet = string2.getAddress();
		IPAddress prefixBlock = addr.toPrefixBlock();
		if(!subnet.equals(prefixBlock)) {
			addFailure(new Failure("prefix block mismatch " + subnet + " with block " + prefixBlock, addr));
		} else if(!Objects.equals(subnet.getNetworkPrefixLength(), prefixBlock.getNetworkPrefixLength())) {
			addFailure(new Failure("prefix block length mismatch " + subnet.getNetworkPrefixLength() + " and " + prefixBlock.getNetworkPrefixLength(), addr));
		}
		incrementTestCount();
	}
	
	public void testZeroHost(String addrString, String zeroHostString) {
		IPAddressString string = createAddress(addrString);
		IPAddressString string2 = createAddress(zeroHostString);
		IPAddress addr = string.getAddress();
		IPAddress specialHost = string2.getAddress();
		IPAddress transformedHost = addr.toZeroHost();
		if(!prefixConfiguration.zeroHostsAreSubnets() && !specialHost.equals(transformedHost)) {
			addFailure(new Failure("mismatch " + specialHost + " with host " + transformedHost, addr));
		}
		if(!prefixConfiguration.allPrefixedAddressesAreSubnets()) {
			IPAddressSection hostSection = transformedHost.getHostSection();
			if(hostSection.getSegmentCount() > 0 && !hostSection.isZero()) {
				addFailure(new Failure("non-zero host " + hostSection, addr));
			}
		}
		if(!Objects.equals(transformedHost.getNetworkPrefixLength(), specialHost.getNetworkPrefixLength())) {
			addFailure(new Failure("prefix length mismatch " + transformedHost.getNetworkPrefixLength() + " and " + specialHost.getNetworkPrefixLength(), addr));
		}
		incrementTestCount();
	}
	
	public void testMaxHost(String addrString, String maxHostString) {
		IPAddressString string = createAddress(addrString);
		IPAddressString string2 = createAddress(maxHostString);
		IPAddress addr = string.getAddress();
		IPAddress specialHost = string2.getAddress();
		IPAddress transformedHost = addr.toMaxHost();
		if(!specialHost.equals(transformedHost)) {
			addFailure(new Failure("mismatch " + specialHost + " with host " + transformedHost, addr));
		} else if(!Objects.equals(transformedHost.getNetworkPrefixLength(), specialHost.getNetworkPrefixLength())) {
			addFailure(new Failure("prefix length mismatch " + transformedHost.getNetworkPrefixLength() + " and " + specialHost.getNetworkPrefixLength(), addr));
		}
		incrementTestCount();
	}

	void testLargeDivs(byte bytes[][]) {
		List<IPAddressLargeDivision> divList = new ArrayList<>();
		int byteTotal = 0;
		for(byte b[] : bytes) {
			byteTotal += b.length;
			divList.add(new IPAddressLargeDivision(b, b.length << 3, 16));
		}
		IPAddressNetwork<?, ?, ?, ?, ?> network = 
				byteTotal > 4 ? IPv6Address.defaultIpv6Network() : IPv4Address.defaultIpv4Network();
		IPAddressLargeDivisionGrouping grouping = new IPAddressLargeDivisionGrouping(divList.toArray(new IPAddressLargeDivision[divList.size()]), network);
		byte bytes1[] = new byte[byteTotal], bytes2[], bytes3[], bytes4[], bytes5[], bytes6[], bytes7[];
		byteTotal = 0;
		for(byte b[] : bytes) {
			System.arraycopy(b, 0,  bytes1, byteTotal, b.length);
			byteTotal += b.length;
		}
		bytes2 = grouping.getBytes();
		bytes3 = new byte[byteTotal];
		bytes3 = grouping.getBytes(bytes3);
		bytes4 = grouping.getUpperBytes();
		bytes5 = new byte[byteTotal];
		bytes5 = grouping.getUpperBytes(bytes5);
		IPAddressLargeDivisionGrouping grouping2 = new IPAddressLargeDivisionGrouping(new IPAddressLargeDivision[] { new IPAddressLargeDivision(bytes5, bytes5.length << 3, 16) }, network);
		bytes6 = grouping2.getBytes();
		bytes6 = grouping2.getUpperBytes();
		bytes7 = grouping.getBytes();
		if(!Arrays.equals(bytes1, bytes2)) {
			addFailure(new Failure("mismatch bytes1 " + Arrays.asList(bytes1) + " with bytes2 " + Arrays.asList(bytes2)));
		} else if(!Arrays.equals(bytes1, bytes3)) {
			addFailure(new Failure("mismatch bytes1 " + Arrays.asList(bytes1) + " with bytes3 " + Arrays.asList(bytes3)));
		} else if(!Arrays.equals(bytes1, bytes4)) {
			addFailure(new Failure("mismatch bytes1 " + Arrays.asList(bytes1) + " with bytes4 " + Arrays.asList(bytes4)));
		} else if(!Arrays.equals(bytes1, bytes5)) {
			addFailure(new Failure("mismatch bytes1 " + Arrays.asList(bytes1) + " with bytes5 " + Arrays.asList(bytes5)));
		} else if(!Arrays.equals(bytes1, bytes6)) {
			addFailure(new Failure("mismatch bytes1 " + Arrays.asList(bytes1) + " with bytes6 " + Arrays.asList(bytes6)));
		} else if(!Arrays.equals(bytes1, bytes7)) {
			addFailure(new Failure("mismatch bytes1 " + Arrays.asList(bytes1) + " with bytes7 " + Arrays.asList(bytes7)));
		}
		if(bytes.length == 1 ? !grouping.equals(grouping2) : grouping.equals(grouping2)) {
			addFailure(new Failure("match grouping" + grouping + " with " + grouping2));
		}
		incrementTestCount();
	}
	
	void testRangeJoin(String lower1, String higher1, String lower2, String higher2, String resultLower, String resultHigher) {
		testRangeJoinImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher);
		testRangeJoinImpl(lower2, higher2, lower1, higher1, resultHigher, resultLower);
	}
	
	void testRangeJoinImpl(String lower1, String higher1, String lower2, String higher2, String resultLower, String resultHigher) {
		IPAddress addr = createAddress(lower1).getAddress();
		IPAddress addr2 = createAddress(higher1).getAddress();
		IPAddressSeqRange range = addr.spanWithRange(addr2);
		
		addr = createAddress(lower2).getAddress();
		addr2 = createAddress(higher2).getAddress();
		IPAddressSeqRange range2 = addr.spanWithRange(addr2);
		
		IPAddressSeqRange result = range.join(range2);
		if(resultLower == null) {
			if(result != null) {
				addFailure(new Failure("mismatch result " + result + " expected null joining '" + addr + "' with '" + addr2 + "'", addr));
			}
		} else {
			addr = createAddress(resultLower).getAddress();
			addr2 = createAddress(resultHigher).getAddress();
			IPAddressSeqRange expectedResult = addr.spanWithRange(addr2);
			if(!result.equals(expectedResult)) {
				addFailure(new Failure("mismatch result '" + result + "' expected '" + expectedResult + "' joining '" + addr + "' with '" + addr2 + "'", addr));
			}
		}
		incrementTestCount();
	}
	
	void testRangeIntersect(String lower1, String higher1, String lower2, String higher2, String resultLower, String resultHigher) {
		testRangeIntersectImpl(lower1, higher1, lower2, higher2, resultLower, resultHigher);
		testRangeIntersectImpl(lower2, higher2, lower1, higher1, resultHigher, resultLower);
	}
	
	void testRangeIntersectImpl(String lower1, String higher1, String lower2, String higher2, String resultLower, String resultHigher) {
		IPAddress addr = createAddress(lower1).getAddress();
		IPAddress addr2 = createAddress(higher1).getAddress();
		IPAddressSeqRange range = addr.spanWithRange(addr2);
		
		addr = createAddress(lower2).getAddress();
		addr2 = createAddress(higher2).getAddress();
		IPAddressSeqRange range2 = addr.spanWithRange(addr2);
		
		IPAddressSeqRange result = range.intersect(range2);
		if(resultLower == null) {
			if(result != null) {
				addFailure(new Failure("mismatch result " + result + " expected null intersecting '" + addr + "' with '" + addr2 + "'", addr));
			}
		} else {
			addr = createAddress(resultLower).getAddress();
			addr2 = createAddress(resultHigher).getAddress();
			IPAddressSeqRange expectedResult = addr.spanWithRange(addr2);
			if(!result.equals(expectedResult)) {
				addFailure(new Failure("mismatch result '" + result + "' expected '" + expectedResult + "' intersecting '" + addr + "' with '" + addr2 + "'", addr));
			}
		}
		incrementTestCount();
	}
	
	void testRangeSubtract(String lower1, String higher1, String lower2, String higher2, 
			String ...resultPairs) {
		IPAddress addr = createAddress(lower1).getAddress();
		IPAddress addr2 = createAddress(higher1).getAddress();
		IPAddressSeqRange range = addr.spanWithRange(addr2);
		
		addr = createAddress(lower2).getAddress();
		addr2 = createAddress(higher2).getAddress();
		IPAddressSeqRange range2 = addr.spanWithRange(addr2);
		
		IPAddressSeqRange result[] = range.subtract(range2);
		if(resultPairs.length == 0) {
			if(result.length != 0) {
				addFailure(new Failure("mismatch result " + result + " expected zero length result subtracting '" + addr2 + "' from '" + addr + "'", addr));
			}
		} else { //resultPairs.length >= 2
			addr = createAddress(resultPairs[0]).getAddress();
			addr2 = createAddress(resultPairs[1]).getAddress();
			IPAddressSeqRange expectedResult = addr.spanWithRange(addr2);
			if(result.length == 0 || !result[0].equals(expectedResult)) {
				addFailure(new Failure("mismatch result '" + Arrays.asList(result) + "' expected '" + expectedResult + "' subtracting '" + addr2 + "' from '" + addr + "'", addr));
			} else if (resultPairs.length == 4){
				addr = createAddress(resultPairs[2]).getAddress();
				addr2 = createAddress(resultPairs[3]).getAddress();
				expectedResult = addr.spanWithRange(addr2);
				if(result.length == 1 || !result[1].equals(expectedResult)) {
					addFailure(new Failure("mismatch result '" + Arrays.asList(result) + "' expected '" + expectedResult + "' subtracting '" + addr2 + "' from '" + addr + "'", addr));
				}
			} else if(result.length > 1) {
				addFailure(new Failure("mismatch result '" + Arrays.asList(result) + "' expected " + (resultPairs.length / 2) + " ranges subtracting '" + addr2 + "' from '" + addr + "'", addr));
			}
		}
		incrementTestCount();
	}
	
	private static List<Byte> toList(byte bytes[]) {
		Byte newBytes[] = new Byte[bytes.length];
		for(int i = 0; i < bytes.length; i++) {
			newBytes[i] = bytes[i];
		}
		return Arrays.asList(newBytes);
	}
	
	public void testByteExtension(String addrString, byte byteRepresentations[][]) {
		IPAddress addr = createAddress(addrString).getAddress();
		ArrayList<IPAddress> all = new ArrayList<IPAddress>();
		if(addr.isIPv4()) {
			for(byte byteRepresentation[] : byteRepresentations) {
				IPv4Address ipv4Addr = new IPv4Address(byteRepresentation);
				all.add(ipv4Addr);
				
				byte bytes[] = new byte[48];
				Arrays.fill(bytes, (byte) 5);
				System.arraycopy(byteRepresentation, 0, bytes, 5, byteRepresentation.length);
				ipv4Addr = new IPv4Address(bytes, 5, 5 + byteRepresentation.length);
				all.add(ipv4Addr);
			}
			all.add(addr);
			byte lastBytes[] = null;
			for(int i = 0; i < all.size(); i++) {
				byte bytes[] = all.get(i).getBytes();
				if(lastBytes == null) {
					lastBytes = bytes;
					if(bytes.length != IPv4Address.BYTE_COUNT) {
						addFailure(new Failure("bytes length for " + toList(bytes), addr));
					}
					IPv4Address ipv4Addr = new IPv4Address(bytes);
					all.add(ipv4Addr);
					ipv4Addr = new IPv4Address(new BigInteger(bytes).intValue());
					all.add(ipv4Addr);
				} else if(!Arrays.equals(lastBytes, bytes)) {
					addFailure(new Failure("generated addr bytes mismatch " + toList(bytes) + " and " + toList(lastBytes), addr));
				}
			}
		} else {
			for(byte byteRepresentation[] : byteRepresentations) {
				IPv6Address ipv6Addr = new IPv6Address(byteRepresentation);
				all.add(ipv6Addr);
				
				byte bytes[] = new byte[48];
				Arrays.fill(bytes, (byte) 5);
				System.arraycopy(byteRepresentation, 0, bytes, 5, byteRepresentation.length);
				ipv6Addr = new IPv6Address(bytes, 5, 5 + byteRepresentation.length);
				all.add(ipv6Addr);
			}
			all.add(addr);
			byte lastBytes[] = null;
			for(int i = 0; i < all.size(); i++) {
				byte bytes[] = all.get(i).getBytes();
				if(lastBytes == null) {
					lastBytes = bytes;
					if(bytes.length != IPv6Address.BYTE_COUNT) {
						addFailure(new Failure("bytes length for " + toList(bytes), addr));
					}
					IPv6Address ipv6Addr = new IPv6Address(bytes);
					all.add(ipv6Addr);
					BigInteger b = new BigInteger(bytes);
					ipv6Addr = new IPv6Address(b);
					all.add(ipv6Addr);
					byte bs[] = b.toByteArray();
					ipv6Addr = new IPv6Address(bs);
					all.add(ipv6Addr);
				} else if(!Arrays.equals(lastBytes, bytes)) {
					addFailure(new Failure("addr bytes mismatch " + toList(bytes) + " and " + toList(lastBytes), addr));
				}
			}
		}
		ArrayList<byte[]> allBytes = new ArrayList<byte[]>();
		for(int i = 0; i < all.size(); i++) {
			allBytes.add(all.get(i).getBytes());
		}
		for(int i = 0; i < all.size(); i++) {
			for(int j = i; j < all.size(); j++) {
				if(!all.get(i).equals(all.get(j))) {
					addFailure(new Failure("addr mismatch " + all.get(i) + " and " + all.get(j), addr));
				}
				if(!Arrays.equals(allBytes.get(i), allBytes.get(j))) {
					addFailure(new Failure("addr bytes mismatch " + allBytes.get(i) + " and " + allBytes.get(j), addr));
				}
			}
		}
		incrementTestCount();
	}
	
	void testSpanAndMerge(String address1, String address2, int count, String expected[], int rangeCount, String rangeExpected[]) {
		IPAddressString string1 = createAddress(address1);
		IPAddressString string2 = createAddress(address2);
		IPAddress addr1 = string1.getAddress();
		IPAddress addr2 = string2.getAddress();
		IPAddress result[] = addr1.spanWithPrefixBlocks(addr2);
		List<IPAddress> resultList = Arrays.asList(result);
		List<IPAddress> expectedList = new ArrayList<>();
		for(String s : expected) {
			expectedList.add(createAddress(s).getAddress());
		}
		if(!resultList.equals(expectedList)) {
			addFailure(new Failure("merge mismatch merging " + addr1 + " and " + addr2 + " into " + resultList + " expected " + expectedList, addr1));
		}
		if(count != result.length) {
			addFailure(new Failure("merge mismatch merging " + addr1 + " and " + addr2 + " into " + resultList + " expected count of " + count, addr1));
		}
		for(IPAddress addr : result) {
			if(!addr.isPrefixed() || !addr.isPrefixBlock()) {
				addFailure(new Failure("merged addr " + addr + " is not prefix block", addr));
			}
		}
		IPAddress result2[] = addr1.spanWithSequentialBlocks(addr2);
		resultList = Arrays.asList(result2);
		expectedList.clear();
		for(String s : rangeExpected) {
			expectedList.add(createAddress(s).getAddress());
		}
		if(!resultList.equals(expectedList)) {
			addFailure(new Failure("range merge mismatch merging " + addr1 + " and " + addr2 + " into " + resultList + " expected " + expectedList, addr1));
		}
		if(rangeCount != result2.length) {
			addFailure(new Failure("range merge mismatch merging " + addr1 + " and " + addr2 + " into " + resultList + " expected count of " + rangeCount, addr1));
		}
		for(IPAddress addr : result2) {
			if(addr.isPrefixed()) {
				addFailure(new Failure("merged addr " + addr + " is prefixed", addr));
			}
		}
		IPAddress backAgain[] = result[0].mergeToPrefixBlocks(result);
		boolean matches = Arrays.deepEquals(result, backAgain);
		if(!matches) {
			addFailure(new Failure("merge mismatch merging " + addr1 + " and " + addr2 + " into " + Arrays.asList(result) + " and " + Arrays.asList(backAgain), addr1));
		}
		List<IPAddressSeqRange> rangeList = new ArrayList<>();
		for(IPAddress a : result) {
			IPAddressSeqRange range = a.toSequentialRange();
			rangeList.add(range);
		}
		IPAddressSeqRange joined[] = IPAddressSeqRange.join(rangeList.toArray(new IPAddressSeqRange[rangeList.size()]));
		if(joined.length == 0 || joined.length > 1 || !joined[0].getLower().equals(addr1.getLower()) || !joined[0].getUpper().equals(addr2.getUpper())) {
			addFailure(new Failure("joined range " + Arrays.asList(joined) + " did not match "+ addr1 + " and " + addr2, addr1));
		}
		rangeList.clear();
		for(IPAddress a : result2) {
			IPAddressSeqRange range = a.toSequentialRange();
			rangeList.add(range);
		}
		joined = IPAddressSeqRange.join(rangeList.toArray(new IPAddressSeqRange[rangeList.size()]));
		if(joined.length == 0 || joined.length > 1 || !joined[0].getLower().equals(addr1.getLower()) || !joined[0].getUpper().equals(addr2.getUpper())) {
			addFailure(new Failure("joined range " + Arrays.asList(joined) + " did not match "+ addr1 + " and " + addr2, addr1));
		}
		incrementTestCount();
	}
	
	void testMergeRange(String result, String ... addresses) {
		testMerge(result, false, addresses);
	}
	
	void testMergeRange2(String result, String result2, String ... addresses) {
		testMerge2(result, result2, false, addresses);
	}
	
	void testMerge(String result, String ... addresses) {
		testMerge(result, true, addresses);
	}
	
	void testMerge2(String result, String result2, String ... addresses) {
		testMerge2(result, result2, true, addresses);
	}
	
	void testMerge(String result, boolean prefix, String ... addresses) {
		IPAddressString resultStr = createAddress(result);
		IPAddressString string2 = createAddress(addresses[0]);
		IPAddress resultAddr = resultStr.getAddress();
		IPAddress addr2 = string2.getAddress();
		IPAddress mergers[] = new IPAddress[addresses.length - 1];
		for(int i = 0; i < mergers.length; i++) {
			mergers[i] = createAddress(addresses[i + 1]).getAddress();
		}
		IPAddress merged[] = prefix ? addr2.mergeToPrefixBlocks(mergers) : addr2.mergeToSequentialBlocks(mergers);
		if(merged.length != 1 || !resultAddr.equals(merged[0])) {
			addFailure(new Failure("merge " + (prefix ? "prefix" : "range") + " mismatch merging " +  Arrays.asList(addresses) + " expected " + result + " got " + Arrays.asList(merged), resultAddr));
		}
		for(IPAddress m : merged) {
			if(prefix) {
				if(!m.isPrefixed() || !m.isPrefixBlock()) {
					addFailure(new Failure("merged addr " + m + " is not prefix block", m));
				}
			} else {
				if(m.isPrefixed()) {
					addFailure(new Failure("merged addr " + m + " is prefixed", m));
				}
			}
		}
		incrementTestCount();
	}
	
	//like testMerge but the merge results in two addresses
	void testMerge2(String result, String result2, boolean prefix, String ... addresses) {
		IPAddressString resultStr = createAddress(result);
		IPAddressString resultStr2 = createAddress(result2);
		IPAddressString string2 = createAddress(addresses[0]);
		IPAddress resultAddr = resultStr.getAddress();
		IPAddress resultAddr2 = resultStr2.getAddress();
		IPAddress addr2 = string2.getAddress();
		IPAddress mergers[] = new IPAddress[addresses.length - 1];
		for(int i = 0; i < mergers.length; i++) {
			mergers[i] = createAddress(addresses[i + 1]).getAddress();
		}
		IPAddress merged[] = prefix ? addr2.mergeToPrefixBlocks(mergers) : addr2.mergeToSequentialBlocks(mergers);
		HashSet<IPAddress> all = new HashSet<IPAddress>(Arrays.asList(merged));
		HashSet<IPAddress> expected = new HashSet<IPAddress>();
		expected.add(resultAddr);
		expected.add(resultAddr2);
		if(!all.equals(expected)) {
			addFailure(new Failure("merge " + (prefix ? "prefix" : "range") + " mismatch merging " +  Arrays.asList(addresses) + " expected " + expected + " got " + all, resultAddr));
		}
		for(IPAddress m : merged) {
			if(prefix) {
				if(!m.isPrefixed() || !m.isPrefixBlock()) {
					addFailure(new Failure("merged addr " + m + " is not prefix block", m));
				}
			} else {
				if(m.isPrefixed()) {
					addFailure(new Failure("merged addr " + m + " is prefixed", m));
				}
			}
		}
		incrementTestCount();
	}
	
	void testIncrement(String originalStr, long increment, String resultStr) {
		testIncrement(createAddress(originalStr).getAddress(), increment, resultStr == null ? null : createAddress(resultStr).getAddress());
	}
	
	@SuppressWarnings("serial")
	static class MyIPv6Address extends IPv6Address {

		public MyIPv6Address(byte[] bytes, Integer prefixLength) {
			super(bytes, prefixLength);
		}
		
		public MyIPv6Address(MyIPv6AddressSection section, CharSequence zone) {
			super(section, zone);
		}
		
		public MyIPv6Address(MyIPv6AddressSection section) {
			super(section);
		}
		
		@Override
		public IPv6AddressNetwork getNetwork() {
			return myIPv6Network;
		}
	}

	@SuppressWarnings("serial")
	static class MyIPv6AddressSection extends IPv6AddressSection {

		public MyIPv6AddressSection(byte[] bytes, Integer prefixLength) {
			super(bytes, prefixLength);
		}

		public MyIPv6AddressSection(byte[] bytes, int byteStartIndex, int byteEndIndex, int segmentCount, Integer prefixLength) {
			super(bytes, byteStartIndex, byteEndIndex, segmentCount, prefixLength, true, false);
		}
		
		public MyIPv6AddressSection(IPv6AddressSegment[] segments, int startIndex, boolean cloneSegments) {
			super(segments, startIndex, cloneSegments);
		}
		
		public MyIPv6AddressSection(IPv6AddressSegment[] segments, Integer prefixLength) {
			super(segments, prefixLength);
		}
		
		@Override
		public IPv6AddressNetwork getNetwork() {
			return myIPv6Network;
		}
	}

	@SuppressWarnings("serial")
	static class MyIPv6AddressSegment extends IPv6AddressSegment {

		public MyIPv6AddressSegment(int lower, Integer segmentPrefixLength) {
			super(lower, segmentPrefixLength);
		}
		
		public MyIPv6AddressSegment(int lower, int upper, Integer segmentPrefixLength) {
			super(lower, upper, segmentPrefixLength);
		}
		
		@Override
		public IPv6AddressNetwork getNetwork() {
			return myIPv6Network;
		}
	}

	@SuppressWarnings("serial")
	static IPv6AddressNetwork myIPv6Network = new IPv6AddressNetwork() {
		@Override
		public PrefixConfiguration getPrefixConfiguration() {
			return PrefixConfiguration.ALL_PREFIXED_ADDRESSES_ARE_SUBNETS;
		}
		
		@Override
		protected IPv6AddressCreator createAddressCreator() {
			return new IPv6AddressCreator(this) {
				@Override
				public IPv6AddressSection createSection(byte bytes[], Integer prefix) {
					return new MyIPv6AddressSection(bytes, prefix);
				}
				
				@Override
				public IPv6AddressSection createSection(byte bytes[], int byteStartIndex, int byteEndIndex, int segmentCount, Integer prefix) {
					return new MyIPv6AddressSection(bytes, byteStartIndex, byteEndIndex, segmentCount, prefix);
				}
				
				@Override
				public IPv6AddressSegment createSegment(int value, Integer segmentPrefixLength) {
					return new MyIPv6AddressSegment(value, segmentPrefixLength);
				}
				
				@Override
				public IPv6AddressSegment createSegment(int lower, int upper, Integer segmentPrefixLength) {
					return new MyIPv6AddressSegment(lower, upper, segmentPrefixLength);
				}
				
				@Override
				protected IPv6AddressSegment createSegmentInternal(int value, Integer segmentPrefixLength, CharSequence addressStr, int originalVal, 
						boolean isStandardString, int lowerStringStartIndex, int lowerStringEndIndex) {
					return new MyIPv6AddressSegment(value, segmentPrefixLength);
				}
				
				@Override
				protected IPv6AddressSection createPrefixedSectionInternal(IPv6AddressSegment segments[], Integer prefix) {
					return new MyIPv6AddressSection(segments, prefix);
				}
				
				@Override
				protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[]) {
					return new MyIPv6AddressSection(segments, 0, false);
				}

				@Override
				protected IPv6Address createAddressInternal(IPv6AddressSection section, HostIdentifierString from) {
					return new MyIPv6Address((MyIPv6AddressSection) section);
				}
				
				@Override
				protected IPv6Address createAddressInternal(IPv6AddressSection section, CharSequence zone, HostIdentifierString from) {
					return new MyIPv6Address((MyIPv6AddressSection) section, zone);
				}
			};
		}
	};
	
	void testCustomNetwork(PrefixConfiguration prefixConfiguration) {
		byte bytes[] = new byte[16];
		bytes[0] = bytes[15] = 1;
		IPv6Address myAddr1 = new MyIPv6Address(bytes, 64);
		IPv6Address regAddr1 = new IPv6Address(bytes, 64);
		bytes[15] = 0;
		IPv6Address regAddrNet1 = new IPv6Address(bytes, 64);
		testCustomNetwork(myAddr1, regAddr1, regAddrNet1);
		IPAddressStringParameters params = new IPAddressStringParameters.Builder().getIPv6AddressParametersBuilder().setNetwork(myIPv6Network).getParentBuilder().toParams();
		IPv6Address myAddr = new IPAddressString("1::1/64", params).getAddress().toIPv6(); 
		IPv6Address regAddr = new IPAddressString("1::1/64").getAddress().toIPv6();
		IPv6Address regAddrNet = new IPAddressString("1::/64").getAddress().toIPv6();
		testCustomNetwork(myAddr, regAddr, regAddrNet);
	}
	
	void testCustomNetwork(IPv6Address myAddr, IPv6Address regAddr, IPv6Address regAddrNet) {
		if(!regAddr.getCount().equals(prefixConfiguration.allPrefixedAddressesAreSubnets() ? myAddr.getCount() : BigInteger.ONE)) {
			addFailure(new Failure("invalid count " + regAddr.getCount(), myAddr));
		}
		if(myAddr.getCount().equals(BigInteger.ONE)) {
			addFailure(new Failure("invalid count " + myAddr.getCount(), myAddr));
		}
		if(prefixConfiguration.prefixedSubnetsAreExplicit()) {
			if(!regAddrNet.getCount().equals(BigInteger.ONE)) {
				addFailure(new Failure("invalid count " + regAddrNet.getCount(), myAddr));
			}
		} else if(!myAddr.getCount().equals(regAddrNet.getCount())) {
			addFailure(new Failure("invalid count matching " + myAddr.getCount() + " and " + regAddrNet.getCount(), myAddr));
		}
		incrementTestCount();
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
		boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		boolean isAutoSubnets = !isNoAutoSubnets;
		
		testEquivalentPrefix("1.2.3.4", 32);
		if(isNoAutoSubnets) {
			testEquivalentPrefix("0.0.0.0/1", 32);
			testEquivalentPrefix("128.0.0.0/1", 32);
			testEquivalentPrefix("1.2.0.0/15", 32);
			testEquivalentPrefix("1.2.0.0/16", 32);
			testEquivalentPrefix("1:2::/32", 128);
			testEquivalentPrefix("8000::/1", 128);
			testEquivalentPrefix("1:2::/31", 128);
			testEquivalentPrefix("1:2::/34", 128);
		} else {
			testEquivalentPrefix("0.0.0.0/1", 1);
			testEquivalentPrefix("128.0.0.0/1", 1);
			testEquivalentPrefix("1.2.0.0/15", 15);
			testEquivalentPrefix("1.2.0.0/16", 16);
			testEquivalentPrefix("1:2::/32", 32);
			testEquivalentPrefix("8000::/1", 1);
			testEquivalentPrefix("1:2::/31", 31);
			testEquivalentPrefix("1:2::/34", 34);
		}
		testEquivalentPrefix("1.2.3.4/32", 32);
		if(allPrefixesAreSubnets) {
			testEquivalentPrefix("1.2.3.4/1", 1);
			testEquivalentPrefix("1.2.3.4/15", 15);
			testEquivalentPrefix("1.2.3.4/16", 16);
			testEquivalentPrefix("1.2.3.4/32", 32);
			testEquivalentPrefix("1:2::/1", 1);
		} else {
			testEquivalentPrefix("1.2.3.4/1", 32);
			testEquivalentPrefix("1.2.3.4/15", 32);
			testEquivalentPrefix("1.2.3.4/16", 32);
			testEquivalentPrefix("1.2.3.4/32", 32);
			testEquivalentPrefix("1:2::/1", 128);
		}

		testEquivalentPrefix("1:2::/128", 128);
		
		testReverse("255.127.128.255", false, false);
		testReverse("255.127.128.255/16", false, false);
		testReverse("1.2.3.4", false, false);
		testReverse("1.1.2.2", false, false);
		testReverse("1.1.1.1", false, false);
		testReverse("0.0.0.0", true, true);
		
		testReverse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, true);
		testReverse("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff", false, false);
		testReverse("ffff:ffff:8181:ffff:ffff:ffff:ffff:ffff", false, true);
		testReverse("ffff:ffff:c3c3:ffff:ffff:ffff:ffff:ffff", false, true);
		testReverse("ffff:4242:c3c3:2424:ffff:ffff:ffff:ffff", false, true);
		testReverse("ffff:ffff:8000:ffff:ffff:0001:ffff:ffff", true, false);
		testReverse("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff/64", false, false);
		testReverse("1:2:3:4:5:6:7:8", false, false);
		testReverse("1:1:2:2:3:3:4:4", false, false);
		testReverse("1:1:1:1:1:1:1:1", false, false);
		testReverse("::", true, true);
		
		testPrefixes("255.127.128.255",
				16, -5,
				"255.127.128.255",
				"255.127.128.255/32",
				allPrefixesAreSubnets ? "255.127.128.224/27" : "255.127.128.255/27",
				allPrefixesAreSubnets ? "255.127.0.0/16" : "255.127.128.255/16",
				allPrefixesAreSubnets ? "255.127.0.0/16" : "255.127.128.255/16");
		
		testPrefixes("255.127.0.0/16", 
				16, -5, 
				"255.127.0.0/24",
				"255.0.0.0/8",
				"255.96.0.0/11",
				"255.127.0.0/16",
				"255.127.0.0/16");

		testPrefixes("255.127.128.255/32",
				16, -5,
				"255.127.128.255",
				"255.127.128.0/24",
				"255.127.128.224/27",
				"255.127.0.0/16",
				"255.127.0.0/16");
		
		testPrefixes("255.127.0.0/17",
				16, -17,
				"255.127.0.0/24",
				"255.127.0.0/16",
				"0.0.0.0/0",
				"255.127.0.0/16",
				"255.127.0.0/16");
		
		testPrefixes("255.127.0.0/16", 
				18, 17, 
				"255.127.0.0/24",
				"255.0.0.0/8",
				"255.127.0.0",
				"255.127.0.0/18",
				"255.127.0.0/16");
		
		testPrefixes("255.127.0.0/16", 
				18, 16, 
				"255.127.0.0/24",
				"255.0.0.0/8",
				"255.127.0.0/32",
				"255.127.0.0/18",
				"255.127.0.0/16");
		
		testPrefixes("254.0.0.0/7", 
				18, 17, 
				"254.0.0.0/8",
				"0.0.0.0/0",
				"254.0.0.0/24",
				"254.0.0.0/18",
				"254.0.0.0/7");
		
		testPrefixes("254.255.127.128/7", 
				18, 17, 
				allPrefixesAreSubnets ? "254.0.0.0/8" : "254.255.127.128/8",
				allPrefixesAreSubnets ? "0.0.0.0/0" : "0.255.127.128/0",
				allPrefixesAreSubnets ? "254.0.0.0/24" : "254.0.0.128/24",
				allPrefixesAreSubnets ? "254.0.0.0/18" : "254.0.63.128/18",
				allPrefixesAreSubnets ? "254.0.0.0/7" : "254.255.127.128/7");
		
		testPrefixes("254.255.127.128/23", 
				18, 17, 
				allPrefixesAreSubnets ? "254.255.126.0/24" : "254.255.126.128/24",
				allPrefixesAreSubnets ? "254.255.0.0/16" : "254.255.1.128/16",
				allPrefixesAreSubnets ? "254.255.126.0/32" : "254.255.126.0/32",
				allPrefixesAreSubnets ? "254.255.64.0/18" : "254.255.65.128/18",
				allPrefixesAreSubnets ? "254.255.64.0/18" : "254.255.65.128/18");
		
		testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				16, -5,
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
				allPrefixesAreSubnets ? "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0/123" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/123",
				allPrefixesAreSubnets ? "ffff::/16" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/16",
				allPrefixesAreSubnets ? "ffff::/16" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/16");
		
		testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
				16, -5,
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:0/112",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0/123",
				"ffff::/16",
				"ffff::/16");
		
		testPrefixes("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				15, 1,
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				allPrefixesAreSubnets ? "fffe::/15" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/15",
				allPrefixesAreSubnets ? "fffe::/15" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/15");
		
		testPrefixes("ffff:ffff:1:ffff::/64",
				16, -5,
				"ffff:ffff:1:ffff::/80",
				"ffff:ffff:1::/48",
				"ffff:ffff:1:ffe0::/59",
				"ffff::/16",
				"ffff::/16");
		
		testPrefixes("ffff:ffff:1:ffff:ffff:ffff:1:ffff/64",
				16, -5,
				allPrefixesAreSubnets ? "ffff:ffff:1:ffff::/80" : "ffff:ffff:1:ffff:0:ffff:1:ffff/80",
				allPrefixesAreSubnets ? "ffff:ffff:1::/48" : "ffff:ffff:1::ffff:ffff:1:ffff/48",
				allPrefixesAreSubnets ? "ffff:ffff:1:ffe0::/59" : "ffff:ffff:1:ffe0:ffff:ffff:1:ffff/59",
				allPrefixesAreSubnets ? "ffff::/16" : "ffff::ffff:ffff:1:ffff/16",
				allPrefixesAreSubnets ? "ffff::/16" : "ffff::ffff:ffff:1:ffff/16");
		
		testPrefixes("ffff:ffff:1:ffff::/64",
				16, 1,
				"ffff:ffff:1:ffff::/80",
				"ffff:ffff:1::/48",
				"ffff:ffff:1:ffff::/65",
				"ffff::/16",
				"ffff::/16");
		
		testPrefixes("ffff:ffff:1:ffff::/63",
				16, -5,
				"ffff:ffff:1:fffe::/64",
				allPrefixesAreSubnets ? "ffff:ffff:1::/48" : "ffff:ffff:1:1::/48",
				allPrefixesAreSubnets ? "ffff:ffff:1:ffc0::/58" :  "ffff:ffff:1:ffc1::/58",
				allPrefixesAreSubnets ? "ffff::/16" : "ffff:0:0:1::/16",
				allPrefixesAreSubnets ? "ffff::/16" : "ffff:0:0:1::/16");
		
		testPrefixes("ffff:ffff:1:ffff::/63",
				17, -64,
				"ffff:ffff:1:fffe::/64",
				allPrefixesAreSubnets ? "ffff:ffff:1::/48" : "ffff:ffff:1:1::/48",
				allPrefixesAreSubnets ? "::/0" : "0:0:0:1::/0",
				allPrefixesAreSubnets ? "ffff:8000::/17" : "ffff:8000:0:1::/16",
				allPrefixesAreSubnets ? "ffff:8000::/17" : "ffff:8000:0:1::/16");
		
		testPrefixes("ffff:ffff:1:ffff::/63",
				15, -63,
				"ffff:ffff:1:fffe::/64",
				allPrefixesAreSubnets ? "ffff:ffff:1::/48" : "ffff:ffff:1:1::/48",
				allPrefixesAreSubnets ? "::/0" : "0:0:0:1::/0",
				allPrefixesAreSubnets ? "fffe::/15" : "fffe:0:0:1::/15",
				allPrefixesAreSubnets ? "fffe::/15" : "fffe:0:0:1::/15");
		
		testPrefixes("ffff:ffff:1:ffff::/63",
				65, 1,
				"ffff:ffff:1:fffe::/64",
				allPrefixesAreSubnets ? "ffff:ffff:1::/48" : "ffff:ffff:1:1::/48",
				"ffff:ffff:1:fffe::/64",
				"ffff:ffff:1:fffe::/65",
				allPrefixesAreSubnets ? "ffff:ffff:1:fffe::/63" : "ffff:ffff:1:ffff::/63");
		
		testPrefixes("ffff:ffff:1:ffff:ffff:ffff:ffff:ffff/128",
				127, 1,
				"ffff:ffff:1:ffff:ffff:ffff:ffff:ffff",
				"ffff:ffff:1:ffff:ffff:ffff:ffff::/112",
				"ffff:ffff:1:ffff:ffff:ffff:ffff:ffff",
				"ffff:ffff:1:ffff:ffff:ffff:ffff:fffe/127",
				"ffff:ffff:1:ffff:ffff:ffff:ffff:fffe/127");
		
		testBitwiseOr("1.2.0.0", null, "0.0.3.4", "1.2.3.4");
		testBitwiseOr("1.2.0.0", null, "0.0.0.0", "1.2.0.0");
		testBitwiseOr("1.2.0.0", null, "255.255.255.255", "255.255.255.255");
		testBitwiseOr("1.0.0.0/8", 16, "0.2.3.0", "1.2.3.0/24");//note the prefix length is dropped to become "1.2.3.*", but equality still holds
		testBitwiseOr("1.2.0.0/16", 8, "0.0.3.0", "1.2.3.0/24");//note the prefix length is dropped to become "1.2.3.*", but equality still holds
		
		testBitwiseOr("0.0.0.0", null, "1.2.3.4", "1.2.3.4");
		testBitwiseOr("0.0.0.0", 1, "1.2.3.4", "1.2.3.4");
		testBitwiseOr("0.0.0.0", -1, "1.2.3.4", "1.2.3.4/31");
		testBitwiseOr("0.0.0.0", 0, "1.2.3.4", "1.2.3.4");
		testBitwiseOr("0.0.0.0/0", -1, "1.2.3.4", isNoAutoSubnets ? "1.2.3.4" : null);
		testBitwiseOr("0.0.0.0/16", null, "0.0.255.255", "0.0.255.255");
		
		testPrefixBitwiseOr("0.0.0.0/16", 18, "0.0.98.8", isNoAutoSubnets ? "0.0.64.0/18" : null, isNoAutoSubnets || allPrefixesAreSubnets ? "0.0.98.8/16" : null);   
		testPrefixBitwiseOr("0.0.0.0/16", 18, "0.0.194.8", "0.0.192.0/18", isNoAutoSubnets || allPrefixesAreSubnets ? "0.0.194.8/16" : null);
		
		//no zeroing going on - first one applies mask up to the new prefix and then applies the prefix, second one masks everything and then keeps the prefix as well (which in the case of all prefixes subnets wipes out any masking done in host)
		testPrefixBitwiseOr("0.0.0.1/16", 18, "0.0.194.8", allPrefixesAreSubnets ? "0.0.192.0/18" : "0.0.192.1/18", allPrefixesAreSubnets ? "0.0.0.0/16" : "0.0.194.9/16");
		
		testPrefixBitwiseOr("1.2.0.0/16", 24, "0.0.3.248", !isNoAutoSubnets ? null : "1.2.3.0/24", isNoAutoSubnets ? "1.2.3.248/16" : (allPrefixesAreSubnets ? "1.2.0.0/16" : null));
		testPrefixBitwiseOr("1.2.0.0/16", 23, "0.0.3.0", !isNoAutoSubnets ? null : "1.2.2.0/23", isNoAutoSubnets ? "1.2.3.0/16" : (allPrefixesAreSubnets ? "1.2.0.0/16" : null));
		testPrefixBitwiseOr("1.2.0.0", 24, "0.0.3.248", "1.2.3.0/24", "1.2.3.248");
		testPrefixBitwiseOr("1.2.0.0", 24, "0.0.3.0", "1.2.3.0/24", "1.2.3.0");
		testPrefixBitwiseOr("1.2.0.0", 23, "0.0.3.0", "1.2.2.0/23", "1.2.3.0");
		
		testPrefixBitwiseOr("::/32", 36, "0:0:6004:8::", isNoAutoSubnets ? "0:0:6000::/36" : null, isNoAutoSubnets || allPrefixesAreSubnets ? "0:0:6004:8::/32" : null);
		testPrefixBitwiseOr("::/32", 36, "0:0:f000:8::", isNoAutoSubnets ? "0:0:f000::/36" : "0:0:f000::/36", isNoAutoSubnets || allPrefixesAreSubnets ? "0:0:f000:8::/32" : null);
		
		testPrefixBitwiseOr("1:2::/32", 48, "0:0:3:effe::", isNoAutoSubnets ? "1:2:3::/48" : null, isNoAutoSubnets || allPrefixesAreSubnets ? "1:2:3:effe::/32" : null);
		testPrefixBitwiseOr("1:2::/32", 47, "0:0:3::", isNoAutoSubnets ? "1:2:2::/47": null, isNoAutoSubnets || allPrefixesAreSubnets ? "1:2:3::/32" : null);
		testPrefixBitwiseOr("1:2::/46", 48, "0:0:3:248::", "1:2:3::/48", isNoAutoSubnets || allPrefixesAreSubnets ? "1:2:3:248::/46" : null);
		testPrefixBitwiseOr("1:2::/48", 48, "0:0:3:248::", "1:2:3::/48", isNoAutoSubnets || allPrefixesAreSubnets ? "1:2:3:248::/48" : null);
		testPrefixBitwiseOr("1:2::/48", 47, "0:0:3::", "1:2:2::/47", "1:2:3::/48");
		testPrefixBitwiseOr("1:2::", 48, "0:0:3:248::", "1:2:3::/48", "1:2:3:248::");
		testPrefixBitwiseOr("1:2::", 47, "0:0:3::", "1:2:2::/47", "1:2:3::");
		
		testBitwiseOr("1:2::", null, "0:0:3:4::", "1:2:3:4::");
		testBitwiseOr("1:2::", null, "::", "1:2::");
		testBitwiseOr("1:2::", null, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		testBitwiseOr("1:2::", null, "fffe:fffd:ffff:ffff:ffff:ffff:ff0f:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ff0f:ffff");
		testBitwiseOr("1::/16", 32, "0:2:3::", "1:2:3::/48");//note the prefix length is dropped to become "1.2.3.*", but equality still holds
		testBitwiseOr("1:2::/32", 16, "0:0:3::", "1:2:3::/48");//note the prefix length is dropped to become "1.2.3.*", but equality still holds
		
		testBitwiseOr("::", null, "::1:2:3:4", "::1:2:3:4");
		testBitwiseOr("::", 1, "::1:2:3:4", "::1:2:3:4");
		testBitwiseOr("::", -1, "::1:2:3:4", "::1:2:3:4/127");
		testBitwiseOr("::", 0, "::1:2:3:4", "::1:2:3:4");
		testBitwiseOr("::/0", -1, "::1:2:3:4", isNoAutoSubnets ? "::1:2:3:4" : null);
		testBitwiseOr("::/32", null, "::ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:ffff:ffff:ffff:ffff:ffff");
		
		testDelimitedCount("1,2.3.4,5.6", 4); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1,2.3,6.4,5.6,8", 16); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1:2:3:6:4:5:6:8", 1); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		testDelimitedCount("1:2,3,4:3:6:4:5,6fff,7,8,99:6:8", 15); //this will iterate through 1.3.4.6 1.3.5.6 2.3.4.6 2.3.5.6
		
		ipv6test(allowsRange(), "aa:-1:cc::d:ee:f");//same as "aa:0-1:cc::d:ee:f"
		ipv6test(allowsRange(), "aa:-dd:cc::d:ee:f");//same as "aa:0-dd:cc::d:ee:f"
		ipv6test(allowsRange(), "aa:1-:cc:d::ee:f");//same as "aa:1-ff:cc:d::ee:f"
		ipv6test(allowsRange(), "-1:aa:cc:d::ee:f");//same as "aa:0-1:cc:d::ee:f"
		ipv6test(allowsRange(), "1-:aa:cc:d::ee:f");//same as "aa:0-1:cc:d::ee:f"
		ipv6test(allowsRange(), "aa:cc:d::ee:f:1-");
		ipv6test(allowsRange(), "aa:0-1:cc:d::ee:f");
		ipv6test(allowsRange(), "aa:1-ff:cc:d::ee:f");
		
		ipv4test(allowsRange(), "1.-1.33.4");
		ipv4test(allowsRange(), "-1.22.33.4");
		ipv4test(allowsRange(), "22.1-.33.4");
		ipv4test(allowsRange(), "22.33.4.1-");
		ipv4test(allowsRange(), "1-.22.33.4");
		ipv4test(allowsRange(), "22.0-1.33.4");
		ipv4test(allowsRange(), "22.1-22.33.4");
		
		ipv4test(false, "1.+1.33.4");
		ipv4test(false, "+1.22.33.4");
		ipv4test(false, "22.1+.33.4");
		ipv4test(false, "22.33.4.1+");
		ipv4test(false, "1+.22.33.4");
		ipv4test(false, "22.0+1.33.4");
		ipv4test(false, "22.1+22.33.4");

		testMatches(false, "1::", "2::");
		testMatches(false, "1::", "1.2.3.4");
		testMatches(true, "1::", "1:0::");
		testMatches(true, "f::", "F:0::");
		testMatches(false, "1::", "1:0:1::");
		testMatches(true, "1.2.3.4", "1.2.3.4");
		testMatches(true, "1.2.3.4", "001.2.3.04");
		testMatches(true, "1.2.3.4", "::ffff:1.2.3.4");//ipv4 mapped
		testMatches(true, "1.2.3.4/32", "1.2.3.4");
		
		//inet_aton style
		testMatches(true, "1.2.3", "1.2.0.3", true);
		testMatches(true, "1.2.3.4", "0x1.0x2.0x3.0x4", true);
		testMatches(true, "1.2.3.4", "01.02.03.04", true);
		testMatches(true, "0.0.0.4", "00.0x0.0x00.04", true);
		testMatches(true, "11.11.11.11", "11.0xb.013.0xB", true);
		testMatches(true, "11.11.0.11", "11.0xb.0xB", true);
		testMatches(true, "11.11.0.11", "11.0x00000000000000000b.0000000000000000000013", true);
		if(allPrefixesAreSubnets) {
			testMatches(true, "11.11.0.11/16", "11.720896/16", true);
			testMatches(true, "11.0.0.11/16", "184549376/16", true);
			testMatches(true, "11.0.0.11/16", "0xb000000/16", true);
			testMatches(true, "11.0.0.11/16", "01300000000/16", true);
		}
		testMatches(true, "11.11.0.11/16", "11.720907/16", true);
		testMatches(true, "11.0.0.11/16", "184549387/16", true);
		testMatches(true, "11.0.0.11/16", "0xb00000b/16", true);
		testMatches(true, "11.0.0.11/16", "01300000013/16", true);
		
		testMatches(true, "/16", "/16");//no prefix to speak of, since not known to be ipv4 or ipv6
		testMatches(false, "/16", "/15");
		testMatches(true, "/15", "/15");
		testMatches(true, "/0", "/0");
		testMatches(false, "/1", "/0");
		testMatches(false, "/0", "/1");
		testMatches(true, "/128", "/128");
		testMatches(false, "/127", "/128");
		testMatches(false, "/128", "/127");
		
		testMatches(true, "11::1.2.3.4/112", "11::102:304/112");
		testMatches(true, "11:0:0:0:0:0:1.2.3.4/112", "11:0:0:0:0:0:102:304/112");
		
		testMatches(true, "1:2::/32", "1:2::/ffff:ffff::");
		testMatches(true, "1:2::/1", "1:2::/8000::");
		if(allPrefixesAreSubnets) {
			testMatches(true, "1:2::", "1:2::/ffff:ffff::1");
		} else {
			testMatches(true, "1:2::/1", "1:2::/ffff:ffff::1");
		}
		
		testMatches(true, "1:2::/31", "1:2::/ffff:fffe::");

		testMatches(true, "0.2.3.0", "1.2.3.4/0.255.255.0");
		if(allPrefixesAreSubnets) {
			testMatches(true, "1.2.3.4/16", "1.2.3.4/255.255.0.0");
			testMatches(true, "1.2.3.4/15", "1.2.3.4/255.254.0.0");
			testMatches(true, "1.2.3.4/17", "1.2.3.4/255.255.128.0");
		} else {
			testMatches(true, "1.2.128.0/16", "1.2.128.4/255.255.254.1");
			testMatches(true, "1.2.2.0/15", "1.2.3.4/255.254.2.3");
			testMatches(true, "1.2.0.4/17", "1.2.3.4/255.255.128.5");
		}
		
		testMatches(allPrefixesAreSubnets, "1.2.0.0/16", "1.2.3.4/255.255.0.0");
		testMatches(allPrefixesAreSubnets, "1.2.0.0/15", "1.2.3.4/255.254.0.0");
		testMatches(allPrefixesAreSubnets, "1.2.0.0/17", "1.2.3.4/255.255.128.0");
		
		testMatches(true, "1.2.3.4/16", "1.2.3.4/255.255.0.0");
		testMatches(true, "1.2.3.4/15", "1.2.3.4/255.254.0.0");
		testMatches(true, "1.2.3.4/17", "1.2.3.4/255.255.128.0");
		
		testMatches(false, "1.1.3.4/15", "1.2.3.4/255.254.0.0");
		testMatches(false, "1.1.3.4/17", "1.2.3.4/255.255.128.0");
		
		testMatches(false, "0.2.3.4", "1.2.3.4/0.255.255.0");
		testMatches(false, "1.2.3.0", "1.2.3.4/0.255.255.0");
		testMatches(false, "1.2.3.4", "1.2.3.4/0.255.255.0");
		testMatches(false, "1.1.3.4/16", "1.2.3.4/255.255.0.0");

		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:1.2.3.4");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:0.0.0.0", "1:2:3:4:5:6::");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:0:0.0.0.0", "1:2:3:4:5::");
		
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%12", "1:2:3:4:5:6:102:304%12");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%a", "1:2:3:4:5:6:102:304%a");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%", "1:2:3:4:5:6:102:304%");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%%", "1:2:3:4:5:6:102:304%%"); //the % reappearing as the zone itself is ok
		
		testMatches(false, "1:2:3:4:5:6:1.2.3.4%a", "1:2:3:4:5:6:102:304");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%", "1:2:3:4:5:6:102:304%");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%-a-", "1:2:3:4:5:6:102:304%-a-"); //we don't validate the zone itself, so the % reappearing as the zone itself is ok
		
		if(isNoAutoSubnets) {
			testMatches(true, "1::%-.1/16", "1::%-.1");//first one is prefixed and zone, second one just zone
			testMatches(false, "1::/16", "1::%-.1");//first one has no zone, second one has zone
			testMatches(true, "1::%-1/16", "1::%-1");//first one is prefixed and zone, second one just zone
			testMatches(false, "1::/16", "1::%-1");//first one has no zone, second one has zone
		}
		testMatches(true, "1::0.0.0.0%-1", "1::%-1");
		testMatches(false, "1::0.0.0.0", "1::%-1");//zones do not match
		testMatches(false, "1::0.0.0.0%-1", "1::");//zones do not match
		
		if(allPrefixesAreSubnets) {
			testMatches(true, "1:2:3:4:5:6:1.2.3.4/64", "1:2:3:4::/64");
			
			//more stuff with prefix in mixed part 1:2:3:4:5:6:1.2.3.4/128
			testMatches(true, "1:2:3:4:5:6:1.2.3.4/96", "1:2:3:4:5:6::/96");
			testMatches(true, "1:2:3:4:5:6:255.2.3.4/97", "1:2:3:4:5:6:8000::/97");
			testMatches(true, "1:2:3:4:5:6:1.2.3.4/112", "1:2:3:4:5:6:102::/112");
			testMatches(true, "1:2:3:4:5:6:1.2.255.4/115", "1:2:3:4:5:6:102:e000/115");
		}
		testMatches(true, "1:2:3:4::0.0.0.0/64", "1:2:3:4::/64");
		
		//more stuff with prefix in mixed part 1:2:3:4:5:6:1.2.3.4/128
		testMatches(true, "1:2:3:4:5:6:0.0.0.0/96", "1:2:3:4:5:6::/96");
		testMatches(true, "1:2:3:4:5:6:128.0.0.0/97", "1:2:3:4:5:6:8000::/97");
		testMatches(true, "1:2:3:4:5:6:1.2.0.0/112", "1:2:3:4:5:6:102::/112");
		testMatches(true, "1:2:3:4:5:6:1.2.224.0/115", "1:2:3:4:5:6:102:e000/115");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/128", "1:2:3:4:5:6:102:304/128");
		
		ipv4test(true, "1.2.3.4/255.1.0.0");
		ipv4test(false, "1.2.3.4/1::1");//mask mismatch
		ipv6test(true, "1:2::/1:2::");
		ipv6test(false, "1:2::/1:2::/16");
		ipv6test(false, "1:2::/1.2.3.4");//mask mismatch
		
		if(allPrefixesAreSubnets) {
			//second arg must be the normalized string
			testCIDRSubnets("9.129.237.26/0", "0.0.0.0/0"); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
			testCIDRSubnets("9.129.237.26/1", "0.0.0.0/1");
			testCIDRSubnets("9.129.237.26/4", "0.0.0.0/4");
			testCIDRSubnets("9.129.237.26/5", "8.0.0.0/5");
			testCIDRSubnets("9.129.237.26/7", "8.0.0.0/7");
			testCIDRSubnets("9.129.237.26/8", "9.0.0.0/8");
			testCIDRSubnets("9.129.237.26/9", "9.128.0.0/9");
			testCIDRSubnets("9.129.237.26/15", "9.128.0.0/15");
			testCIDRSubnets("9.129.237.26/16", "9.129.0.0/16");
			testCIDRSubnets("9.129.237.26/30", "9.129.237.24/30");
		}
		testCIDRSubnets("9.129.237.26/32", "9.129.237.26/32");
		
		if(allPrefixesAreSubnets) {
			testCIDRSubnets("ffff::ffff/0", "0:0:0:0:0:0:0:0/0"); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
			testCIDRSubnets("ffff::ffff/1", "8000:0:0:0:0:0:0:0/1");
			testCIDRSubnets("ffff::ffff/30", "ffff:0:0:0:0:0:0:0/30");
			testCIDRSubnets("ffff::ffff/32", "ffff:0:0:0:0:0:0:0/32");
			testCIDRSubnets("ffff::ffff/126", "ffff:0:0:0:0:0:0:fffc/126");
		}
		testCIDRSubnets("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff/128");
		
		testMasksAndPrefixes();
		
		if(allPrefixesAreSubnets) {
			testContains("9.129.237.26/0", "1.2.3.4", false);
			testContains("9.129.237.26/1", "127.2.3.4", false);
			testNotContains("9.129.237.26/1", "128.2.3.4");
			testContains("9.129.237.26/4", "15.2.3.4", false);
			testContains("9.129.237.26/4", "9.129.237.26/16", false);
			testContains("9.129.237.26/5", "15.2.3.4", false);
			testContains("9.129.237.26/7", "9.2.3.4", false);
			testContains("9.129.237.26/8", "9.2.3.4", false);
			testContains("9.129.237.26/9", "9.255.3.4", false);
			testContains("9.129.237.26/15", "9.128.3.4", false);
			testNotContains("9.129.237.26/15", "10.128.3.4");
			testContains("9.129.237.26/16", "9.129.3.4", false);
			testContains("9.129.237.26/30", "9.129.237.27", false);
			testContains("9.129.237.26/30", "9.129.237.27/31", false);
		}
		
		testContains("0.0.0.0/0", "1.2.3.4", isAutoSubnets, false);
		testContains("0.0.0.0/1", "127.2.3.4", isAutoSubnets, false);
		testNotContains("0.0.0.0/1", "128.2.3.4");
		testContains("0.0.0.0/4", "15.2.3.4", isAutoSubnets, false);
		testContains("0.0.0.0/4", "9.129.0.0/16", isAutoSubnets, false);
		testContains("8.0.0.0/5", "15.2.3.4", isAutoSubnets, false);
		testContains("8.0.0.0/7", "9.2.3.4", isAutoSubnets, false);
		testContains("9.0.0.0/8", "9.2.3.4", isAutoSubnets, false);
		testContains("9.128.0.0/9", "9.255.3.4", isAutoSubnets, false);
		testContains("9.128.0.0/15", "9.128.3.4", isAutoSubnets, false);
		testNotContains("9.128.0.0/15", "10.128.3.4");
		testContains("9.129.0.0/16", "9.129.3.4", isAutoSubnets, false);
		testContains("9.129.237.24/30", "9.129.237.27", isAutoSubnets, false);
		testContains("9.129.237.24/30", "9.129.237.26/31", isAutoSubnets, false);
		
		
		testContains("9.129.237.26/32", "9.129.237.26", true);
		testNotContains("9.129.237.26/32", "9.128.237.26");

		
		if(allPrefixesAreSubnets) {
			testContains("9.129.237.26/0", "0.0.0.0/0", true);
			testContains("9.129.237.26/1", "0.0.0.0/1", true);
			testContains("9.129.237.26/4", "0.0.0.0/4", true);
			testContains("9.129.237.26/5", "8.0.0.0/5", true);
			testContains("9.129.237.26/7", "8.0.0.0/7", true);
			testContains("9.129.237.26/8", "9.0.0.0/8", true);
			testContains("9.129.237.26/9", "9.128.0.0/9", true);
			testContains("9.129.237.26/15", "9.128.0.0/15", true);
			testContains("9.129.237.26/16", "9.129.0.0/16", true);
			testContains("9.129.237.26/30", "9.129.237.24/30", true);
		}
		
		testContains("0.0.0.0/0", "0.0.0.0/0", true);
		testContains("0.0.0.0/1", "0.0.0.0/1", true);
		testContains("0.0.0.0/4", "0.0.0.0/4", true);
		testContains("8.0.0.0/5", "8.0.0.0/5", true);
		testContains("8.0.0.0/7", "8.0.0.0/7", true);
		testContains("9.0.0.0/8", "9.0.0.0/8", true);
		testContains("9.128.0.0/9", "9.128.0.0/9", true);
		testContains("9.128.0.0/15", "9.128.0.0/15", true);
		testContains("9.129.0.0/16", "9.129.0.0/16", true);
		testContains("9.129.237.24/30", "9.129.237.24/30", true);
		testContains("9.129.237.26/32", "9.129.237.26/32", true);
		
		testContains("::ffff:1.2.3.4", "1.2.3.4", true);//ipv4 mapped
		
		if(allPrefixesAreSubnets) {
			testContains("::ffff:1.2.3.4/112", "1.2.3.4", false);
			testContains("::ffff:1.2.3.4/112", "1.2.3.4/16", true);
			testContains("ffff::ffff/0", "a:b:c:d:e:f:a:b", false);
			testContains("ffff::ffff/1", "8aaa:b:c:d:e:f:a:b", false);
			testNotContains("ffff::ffff/30", "ffff:4:c:d:e:f:a:b");
			testContains("ffff::ffff/30", "ffff:3:c:d:e:f:a:b", false);
			testContains("ffff::ffff/30", "ffff:0:c:d:e:f:a:b", false);
			testContains("ffff::ffff/32", "ffff:0:c:d:e:f:a:b", false);
			testContains("ffff:0::ffff/32", "ffff::c:d:e:f:a:b", false);
			testNotContains("ffff:1::ffff/32", "ffff::c:d:e:f:a:b");
			testContains("ffff::ffff/32", "ffff:0:ffff:d:e:f:a:b", false);
			testNotContains("ffff::ffff/32", "ffff:1:ffff:d:e:f:a:b");
			testContains("ffff::ffff/126", "ffff:0:0:0:0:0:0:ffff", false);
			testContains("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff", true);
		}
		testContains("::ffff:1.2.0.0/112", "1.2.3.4", isAutoSubnets, false);
		testContains("::ffff:1.2.0.0/112", "1.2.0.0/16", true);

		testContains("0:0:0:0:0:0:0:0/0", "a:b:c:d:e:f:a:b", isAutoSubnets, false);
		testContains("8000:0:0:0:0:0:0:0/1", "8aaa:b:c:d:e:f:a:b", isAutoSubnets, false);
		testNotContains("8000:0:0:0:0:0:0:0/1", "aaa:b:c:d:e:f:a:b");
		testContains("ffff:0:0:0:0:0:0:0/30", "ffff:3:c:d:e:f:a:b", isAutoSubnets, false);
		testNotContains("ffff:0:0:0:0:0:0:0/30", "ffff:4:c:d:e:f:a:b");
		testContains("ffff:0:0:0:0:0:0:0/32", "ffff:0:ffff:d:e:f:a:b", isAutoSubnets, false);
		testNotContains("ffff:0:0:0:0:0:0:0/32", "ffff:1:ffff:d:e:f:a:b");
		testContains("ffff:0:0:0:0:0:0:fffc/126", "ffff:0:0:0:0:0:0:ffff", isAutoSubnets, false);
		testContains("ffff:0:0:0:0:0:0:ffff/128", "ffff:0:0:0:0:0:0:ffff", true);
		
		if(allPrefixesAreSubnets) {
			testContains("ffff::ffff/0", "0:0:0:0:0:0:0:0/0", true);
			testContains("ffff::ffff/1", "8000:0:0:0:0:0:0:0/1", true);
			testContains("ffff::ffff/30", "ffff:0:0:0:0:0:0:0/30", true);
			testContains("ffff::ffff/32", "ffff:0:0:0:0:0:0:0/32", true);
			testContains("ffff::ffff/126", "ffff:0:0:0:0:0:0:fffc/126", true);
			testContains("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff/128", true);
		}
		testContains("::/0", "0:0:0:0:0:0:0:0/0", true);
		testContains("8000::/1", "8000:0:0:0:0:0:0:0/1", true);
		testContains("ffff::/30", "ffff:0:0:0:0:0:0:0/30", true);
		testContains("ffff::/32", "ffff:0:0:0:0:0:0:0/32", true);
		testContains("ffff::fffc/126", "ffff:0:0:0:0:0:0:fffc/126", true);
		testContains("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff/128", true);
		
		if(isAutoSubnets) {
			testContains("2001:db8::/120", "2001:db8::1", false);
		} else {
			testNotContains("2001:db8::/120", "2001:db8::1");
		}
		testContains("2001:db8::1/120", "2001:db8::1", !allPrefixesAreSubnets);
		if(allPrefixesAreSubnets) {
			testContains("2001:db8::1/120", "2001:db8::", false);
		} else {
			testNotContains("2001:db8::1/120", "2001:db8::");
		}
		testContains("2001:db8::/112", "2001:db8::", !isAutoSubnets);
		testContains("2001:db8::/111", "2001:db8::", !isAutoSubnets);
		testContains("2001:db8::/113", "2001:db8::", !isAutoSubnets);
		testNotContains("2001:db80::/113", "2001:db8::");
		testNotContains("2001:db0::/113", "2001:db8::");
		testNotContains("2001:db7::/113", "2001:db8::");
		
		testContains("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128", !allPrefixesAreSubnets);
		testContains("2001:0db8:85a3::8a2e:0370:7334/120", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128", !allPrefixesAreSubnets);
		testContains("2001:0db8:85a3:0000:0000:8a2e:0370:7334/120", "2001:0db8:85a3::8a2e:0370:7334/128", !allPrefixesAreSubnets);
		testContains("2001:0db8:85a3::8a2e:0370:7334/120", "2001:0db8:85a3::8a2e:0370:7334/128", !allPrefixesAreSubnets);
		
		testContains("2001:0db8:85a3:0000:0000:8a2e:0370::/120", "2001:0db8:85a3:0000:0000:8a2e:0370::/128", !isAutoSubnets);
		testContains("2001:0db8:85a3:0000:0000:8a2e:0370::/120", "2001:0db8:85a3::8a2e:0370:0/128", !isAutoSubnets);
		testContains("2001:0db8:85a3::8a2e:0370:0/120", "2001:0db8:85a3:0000:0000:8a2e:0370::/128", !isAutoSubnets);
		testContains("2001:0db8:85a3::8a2e:0370:0/120", "2001:0db8:85a3::8a2e:0370:0/128", !isAutoSubnets);
		
		if(allPrefixesAreSubnets) {
			testContains("12::/4", "123::", false);
		} else {
			testNotContains("12::/4", "123::");
		}
		testNotContains("12::/4", "1234::");
		testNotContains("12::/8", "123::");
		testNotContains("123::/8", "1234::");
		testNotContains("12::/12", "123::");
		testNotContains("12::/16", "123::");
		testNotContains("12::/24", "123::");
		
		if(allPrefixesAreSubnets) {
			testContains("1:12::/20", "1:123::", false);
		} else {
			testNotContains("1:12::/20", "1:123::");
		}
		testNotContains("1:12::/20", "1:1234::");
		testNotContains("1:12::/24", "1:123::");
		testNotContains("1:123::/24", "1:1234::");
		testNotContains("1:12::/28", "1:123::");
		testNotContains("1:12::/32", "1:123::");
		testNotContains("1:12::/40", "1:123::");
		
		
		if(isAutoSubnets) {
			testNotContains("1.0.0.0/16", "1.0.0.0/8", true);
			testContains("::/4", "123::", false);
		} else {
			testContains("1.0.0.0/16", "1.0.0.0/8", true);
			testNotContains("::/4", "123::");
		}
		testNotContains("::/4", "1234::");
		testNotContains("::/8", "123::");
		testNotContains("100::/8", "1234::");
		testNotContains("10::/12", "123::");
		testNotContains("10::/16", "123::");
		testNotContains("10::/24", "123::");
		
		if(allPrefixesAreSubnets) {
			testContains("1:12::/20", "1:123::", false);
		} else {
			testNotContains("1:12::/20", "1:123::");
		}
		testNotContains("1::/20", "1:1234::");
		testNotContains("1::/24", "1:123::");
		testNotContains("1:100::/24", "1:1234::");
		testNotContains("1:10::/28", "1:123::");
		testNotContains("1:10::/32", "1:123::");
		testNotContains("1:10::/40", "1:123::");
		
		
		testContains("1.0.0.0/16", "1.0.0.0/24", !isAutoSubnets);
		
		prefixtest(true, "/24");
		
		prefixtest(true, "/33");
		prefixtest(false, "/129");
		
		prefixtest(false, "/2 4");
		prefixtest(false, "/ 24");
		prefixtest(false, "/-24");
		prefixtest(false, "/+24");
		prefixtest(false, "/x");
		
		prefixtest(false, "/1.2.3.4");
		prefixtest(false, "/1::1");
		
		//test some valid and invalid prefixes
		ipv4test(true, "1.2.3.4/1");
		ipv4test(false, "1.2.3.4/ 1");
		ipv4test(false, "1.2.3.4/-1");
		ipv4test(false, "1.2.3.4/+1");
		ipv4test(false, "1.2.3.4/");
		ipv4test(true, "1.2.3.4/1.2.3.4");
		ipv4test(false, "1.2.3.4/x");
		ipv4test(false, "1.2.3.4/33");//we are not allowing extra-large prefixes
		ipv6test(true, "1::1/1");
		ipv6test(false, "1::1/-1");
		ipv6test(false, "1::1/");
		ipv6test(false, "1::1/x");
		ipv6test(false, "1::1/129");//we are not allowing extra-large prefixes
		ipv6test(true, "1::1/1::1");
		
		
		testNetmasks(0, "0.0.0.0/0", "0.0.0.0", "255.255.255.255", "::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); //test that the given prefix gives ipv4 and ipv6 addresses matching the netmasks
		testNetmasks(1, "128.0.0.0/1", "128.0.0.0", "127.255.255.255", "8000::/1", "8000::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		testNetmasks(15, "255.254.0.0/15", "255.254.0.0", "0.1.255.255", "fffe::/15", "fffe::", "1:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		testNetmasks(16, "255.255.0.0/16", "255.255.0.0", "0.0.255.255", "ffff::/16", "ffff::", "::ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		testNetmasks(17, "255.255.128.0/17", "255.255.128.0", "0.0.127.255", "ffff:8000::/17", "ffff:8000::", "::7fff:ffff:ffff:ffff:ffff:ffff:ffff");
		testNetmasks(31, "255.255.255.254/31", "255.255.255.254", "0.0.0.1", "ffff:fffe::/31", "ffff:fffe::", "::1:ffff:ffff:ffff:ffff:ffff:ffff");
		testNetmasks(32, "255.255.255.255/32", "255.255.255.255", "0.0.0.0", "ffff:ffff::/32", "ffff:ffff::", "::ffff:ffff:ffff:ffff:ffff:ffff");
		testNetmasks(127, "255.255.255.255/127", null, "0.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "::1");
		
		testNetmasks(128, "255.255.255.255/128", null, "0.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::");
		testNetmasks(129, "255.255.255.255/129", null,  "0.0.0.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/129", null, "::");
		
		checkNotMask("254.255.0.0");
		checkNotMask("255.255.0.1");
		checkNotMask("0.1.0.0");
		checkNotMask("0::10");
		checkNotMask("1::0");
		
		
			
		
		//Some mask/address combinations do not result in a contiguous range and thus don't work
		//The underlying rule is that mask bits that are 0 must be above the resulting segment range.  
		//Any bit in the mask that is 0 must not fall below any bit in the masked segment rrange that is different between low and high
		//Any network mask must eliminate the entire range in the segment
		//Any host mask is fine
		
		testSubnet("1.2.0.0", "0.0.255.255", 16 /* mask is valid with prefix */, "0.0.0.0/16" /* mask is valid alone */, "0.0.0.0", "1.2.0.0/16" /* prefix alone */);
		testSubnet("1.2.0.0", "0.0.255.255", 17, "0.0.0.0/17" , "0.0.0.0", "1.2.0.0/17");
		testSubnet("1.2.128.0", "0.0.255.255", 17, "0.0.128.0/17" , "0.0.128.0", "1.2.128.0/17");
		testSubnet("1.2.0.0", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.0.0", "1.2.0.0/15");
		testSubnet("1.2.0.0", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.0.0", "1.2.0.0/15");

		testSubnet("1.2.0.0/15", "0.0.255.255", 16, "0.0.0.0/16", isNoAutoSubnets ? "0.0.0.0" : "0.0.*.*", "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "0.0.255.255", 15, "0.0.0.0/15" , isNoAutoSubnets ? "0.0.0.0" : "0.0.*.*", "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "0.0.255.255", 15, "0.0.0.0/15" , isNoAutoSubnets ? "0.0.0.0" : "0.0.*.*", "1.2.0.0/15");
		testSubnet("1.0.0.0/15", "0.1.255.255", 15, "0.0.0.0/15" , isNoAutoSubnets ? "0.0.0.0" : "0.0-1.*.*", "1.0.0.0/15");
		
		testSubnet("1.2.0.0/17", "0.0.255.255", 16 , "0.0.0.0/16", isNoAutoSubnets ? "0.0.0.0" : "0.0.0-127.*", "1.2.0.0/16");
		testSubnet("1.2.0.0/17", "0.0.255.255", 17, "0.0.0.0/17" , isNoAutoSubnets ? "0.0.0.0" : "0.0.0-127.*", "1.2.0.0/17");
		testSubnet("1.2.128.0/17", "0.0.255.255", 17, "0.0.128.0/17" , isNoAutoSubnets ? "0.0.128.0" : "0.0.128-255.*", "1.2.128.0/17");
		testSubnet("1.2.0.0/17", "0.0.255.255", 15, "0.0.0.0/15" , isNoAutoSubnets ? "0.0.0.0" : "0.0.0-127.*", "1.2.0.0/15");
		testSubnet("1.3.128.0/17", "0.0.255.255", 15, allPrefixesAreSubnets ? "0.0.0.0/15" : (isNoAutoSubnets ? "0.1.128.0/15" : "0.1.128-255.*/15"), isNoAutoSubnets ? "0.0.128.0" : "0.0.128-255.*", "1.2.0.0/15");
		testSubnet("1.3.128.0/17", "255.255.255.255", 15, allPrefixesAreSubnets ? "1.2.0.0/15" : (isNoAutoSubnets ? "1.3.128.0/15" : "1.3.128-255.*/15"), isNoAutoSubnets ? "1.3.128.0" : "1.3.128-255.*", "1.2.0.0/15");
		testSubnet("1.3.0.0/16", "255.255.255.255", 8, allPrefixesAreSubnets ? "1.0.0.0/8" : (isNoAutoSubnets ? "1.3.0.0/8" : "1.3.*.*/8"), isNoAutoSubnets ? "1.3.0.0" : "1.3.*.*", "1.0.0.0/8");
		testSubnet("1.0.0.0/16", "255.255.255.255", 8, "1.0.0.0/8" , isNoAutoSubnets ? "1.0.0.0" : "1.0.*.*", "1.0.0.0/8");
		testSubnet("1.0.0.0/18", "255.255.255.255", 16, "1.0.0.0/16" , isNoAutoSubnets ? "1.0.0.0" :  "1.0.0-63.*", "1.0.0.0/16");
		
		testSubnet("1.2.0.0", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16");
		testSubnet("1.2.0.0", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/17");
		testSubnet("1.2.128.0", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.128.0/17");
		testSubnet("1.2.128.0", "255.255.128.0", 17, "1.2.128.0/17" , "1.2.128.0", "1.2.128.0/17");
		testSubnet("1.2.0.0", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
		
		testSubnet("1.2.0.0/17", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16");
		testSubnet("1.2.0.0/17", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/17");
		testSubnet("1.2.128.0/17", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.128.0/17");
		testSubnet("1.2.128.0/17", "255.255.128.0", 17, "1.2.128.0/17" , "1.2.128.0", "1.2.128.0/17");
		testSubnet("1.2.0.0/17", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
		
		testSubnet("1.2.0.0/16", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16");
		testSubnet("1.2.0.0/16", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/16");
		testSubnet("1.2.0.0/16", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/16");
		testSubnet("1.2.0.0/16", "255.255.128.0", 17, isNoAutoSubnets ? "1.2.0.0/17" : "1.2.0-128.0/17" , isNoAutoSubnets ? "1.2.0.0" : null, "1.2.0.0/16");
		testSubnet("1.2.0.0/16", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
		
		testSubnet("1.2.0.0/15", "255.255.0.0", 16, isNoAutoSubnets ? "1.2.0.0/16" : "1.2-3.0.0/16", isNoAutoSubnets ? "1.2.0.0" : "1.2-3.0.0", "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.255.0.0", 17, isNoAutoSubnets ? "1.2.0.0/17" : "1.2-3.0.0/17" , isNoAutoSubnets ? "1.2.0.0" : "1.2-3.0.0", "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.255.128.0", 17, isNoAutoSubnets ? "1.2.0.0/17" : "1.2-3.0-128.0/17", isNoAutoSubnets ? "1.2.0.0" : null, "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.255.128.0", 18, isNoAutoSubnets ? "1.2.0.0/18" : null, isNoAutoSubnets ? "1.2.0.0" : null, "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.255.192.0", 18, isNoAutoSubnets ? "1.2.0.0/18" : "1.2-3.0-192.0/18", isNoAutoSubnets ? "1.2.0.0" : null, "1.2.0.0/15");
		
		testSubnet("1.0.0.0/12", "255.254.0.0", 16, isNoAutoSubnets ? "1.0.0.0/16" : null, isNoAutoSubnets ? "1.0.0.0" : null, "1.0.0.0/12");
		testSubnet("1.0.0.0/12", "255.243.0.255", 16, isNoAutoSubnets ? "1.0.0.0/16" : "1.0-3.0.0/16", isNoAutoSubnets ? "1.0.0.0" : "1.0-3.0.*", "1.0.0.0/12");
		testSubnet("1.0.0.0/12", "255.255.0.0", 16, isNoAutoSubnets ? "1.0.0.0/16" : "1.0-15.0.0/16", isNoAutoSubnets ? "1.0.0.0" : "1.0-15.0.0", "1.0.0.0/12");
		testSubnet("1.0.0.0/12", "255.240.0.0", 16, "1.0.0.0/16", "1.0.0.0", "1.0.0.0/12");
		testSubnet("1.0.0.0/12", "255.248.0.0", 13, isNoAutoSubnets ? "1.0.0.0/13" : "1.0-8.0.0/13", isNoAutoSubnets ? "1.0.0.0" : null, "1.0.0.0/12");

		testSubnet("1.2.0.0/15", "255.254.128.0", 17, isNoAutoSubnets ? "1.2.0.0/17" : "1.2.0-128.0/17", isNoAutoSubnets ? "1.2.0.0" : null, "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.255.128.0", 17, isNoAutoSubnets ? "1.2.0.0/17" : "1.2-3.0-128.0/17", isNoAutoSubnets ? "1.2.0.0" : null, "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.252.128.0", 17, isNoAutoSubnets ? "1.0.0.0/17" : "1.0.0-128.0/17", isNoAutoSubnets ? "1.0.0.0" : null, "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.252.128.0", 18, isNoAutoSubnets ? "1.0.0.0/18" : null, isNoAutoSubnets ? "1.0.0.0" : null, "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.255.127.0", 15, "1.2.0.0/15", isNoAutoSubnets ? "1.2.0.0" : "1.2-3.0-127.0", "1.2.0.0/15");
		testSubnet("1.2.0.0/15", "255.255.0.255", 15, "1.2.0.0/15" , isNoAutoSubnets ? "1.2.0.0" : "1.2-3.0.*", "1.2.0.0/15");
		
		if(allPrefixesAreSubnets) {
			testSubnet("1.2.128.1/17", "0.0.255.255", 17, "0.0.128.0/17", "0.0.128-255.*", "1.2.128.0/17");
			
			testSubnet("1.2.3.4", "0.0.255.255", 16 /* mask is valid with prefix */, "0.0.0.0/16" /* mask is valid alone */, "0.0.3.4", "1.2.0.0/16" /* prefix alone */);
			testSubnet("1.2.3.4", "0.0.255.255", 17, "0.0.0.0/17" , "0.0.3.4", "1.2.0.0/17");
			testSubnet("1.2.128.4", "0.0.255.255", 17, "0.0.128.0/17" , "0.0.128.4", "1.2.128.0/17");
			testSubnet("1.2.3.4", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.3.4", "1.2.0.0/15");
			testSubnet("1.1.3.4", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.3.4", "1.0.0.0/15");
			testSubnet("1.2.128.4", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.128.4", "1.2.0.0/15");
			
			testSubnet("1.2.3.4/15", "0.0.255.255", 16, "0.0.0.0/16", "0.0.*.*", "1.2.0.0/15");//second to last is 0.0.0.0/15 and I don't know why. we are applying the mask only.  I can see how the range becomes /16 but why the string look ike that?
			testSubnet("1.2.3.4/15", "0.0.255.255", 17, "0.0.0-128.0/17" , "0.0.*.*", "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "0.0.255.255", 17, "0.0.0-128.0/17" , "0.0.*.*", "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.*.*", "1.2.0.0/15");
			testSubnet("1.1.3.4/15", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.*.*", "1.0.0.0/15");
			testSubnet("1.2.128.4/15", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.*.*", "1.2.0.0/15");
			testSubnet("1.1.3.4/15", "0.1.255.255", 15, "0.0.0.0/15" , "0.0-1.*.*", "1.0.0.0/15");
			testSubnet("1.0.3.4/15", "0.1.255.255", 15, "0.0.0.0/15" , "0.0-1.*.*", "1.0.0.0/15");
			
			testSubnet("1.2.3.4/17", "0.0.255.255", 16 , "0.0.0.0/16" , "0.0.0-127.*", "1.2.0.0/16");
			testSubnet("1.2.3.4/17", "0.0.255.255", 17, "0.0.0.0/17" , "0.0.0-127.*", "1.2.0.0/17");
			testSubnet("1.2.128.4/17", "0.0.255.255", 17, "0.0.128.0/17" , "0.0.128-255.*", "1.2.128.0/17");
			testSubnet("1.2.3.4/17", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.0-127.*", "1.2.0.0/15");
			testSubnet("1.1.3.4/17", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.0-127.*", "1.0.0.0/15");
			testSubnet("1.2.128.4/17", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.128-255.*", "1.2.0.0/15");
			
			testSubnet("1.2.3.4", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16");
			testSubnet("1.2.3.4", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/17");
			testSubnet("1.2.128.4", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.128.0/17");
			testSubnet("1.2.128.4", "255.255.128.0", 17, "1.2.128.0/17" , "1.2.128.0", "1.2.128.0/17");
			testSubnet("1.2.3.4", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
			testSubnet("1.1.3.4", "255.255.0.0", 15, "1.0.0.0/15" , "1.1.0.0", "1.0.0.0/15");
			testSubnet("1.2.128.4", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
			
			testSubnet("1.2.3.4/17", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16");
			testSubnet("1.2.3.4/17", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/17");
			testSubnet("1.2.128.4/17", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.128.0/17");
			testSubnet("1.2.128.4/17", "255.255.128.0", 17, "1.2.128.0/17" , "1.2.128.0", "1.2.128.0/17");
			testSubnet("1.2.3.4/17", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
			testSubnet("1.1.3.4/17", "255.255.0.0", 15, "1.0.0.0/15" , "1.1.0.0", "1.0.0.0/15");
			testSubnet("1.2.128.4/17", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
			
			testSubnet("1.2.3.4/16", "255.255.0.0", 16, "1.2.0.0/16", "1.2.0.0", "1.2.0.0/16");
			testSubnet("1.2.3.4/16", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/16");
			testSubnet("1.2.128.4/16", "255.255.0.0", 17, "1.2.0.0/17" , "1.2.0.0", "1.2.0.0/16");
			testSubnet("1.2.128.4/16", "255.255.128.0", 17, "1.2.0-128.0/17" , null, "1.2.0.0/16");
			testSubnet("1.2.3.4/16", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
			testSubnet("1.1.3.4/16", "255.255.0.0", 15, "1.0.0.0/15" , "1.1.0.0", "1.0.0.0/15");
			testSubnet("1.2.128.4/16", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
			
			testSubnet("1.2.3.4/15", "255.255.0.0", 16, "1.2-3.0.0/16", "1.2-3.0.0", "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.255.0.0", 17, "1.2-3.0.0/17" , "1.2-3.0.0", "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "255.255.0.0", 17, "1.2-3.0.0/17" , "1.2-3.0.0", "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "255.255.128.0", 17, "1.2-3.0-128.0/17", null, "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "255.255.128.0", 18, null, null, "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "255.255.192.0", 18, "1.2-3.0-192.0/18", null, "1.2.0.0/15");
			
			testSubnet("1.2.3.4/12", "255.254.0.0", 16, null, null, "1.0.0.0/12");
			testSubnet("1.2.3.4/12", "255.243.0.255", 16, "1.0-3.0.0/16", "1.0-3.0.*", "1.0.0.0/12");
			testSubnet("1.2.3.4/12", "255.255.0.0", 16, "1.0-15.0.0/16", "1.0-15.0.0", "1.0.0.0/12");
			testSubnet("1.2.3.4/12", "255.240.0.0", 16, "1.0.0.0/16", "1.0.0.0", "1.0.0.0/12");
			testSubnet("1.2.3.4/12", "255.248.0.0", 13, "1.0-8.0.0/13", null, "1.0.0.0/12");
			
			testSubnet("1.2.128.4/15", "255.254.128.0", 17, "1.2.0-128.0/17", null, "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "255.255.128.0", 17, "1.2-3.0-128.0/17", null, "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "255.252.128.0", 17, "1.0.0-128.0/17", null, "1.2.0.0/15");
			testSubnet("1.2.128.4/15", "255.252.128.0", 18, null, null, "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.255.127.0", 15, "1.2.0.0/15", "1.2-3.0-127.0", "1.2.0.0/15");
			testSubnet("1.1.3.4/15", "255.255.0.0", 15, "1.0.0.0/15" , "1.0-1.0.0", "1.0.0.0/15");
			testSubnet("1.2.128.4/15", "255.255.0.255", 15, "1.2.0.0/15" , "1.2-3.0.*", "1.2.0.0/15");
			
			testSubnet("1.2.3.4", "255.254.255.255", 15, "1.2.0.0/15", "1.2.3.4", "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.254.255.255", 15, "1.2.0.0/15", "1.2.*.*", "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.255.254.255", 15, "1.2.0.0/15", null, "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.254.0.255", 15, "1.2.0.0/15", "1.2.0.*", "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.255.254.255", 16, "1.2-3.0.0/16", null, "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.255.254.255", 23, "1.2-3.0-254.0/23", null, "1.2.0.0/15"); 
			testSubnet("1.2.3.4/23", "255.255.254.255", 23, "1.2.2.0/23", "1.2.2.*", "1.2.2.0/23");
			testSubnet("1.2.3.4/23", "255.255.254.255", 15, "1.2.0.0/15", "1.2.2.*", "1.2.0.0/15");
			testSubnet("1.2.3.4/15", "255.255.254.255", 24, null, null, "1.2.0.0/15");
			testSubnet("1.2.3.4/17", "255.255.255.255", 15, "1.2.0.0/15", "1.2.0-127.*", "1.2.0.0/15");
			testSubnet("1.2.3.4/17", "255.255.254.255", 24, null, null, "1.2.0.0/17");
			testSubnet("1.2.3.4/17", "255.255.254.255", 23, "1.2.0-126.0/23", null, "1.2.0.0/17");
			testSubnet("1.2.3.4/17", "255.255.254.255", 22, "1.2.0-124.0/22", null, "1.2.0.0/17");
		} else {
			testSubnet("1.2.128.1/17", "0.0.255.255", 17, "0.0.128.1/17" , "0.0.128.1", "1.2.128.1/17");
	
			testSubnet("1.2.3.4", "0.0.255.255", 16 /* mask is valid with prefix */, "0.0.3.4/16" /* mask is valid alone */, "0.0.3.4", "1.2.3.4/16" /* prefix alone */);
			testSubnet("1.2.3.4", "0.0.255.255", 17, "0.0.3.4/17" , "0.0.3.4", "1.2.3.4/17");
			testSubnet("1.2.128.4", "0.0.255.255", 17, "0.0.128.4/17" , "0.0.128.4", "1.2.128.4/17");
			testSubnet("1.2.3.4", "0.0.255.255", 15, "0.0.3.4/15" , "0.0.3.4", "1.2.3.4/15");
			testSubnet("1.1.3.4", "0.0.255.255", 15, "0.1.3.4/15" , "0.0.3.4", "1.1.3.4/15");
			testSubnet("1.2.128.4", "0.0.255.255", 15, "0.0.128.4/15" , "0.0.128.4", "1.2.128.4/15");
			
			testSubnet("1.2.3.4/15", "0.0.255.255", 16, "0.0.3.4/16", "0.0.3.4", "1.2.3.4/15");//second to last is 0.0.0.0/15 and I don't know why. we are applying the mask only.  I can see how the range becomes /16 but why the string look ike that?
			testSubnet("1.2.3.4/15", "0.0.255.255", 17, "0.0.3.4/17" , "0.0.3.4", "1.2.3.4/15");
			testSubnet("1.2.128.4/15", "0.0.255.255", 17, "0.0.128.4/17" , "0.0.128.4", "1.2.128.4/15");
			testSubnet("1.2.3.4/15", "0.0.255.255", 15, "0.0.3.4/15" , "0.0.3.4", "1.2.3.4/15");
			testSubnet("1.1.3.4/15", "0.0.255.255", 15, "0.1.3.4/15" , "0.0.3.4", "1.1.3.4/15");
			testSubnet("1.2.128.4/15", "0.0.255.255", 15, "0.0.128.4/15" , "0.0.128.4", "1.2.128.4/15");
			testSubnet("1.1.3.4/15", "0.1.255.255", 15, "0.1.3.4/15" , "0.1.3.4", "1.1.3.4/15");
			testSubnet("1.0.3.4/15", "0.1.255.255", 15, "0.0.3.4/15" , "0.0.3.4", "1.0.3.4/15");
			
			testSubnet("1.2.3.4/17", "0.0.255.255", 16 , "0.0.3.4/16" , "0.0.3.4", "1.2.3.4/16");
			testSubnet("1.2.3.4/17", "0.0.255.255", 17, "0.0.3.4/17" , "0.0.3.4", "1.2.3.4/17");
			testSubnet("1.2.128.4/17", "0.0.255.255", 17, "0.0.128.4/17" , "0.0.128.4", "1.2.128.4/17");
			testSubnet("1.2.3.4/17", "0.0.255.255", 15, "0.0.3.4/15" , "0.0.3.4", "1.2.3.4/15");
			testSubnet("1.1.3.4/17", "0.0.255.255", 15, "0.1.3.4/15" , "0.0.3.4", "1.0.3.4/15");
			testSubnet("1.2.128.4/17", "0.0.255.255", 15, "0.0.128.4/15" , "0.0.128.4", "1.2.0.4/15");
			
			testSubnet("1.2.3.4", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/16");
			testSubnet("1.2.3.4", "255.255.0.0", 17, "1.2.3.4/17" , "1.2.0.0", "1.2.3.4/17");
			testSubnet("1.2.128.4", "255.255.0.0", 17, "1.2.0.4/17" , "1.2.0.0", "1.2.128.4/17");
			testSubnet("1.2.128.4", "255.255.128.0", 17, "1.2.128.4/17" , "1.2.128.0", "1.2.128.4/17");
			testSubnet("1.2.3.4", "255.255.0.0", 15, "1.2.3.4/15" , "1.2.0.0", "1.2.3.4/15");
			testSubnet("1.1.3.4", "255.255.0.0", 15, "1.1.3.4/15" , "1.1.0.0", "1.1.3.4/15");
			testSubnet("1.2.128.4", "255.255.0.0", 15, "1.2.128.4/15" , "1.2.0.0", "1.2.128.4/15");

			testSubnet("1.2.3.4/17", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/16");
			testSubnet("1.2.3.4/17", "255.255.0.0", 17, "1.2.3.4/17" , "1.2.0.0", "1.2.3.4/17");
			testSubnet("1.2.128.4/17", "255.255.0.0", 17, "1.2.0.4/17" , "1.2.0.0", "1.2.128.4/17");
			testSubnet("1.2.128.4/17", "255.255.128.0", 17, "1.2.128.4/17" , "1.2.128.0", "1.2.128.4/17");
			testSubnet("1.2.3.4/17", "255.255.0.0", 15, "1.2.3.4/15" , "1.2.0.0", "1.2.3.4/15");
			testSubnet("1.1.3.4/17", "255.255.0.0", 15, "1.1.3.4/15" , "1.1.0.0", "1.0.3.4/15");
			testSubnet("1.2.128.4/17", "255.255.0.0", 15, "1.2.128.4/15" , "1.2.0.0", "1.2.0.4/15");
			
			testSubnet("1.2.3.4/16", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/16");
			testSubnet("1.2.3.4/16", "255.255.0.0", 17, "1.2.3.4/17" , "1.2.0.0", "1.2.3.4/16");
			testSubnet("1.2.128.4/16", "255.255.0.0", 17, "1.2.0.4/17" , "1.2.0.0", "1.2.128.4/16");
			testSubnet("1.2.128.4/16", "255.255.128.0", 17, "1.2.128.4/17" , "1.2.128.0", "1.2.128.4/16");
			testSubnet("1.2.3.4/16", "255.255.0.0", 15, "1.2.3.4/15" , "1.2.0.0", "1.2.3.4/15");
			testSubnet("1.1.3.4/16", "255.255.0.0", 15, "1.1.3.4/15" , "1.1.0.0", "1.0.3.4/15");
			testSubnet("1.2.128.4/16", "255.255.0.0", 15, "1.2.128.4/15" , "1.2.0.0", "1.2.128.4/15");
			
			
			testSubnet("1.2.3.4/15", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/15");
			testSubnet("1.2.3.4/15", "255.255.0.0", 17, "1.2.3.4/17" , "1.2.0.0", "1.2.3.4/15");
			testSubnet("1.2.128.4/15", "255.255.0.0", 17, "1.2.0.4/17" , "1.2.0.0", "1.2.128.4/15");
			testSubnet("1.2.128.4/15", "255.255.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/15");
			testSubnet("1.2.128.4/15", "255.255.128.0", 18, "1.2.128.4/18", "1.2.128.0", "1.2.128.4/15");
			testSubnet("1.2.128.4/15", "255.255.192.0", 18, "1.2.128.4/18", "1.2.128.0", "1.2.128.4/15");
			
			testSubnet("1.2.3.4/12", "255.254.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/12");
			testSubnet("1.2.3.4/12", "255.243.0.255", 16, "1.2.3.4/16", "1.2.0.4", "1.2.3.4/12");
			testSubnet("1.2.3.4/12", "255.255.0.0", 16, "1.2.3.4/16", "1.2.0.0", "1.2.3.4/12");
			testSubnet("1.2.3.4/12", "255.240.0.0", 16, "1.0.3.4/16", "1.0.0.0", "1.2.3.4/12");
			testSubnet("1.2.3.4/12", "255.248.0.0", 13,"1.2.3.4/13", "1.0.0.0", "1.2.3.4/12");
			
			testSubnet("1.2.128.4/15", "255.254.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/15");
			testSubnet("1.2.128.4/15", "255.255.128.0", 17, "1.2.128.4/17", "1.2.128.0", "1.2.128.4/15");
			testSubnet("1.2.128.4/15", "255.252.128.0", 17, "1.0.128.4/17", "1.0.128.0", "1.2.128.4/15");
			testSubnet("1.2.128.4/15", "255.252.128.0", 18, "1.0.128.4/18", "1.0.128.0", "1.2.128.4/15");
			testSubnet("1.2.3.4/15", "255.255.127.0", 15, "1.2.3.4/15", "1.2.3.0", "1.2.3.4/15");
			testSubnet("1.1.3.4/15", "255.255.0.0", 15, "1.1.3.4/15" , "1.1.0.0", "1.1.3.4/15");
			testSubnet("1.2.128.4/15", "255.255.0.255", 15, "1.2.128.4/15" , "1.2.0.4", "1.2.128.4/15");
		}
		
		testSubnet("::/8", "ffff::", 128, isNoAutoSubnets ? "0:0:0:0:0:0:0:0/128" : "0-ff:0:0:0:0:0:0:0/128", isNoAutoSubnets ? "0:0:0:0:0:0:0:0" : "0-ff:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:0/8");
		testSubnet("::/8", "fff0::", 128, isNoAutoSubnets ? "0:0:0:0:0:0:0:0/128" : null, isNoAutoSubnets ? "0:0:0:0:0:0:0:0" : null, "0:0:0:0:0:0:0:0/8");
		testSubnet("::/8", "fff0::", 12, isNoAutoSubnets ? "0:0:0:0:0:0:0:0/12" : "0-f0:0:0:0:0:0:0:0/12", isNoAutoSubnets ? "0:0:0:0:0:0:0:0" : null, "0:0:0:0:0:0:0:0/8");
		
		testSubnet("1.2.0.0/16", "255.255.0.1", 24, "1.2.0.0/24", isNoAutoSubnets ? "1.2.0.0" : "1.2.0.0-1", "1.2.0.0/16");
		testSubnet("1.2.0.0/16", "255.255.0.3", 24, "1.2.0.0/24", isNoAutoSubnets ? "1.2.0.0" : "1.2.0.0-3", "1.2.0.0/16");
		testSubnet("1.2.0.0/16", "255.255.3.3", 24, isNoAutoSubnets ? "1.2.0.0/24" : "1.2.0-3.0/24", isNoAutoSubnets ? "1.2.0.0" : "1.2.0-3.0-3", "1.2.0.0/16");
		

		testSplit("9.129.237.26", 0, "", "", "", 1, "9.129.237.26", 2); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
		testSplit("9.129.237.26", 8, "9", "9", "9/8", 2, "129.237.26", 2);
		testSplit("9.129.237.26", 16, "9.129", "9.129", "9.129/16", 2, "237.26", 2);
		
		testSplit("9.129.237.26", 31, "9.129.237.26-27", "9.129.237.26", isNoAutoSubnets ? "9.129.237.26-27/31" :  "9.129.237.26/31", 2, "0", 2);
		testSplit("9.129.237.26", 32, "9.129.237.26", "9.129.237.26", "9.129.237.26/32", 2, "", 1);
		
		testSplit("1.2.3.4", 4, "0-15", "0", isNoAutoSubnets ? "0-15/4" : "0/4", 2, "1.2.3.4", 2);
		testSplit("255.2.3.4", 4, "240-255", "240", isNoAutoSubnets ? "240-255/4" : "240/4", 1, "15.2.3.4", 2);
		
		
		testSplit("9:129::237:26", 0, "", "", "", 1, "9:129:0:0:0:0:237:26", 12); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
		testSplit("9:129::237:26", 16, "9", "9", "9/16", 2, "129:0:0:0:0:237:26", 12);
		testSplit("9:129::237:26", 31, "9:128-129", "9:128", isNoAutoSubnets ? "9:128-129/31" : "9:128/31", 2, "1:0:0:0:0:237:26", 12);
		
		testSplit("9:129::237:26", 32, "9:129", "9:129", "9:129/32", 2, "0:0:0:0:237:26", 10);
		testSplit("9:129::237:26", 33, "9:129:0-7fff", "9:129:0", isNoAutoSubnets ? "9:129:0-7fff/33" : "9:129:0/33", 2, "0:0:0:0:237:26", 10);
		testSplit("9:129::237:26", 63, "9:129:0:0-1", "9:129:0:0", isNoAutoSubnets ? "9:129:0:0-1/63" : "9:129:0:0/63", 4, "0:0:0:237:26", 10);
		testSplit("9:129::237:26", 64, "9:129:0:0", "9:129:0:0", "9:129:0:0/64", 4, "0:0:237:26", 10);
		testSplit("9:129::237:26", 96, "9:129:0:0:0:0", "9:129:0:0:0:0", "9:129:0:0:0:0/96", 4, "237:26", 4);
		testSplit("9:129::237:26", 111, "9:129:0:0:0:0:236-237", "9:129:0:0:0:0:236", isNoAutoSubnets ? "9:129:0:0:0:0:236-237/111" : "9:129:0:0:0:0:236/111", 12, "1:26", 4);
		testSplit("9:129::237:26", 112, "9:129:0:0:0:0:237", "9:129:0:0:0:0:237", "9:129:0:0:0:0:237/112", 12, "26", 4);
		testSplit("9:129::237:26", 113, "9:129:0:0:0:0:237:0-7fff", "9:129:0:0:0:0:237:0", isNoAutoSubnets ? "9:129:0:0:0:0:237:0-7fff/113" : "9:129:0:0:0:0:237:0/113", 12, "26", 4);
		testSplit("9:129::237:ffff", 113, "9:129:0:0:0:0:237:8000-ffff", "9:129:0:0:0:0:237:8000", isNoAutoSubnets ? "9:129:0:0:0:0:237:8000-ffff/113" : "9:129:0:0:0:0:237:8000/113", 12, "7fff", 3);
		testSplit("9:129::237:26", 127, "9:129:0:0:0:0:237:26-27", "9:129:0:0:0:0:237:26", isNoAutoSubnets ? "9:129:0:0:0:0:237:26-27/127" : "9:129:0:0:0:0:237:26/127", 12, "0", 5); //previously when splitting host we would have just one ipv4 segment, but now we have two ipv4 segments
		testSplit("9:129::237:26", 128, "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26/128", 12, "", 1);
		
		int USE_UPPERCASE = 2;
		
		testSplit("a:b:c:d:e:f:a:b", 4, "0-fff", "0", isNoAutoSubnets ? "0-fff/4" : "0/4", 2, "a:b:c:d:e:f:a:b", 6 * USE_UPPERCASE);
		testSplit("ffff:b:c:d:e:f:a:b", 4, "f000-ffff", "f000", isNoAutoSubnets ? "f000-ffff/4" : "f000/4", 1 * USE_UPPERCASE, "fff:b:c:d:e:f:a:b", 6 * USE_UPPERCASE);
		testSplit("ffff:b:c:d:e:f:a:b", 2, "c000-ffff", "c000", isNoAutoSubnets ? "c000-ffff/2" : "c000/2", 1 * USE_UPPERCASE, "3fff:b:c:d:e:f:a:b", 6 * USE_UPPERCASE);
		
		testURL("http://1.2.3.4");
		testURL("http://[a:a:a:a:b:b:b:b]");
		testURL("http://a:a:a:a:b:b:b:b");
		
		testSections("9.129.237.26", 0, 1);
		testSections("9.129.237.26", 8, 1 /* 2 */);
		testSections("9.129.237.26", 16, 1 /* 2 */);
		testSections("9.129.237.26", 24, 1 /* 2 */);
		testSections("9.129.237.26", 32, 1 /* 2 */);
		testSections("9:129::237:26", 0, 1);
		testSections("9:129::237:26", 16, 1 /* 2 */);
		testSections("9:129::237:26", 64, 2 /* 4 */);
		testSections("9:129::237:26", 80, 2 /* 4 */);
		testSections("9:129::237:26", 96, 2 /* 4 */);
		testSections("9:129::237:26", 112, 2 /* 12 */);
		testSections("9:129::237:26", 128, 2 /* 12 */);
		
		testSections("9.129.237.26", 7, 2 /* 4 */);
		testSections("9.129.237.26", 9, 128 /* 256 */); //129 is 10000001
		testSections("9.129.237.26", 10, 64 /* 128 */);
		testSections("9.129.237.26", 11, 32 /* 64 */);
		testSections("9.129.237.26", 12, 16 /* 32 */);
		testSections("9.129.237.26", 13, 8 /* 16 */);
		testSections("9.129.237.26", 14, 4 /* 8 */); //10000000 to 10000011 (128 to 131)
		testSections("9.129.237.26", 15, 2 /* 4 */); //10000000 to 10000001 (128 to 129)
				
		//test that the given address has the given number of standard variants and total variants
		testVariantCounts("::", 2, 2, 9, 1297);
		testVariantCounts("::1", 2, 2, 10, 1298);
		//testVariantCounts("::1", 2, 2, IPv6Address.network().getStandardLoopbackStrings().length, 1298);//this confirms that IPv6Address.getStandardLoopbackStrings() is being initialized properly
		testVariantCounts("::ffff:1.2.3.4", 6, 4, 20, 1410, 1320);//ipv4 mapped
		testVariantCounts("::fffe:1.2.3.4", 2, 4, 20, 1320, 1320);//almost identical but not ipv4 mapped
		testVariantCounts("::ffff:0:0", 6, 4, 24, 1474, 1384);//ipv4 mapped
		testVariantCounts("::fffe:0:0", 2, 4, 24, 1384, 1384);//almost identical but not ipv4 mapped
		testVariantCounts("2:2:2:2:2:2:2:2", 2, 1, 6, 1280);
		testVariantCounts("2:0:0:2:0:2:2:2", 2, 2, 18, 2240);
		testVariantCounts("a:b:c:0:d:e:f:1", 2, 4, 12 * USE_UPPERCASE, 1920 * USE_UPPERCASE);
		testVariantCounts("a:b:c:0:0:d:e:f", 2, 4, 12 * USE_UPPERCASE, 1600 * USE_UPPERCASE);
		testVariantCounts("a:b:c:d:e:f:0:1", 2, 4, 8 * USE_UPPERCASE, 1408 * USE_UPPERCASE);
		testVariantCounts("a:b:c:d:e:f:0:0", 2, 4, 8 * USE_UPPERCASE, 1344 * USE_UPPERCASE);
		testVariantCounts("a:b:c:d:e:f:a:b", 2, 2, 6 * USE_UPPERCASE, 1280 * USE_UPPERCASE);
		testVariantCounts("aaaa:bbbb:cccc:dddd:eeee:ffff:aaaa:bbbb", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
		testVariantCounts("a111:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
		testVariantCounts("1a11:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
		testVariantCounts("11a1:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
		testVariantCounts("111a:1111:1111:1111:1111:1111:9999:9999", 2, 2, 2 * USE_UPPERCASE, 2 * USE_UPPERCASE);
		testVariantCounts("aaaa:b:cccc:dddd:eeee:ffff:aaaa:bbbb", 2, 2, 4 * USE_UPPERCASE, 4 * USE_UPPERCASE);
		testVariantCounts("aaaa:b:cc:dddd:eeee:ffff:aaaa:bbbb", 2, 2, 4 * USE_UPPERCASE, 8 * USE_UPPERCASE);
		testVariantCounts("1.2.3.4", 6, 1, 2, 420, 90, 16);
		testVariantCounts("0.0.0.0", 6, 1, 2, 484, 90, 16);
		testVariantCounts("1111:2222:aaaa:4444:5555:6666:7070:700a", 2,  1 * USE_UPPERCASE, 1 * USE_UPPERCASE + 2 * USE_UPPERCASE, 1 * USE_UPPERCASE + 2 * USE_UPPERCASE);//this one can be capitalized when mixed 
		testVariantCounts("1111:2222:3333:4444:5555:6666:7070:700a", 2, 2, 1 * USE_UPPERCASE + 2, 1 * USE_UPPERCASE + 2);//this one can only be capitalized when not mixed, so the 2 mixed cases are not doubled

		testReverseHostAddress("1.2.0.0/20");
		testReverseHostAddress("1.2.3.4");
		testReverseHostAddress("1:f000::/20");
		
		testFromBytes(new byte[] {-1, -1, -1, -1}, "255.255.255.255");
		testFromBytes(new byte[] {1, 2, 3, 4}, "1.2.3.4");
		testFromBytes(new byte[16], "::");
		testFromBytes(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "::1");
		testFromBytes(new byte[] {0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 1, 0, 2}, "a:b:c:d:e:f:1:2");
		
		if(fullTest && HostTest.runDNS) {
			testResolved("espn.com", "199.181.132.250");
			testResolved("instapundit.com", "72.32.173.45");
		}
		
		testResolved("9.32.237.26", "9.32.237.26");
		testResolved("9.70.146.84", "9.70.146.84");
		
		testNormalized("1.2.3.4", "1.2.3.4");
		testNormalized("1.2.00.4", "1.2.0.4");
		testNormalized("000.2.00.4", "0.2.0.4");
		testNormalized("00.2.00.000", "0.2.0.0");
		testNormalized("000.000.000.000", "0.0.0.0");
		
		testNormalized("A:B:C:D:E:F:A:B", "a:b:c:d:e:f:a:b");
		testNormalized("ABCD:ABCD:CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "abcd:abcd:cccc:dddd:eeee:ffff:aaaa:bbbb");
		testNormalized("AB12:12CD:CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "ab12:12cd:cccc:dddd:eeee:ffff:aaaa:bbbb");
		testNormalized("ABCD::CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "abcd::cccc:dddd:eeee:ffff:aaaa:bbbb");
		testNormalized("::ABCD:CCCC:Dddd:EeEe:fFfF:aAAA:Bbbb", "::abcd:cccc:dddd:eeee:ffff:aaaa:bbbb");
		testNormalized("ABCD:ABCD:CCCC:Dddd:EeEe:fFfF:aAAA::", "abcd:abcd:cccc:dddd:eeee:ffff:aaaa::");
		testNormalized("::ABCD:Dddd:EeEe:fFfF:aAAA:Bbbb", "::abcd:dddd:eeee:ffff:aaaa:bbbb");
		testNormalized("ABCD:ABCD:CCCC:Dddd:fFfF:aAAA::", "abcd:abcd:cccc:dddd:ffff:aaaa::");
		testNormalized("::ABCD", "::abcd");
		testNormalized("aAAA::", "aaaa::");
		
		testNormalized("0:0:0:0:0:0:0:0", "::");
		testNormalized("0000:0000:0000:0000:0000:0000:0000:0000", "::");
		testNormalized("0000:0000:0000:0000:0000:0000:0000:0000", "0:0:0:0:0:0:0:0", true, false);
		testNormalized("0:0:0:0:0:0:0:1", "::1");
		testNormalized("0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1", true, false);
		testNormalized("0:0:0:0::0:0:1", "0:0:0:0:0:0:0:1", true, false);
		testNormalized("0000:0000:0000:0000:0000:0000:0000:0001", "::1");
		testNormalized("1:0:0:0:0:0:0:0", "1::");
		testNormalized("0001:0000:0000:0000:0000:0000:0000:0000", "1::");
		testNormalized("1:0:0:0:0:0:0:1", "1::1");
		testNormalized("0001:0000:0000:0000:0000:0000:0000:0001", "1::1");
		testNormalized("1:0:0:0::0:0:1", "1::1");
		testNormalized("0001::0000:0000:0000:0000:0000:0001", "1::1");
		testNormalized("0001:0000:0000:0000:0000:0000::0001", "1::1");
		testNormalized("::0000:0000:0000:0000:0000:0001", "::1");
		testNormalized("0001:0000:0000:0000:0000:0000::", "1::");
		testNormalized("1:0::1", "1::1");
		testNormalized("0001:0000::0001", "1::1");
		testNormalized("0::", "::");
		testNormalized("0000::", "::");
		testNormalized("::0", "::");
		testNormalized("::0000", "::");
		testNormalized("0:0:0:0:1:0:0:0", "::1:0:0:0");
		testNormalized("0000:0000:0000:0000:0001:0000:0000:0000", "::1:0:0:0");
		testNormalized("0:0:0:1:0:0:0:0", "0:0:0:1::");
		testNormalized("0000:0000:0000:0001:0000:0000:0000:0000", "0:0:0:1::");
		testNormalized("0:1:0:1:0:1:0:1", "::1:0:1:0:1:0:1");
		testNormalized("0000:0001:0000:0001:0000:0001:0000:0001", "::1:0:1:0:1:0:1");
		testNormalized("1:1:0:1:0:1:0:1", "1:1::1:0:1:0:1");
		testNormalized("0001:0001:0000:0001:0000:0001:0000:0001", "1:1::1:0:1:0:1");
		
		testCanonical("0001:0000:0000:000F:0000:0000:0001:0001", "1::f:0:0:1:1");//must be leftmost
		testCanonical("0001:0001:0000:000F:0000:0001:0000:0001", "1:1:0:f:0:1:0:1");//but singles not compressed
		testMixed("0001:0001:0000:000F:0000:0001:0000:0001", "1:1::f:0:1:0.0.0.1");//singles compressed in mixed
		testCompressed("a.b.c.d", "a.b.c.d");
		
		testCompressed("1:0:1:1:1:1:1:1", "1::1:1:1:1:1:1");
		testCanonical("1:0:1:1:1:1:1:1", "1:0:1:1:1:1:1:1");
		testMixed("1:0:1:1:1:1:1:1", "1::1:1:1:1:0.1.0.1");
		
		testMixed("::", "::", "::0.0.0.0");
		testMixed("::1", "::0.0.0.1");
		
		testRadices("255.127.254.2", "11111111.1111111.11111110.10", 2);
		testRadices("2.254.127.255", "10.11111110.1111111.11111111", 2);
		testRadices("1.12.4.8", "1.1100.100.1000", 2);
		testRadices("8.4.12.1", "1000.100.1100.1", 2);
		testRadices("10.5.10.5", "1010.101.1010.101", 2);
		testRadices("5.10.5.10", "101.1010.101.1010", 2);
		testRadices("0.1.0.1", "0.1.0.1", 2);
		testRadices("1.0.1.0", "1.0.1.0", 2);
		
		testRadices("255.127.254.2", "513.241.512.2", 7);
		testRadices("2.254.127.255", "2.512.241.513", 7);
		testRadices("0.1.0.1", "0.1.0.1", 7);
		testRadices("1.0.1.0", "1.0.1.0", 7);
		
		testRadices("255.127.254.2", "120.87.11e.2", 15);
		testRadices("2.254.127.255", "2.11e.87.120", 15);
		testRadices("0.1.0.1", "0.1.0.1", 15);
		testRadices("1.0.1.0", "1.0.1.0", 15);
		
		testNormalized("A:B:C:D:E:F:000.000.000.000", "a:b:c:d:e:f::", true, true);
		testNormalized("A:B:C:D:E::000.000.000.000", "a:b:c:d:e::", true, true);
		testNormalized("::B:C:D:E:F:000.000.000.000", "0:b:c:d:e:f::", true, true);
		testNormalized("A:B:C:D::000.000.000.000", "a:b:c:d::", true, true);
		testNormalized("::C:D:E:F:000.000.000.000", "::c:d:e:f:0.0.0.0", true, true);
		testNormalized("::C:D:E:F:000.000.000.000", "0:0:c:d:e:f:0.0.0.0", true, false);
		testNormalized("A:B:C::E:F:000.000.000.000", "a:b:c:0:e:f::", true, true);
		testNormalized("A:B::E:F:000.000.000.000", "a:b::e:f:0.0.0.0", true, true);
		
		testNormalized("A:B:C:D:E:F:000.000.000.001", "a:b:c:d:e:f:0.0.0.1", true, true);
		testNormalized("A:B:C:D:E::000.000.000.001", "a:b:c:d:e::0.0.0.1", true, true);
		testNormalized("::B:C:D:E:F:000.000.000.001", "::b:c:d:e:f:0.0.0.1", true, true);
		testNormalized("A:B:C:D::000.000.000.001", "a:b:c:d::0.0.0.1", true, true);
		testNormalized("::C:D:E:F:000.000.000.001", "::c:d:e:f:0.0.0.1", true, true);
		testNormalized("::C:D:E:F:000.000.000.001", "0:0:c:d:e:f:0.0.0.1", true, false);
		testNormalized("A:B:C::E:F:000.000.000.001", "a:b:c::e:f:0.0.0.1", true, true);
		testNormalized("A:B::E:F:000.000.000.001", "a:b::e:f:0.0.0.1", true, true);
		
		testNormalized("A:B:C:D:E:F:001.000.000.000", "a:b:c:d:e:f:1.0.0.0", true, true);
		testNormalized("A:B:C:D:E::001.000.000.000", "a:b:c:d:e::1.0.0.0", true, true);
		testNormalized("::B:C:D:E:F:001.000.000.000", "::b:c:d:e:f:1.0.0.0", true, true);
		testNormalized("A:B:C:D::001.000.000.000", "a:b:c:d::1.0.0.0", true, true);
		testNormalized("::C:D:E:F:001.000.000.000", "::c:d:e:f:1.0.0.0", true, true);
		testNormalized("::C:D:E:F:001.000.000.000", "0:0:c:d:e:f:1.0.0.0", true, false);
		testNormalized("A:B:C::E:F:001.000.000.000", "a:b:c::e:f:1.0.0.0", true, true);
		testNormalized("A:B::E:F:001.000.000.000", "a:b::e:f:1.0.0.0", true, true);
		
		testMask("1.2.3.4", "0.0.2.0", "0.0.2.0");
		testMask("1.2.3.4", "0.0.1.0", "0.0.1.0");
		testMask("A:B:C:D:E:F:A:B", "A:0:C:0:E:0:A:0", "A:0:C:0:E:0:A:0");
		testMask("A:B:C:D:E:F:A:B", "FFFF:FFFF:FFFF:FFFF::", "A:B:C:D::");
		testMask("A:B:C:D:E:F:A:B", "::FFFF:FFFF:FFFF:FFFF", "::E:F:A:B");

		if(fullTest) {
			int len = 5000;
			StringBuilder builder = new StringBuilder(len + 6);
			for(int i = 0; i < len; i++) {
				builder.append('1');
			}
			builder.append(".2.3.4");
			ipv4test(false, builder.toString());
		}
		
		ipv4test(isLenient(), ""); //this needs special validation options to be valid
		
		ipv4test(true, "1.2.3.4");
		ipv4test(false, "[1.2.3.4]");//HostName accepts square brackets, not addresses
		
		ipv4test(false, "a");
		
		ipv4test(isLenient(), "1.2.3");
		
		ipv4test(false, "a.2.3.4");
		ipv4test(false, "1.a.3.4");
		ipv4test(false, "1.2.a.4");
		ipv4test(false, "1.2.3.a");
		
		ipv4test(false, ".2.3.4");
		ipv4test(false, "1..3.4");
		ipv4test(false, "1.2..4");
		ipv4test(false, "1.2.3.");
		
		ipv4test(false, "256.2.3.4");
		ipv4test(false, "1.256.3.4");
		ipv4test(false, "1.2.256.4");
		ipv4test(false, "1.2.3.256");
		
		ipv4test(false, "f.f.f.f");
		
		
		ipv4test(true, "0.0.0.0", true);
		ipv4test(true, "00.0.0.0", true);
		ipv4test(true, "0.00.0.0", true);
		ipv4test(true, "0.0.00.0", true);
		ipv4test(true, "0.0.0.00", true);
		ipv4test(true, "000.0.0.0", true);
		ipv4test(true, "0.000.0.0", true);
		ipv4test(true, "0.0.000.0", true);
		ipv4test(true, "0.0.0.000", true);

		ipv4test(true, "000.000.000.000", true);
		
		ipv4test(isLenient(), "0000.0.0.0", true);
		ipv4test(isLenient(), "0.0000.0.0", true);
		ipv4test(isLenient(), "0.0.0000.0", true);
		ipv4test(isLenient(), "0.0.0.0000", true);
		
		
		ipv4test(true, "3.3.3.3", false);
		ipv4test(true, "33.3.3.3", false);
		ipv4test(true, "3.33.3.3", false);
		ipv4test(true, "3.3.33.3", false);
		ipv4test(true, "3.3.3.33", false);
		ipv4test(true, "233.3.3.3", false);
		ipv4test(true, "3.233.3.3", false);
		ipv4test(true, "3.3.233.3", false);
		ipv4test(true, "3.3.3.233", false);
		
		ipv4test(true, "200.200.200.200", false);
		
		ipv4test(isLenient(), "0333.0.0.0", false);
		ipv4test(isLenient(), "0.0333.0.0", false);
		ipv4test(isLenient(), "0.0.0333.0", false);
		ipv4test(isLenient(), "0.0.0.0333", false);
		
		
		
		ipv6test(true, "0:0:0:0:0:0:0:0", true);
		ipv6test(true, "00:0:0:0:0:0:0:0", true);
		ipv6test(true, "0:00:0:0:0:0:0:0", true);
		ipv6test(true, "0:0:00:0:0:0:0:0", true);
		ipv6test(true, "0:0:0:00:0:0:0:0", true);
		ipv6test(true, "0:0:0:0:00:0:0:0", true);
		ipv6test(true, "0:0:0:0:0:00:0:0", true);
		ipv6test(true, "0:0:0:0:0:0:00:0", true);
		ipv6test(true, "0:0:0:0:0:0:0:00", true);
		ipv6test(true, "0:0:0:0:0:0:0:0", true);
		ipv6test(true, "000:0:0:0:0:0:0:0", true);
		ipv6test(true, "0:000:0:0:0:0:0:0", true);
		ipv6test(true, "0:0:000:0:0:0:0:0", true);
		ipv6test(true, "0:0:0:000:0:0:0:0", true);
		ipv6test(true, "0:0:0:0:000:0:0:0", true);
		ipv6test(true, "0:0:0:0:0:000:0:0", true);
		ipv6test(true, "0:0:0:0:0:0:000:0", true);
		ipv6test(true, "0:0:0:0:0:0:0:000", true);
		ipv6test(true, "0000:0:0:0:0:0:0:0", true);
		ipv6test(true, "0:0000:0:0:0:0:0:0", true);
		ipv6test(true, "0:0:0000:0:0:0:0:0", true);
		ipv6test(true, "0:0:0:0000:0:0:0:0", true);
		ipv6test(true, "0:0:0:0:0000:0:0:0", true);
		ipv6test(true, "0:0:0:0:0:0000:0:0", true);
		ipv6test(true, "0:0:0:0:0:0:0000:0", true);
		ipv6test(true, "0:0:0:0:0:0:0:0000", true);
		ipv6test(isLenient(), "00000:0:0:0:0:0:0:0", true);
		ipv6test(isLenient(), "0:00000:0:0:0:0:0:0", true);
		ipv6test(isLenient(), "0:0:00000:0:0:0:0:0", true);
		ipv6test(isLenient(), "0:0:0:00000:0:0:0:0", true);
		ipv6test(isLenient(), "0:0:0:0:00000:0:0:0", true);
		ipv6test(isLenient(), "0:0:0:0:0:00000:0:0", true);
		ipv6test(isLenient(), "0:0:0:0:0:0:00000:0", true);
		ipv6test(isLenient(), "0:0:0:0:0:0:0:00000", true);
		ipv6test(isLenient(), "00000:00000:00000:00000:00000:00000:00000:00000", true);
		
		ipv6test(isLenient(), "03333:0:0:0:0:0:0:0", false);
		ipv6test(isLenient(), "0:03333:0:0:0:0:0:0", false);
		ipv6test(isLenient(), "0:0:03333:0:0:0:0:0", false);
		ipv6test(isLenient(), "0:0:0:03333:0:0:0:0", false);
		ipv6test(isLenient(), "0:0:0:0:03333:0:0:0", false);
		ipv6test(isLenient(), "0:0:0:0:0:03333:0:0", false);
		ipv6test(isLenient(), "0:0:0:0:0:0:03333:0", false);
		ipv6test(isLenient(), "0:0:0:0:0:0:0:03333", false);
		ipv6test(isLenient(), "03333:03333:03333:03333:03333:03333:03333:03333", false);
		
		ipv4test(false, ".0.0.0");
		ipv4test(false, "0..0.0");
		ipv4test(false, "0.0..0");
		ipv4test(false, "0.0.0.");
		
		ipv4test(true, "/0");
		ipv4test(true, "/1");
		ipv4test(true, "/31");
		ipv4test(true, "/32");
		ipv4test(false, "/33", false, true);
		
		ipv4test(false, "1.2.3.4//16");
		ipv4test(false, "1.2.3.4//");
		ipv4test(false, "1.2.3.4/");
		ipv4test(false, "/1.2.3.4//16");
		ipv4test(false, "/1.2.3.4/16");
		ipv4test(false, "/1.2.3.4");
		ipv4test(false, "1.2.3.4/y");
		ipv4test(true, "1.2.3.4/16");
		ipv6test(false, "1:2::3:4//16");
		ipv6test(false, "1:2::3:4//");
		ipv6test(false, "1:2::3:4/");
		ipv6test(false, "1:2::3:4/y");
		ipv6test(true, "1:2::3:4/16");
		ipv6test(true, "1:2::3:1.2.3.4/16");
		ipv6test(false, "1:2::3:1.2.3.4//16");
		ipv6test(false, "1:2::3:1.2.3.4//");
		ipv6test(false, "1:2::3:1.2.3.4/y");
		
		ipv4test(false, "127.0.0.1/x");
		ipv4test(false, "127.0.0.1/127.0.0.1/x");

		ipv4_inet_aton_test(true, "0.0.0.255");
		ipv4_inet_aton_test(false, "0.0.0.256");
		ipv4_inet_aton_test(true, "0.0.65535");
		ipv4_inet_aton_test(false, "0.0.65536");
		ipv4_inet_aton_test(true, "0.16777215");
		ipv4_inet_aton_test(false, "0.16777216");
		ipv4_inet_aton_test(true, "4294967295");
		ipv4_inet_aton_test(false, "4294967296");
		ipv4_inet_aton_test(true, "0.0.0.0xff");
		ipv4_inet_aton_test(false, "0.0.0.0x100");
		ipv4_inet_aton_test(true, "0.0.0xffff");
		ipv4_inet_aton_test(false, "0.0.0x10000");
		ipv4_inet_aton_test(true, "0.0xffffff");
		ipv4_inet_aton_test(false, "0.0x1000000");
		ipv4_inet_aton_test(true, "0xffffffff");
		ipv4_inet_aton_test(false, "0x100000000");
		ipv4_inet_aton_test(true, "0.0.0.0377");
		ipv4_inet_aton_test(false, "0.0.0.0400");
		ipv4_inet_aton_test(true, "0.0.017777");
		ipv4_inet_aton_test(false, "0.0.0200000");
		ipv4_inet_aton_test(true, "0.077777777");
		ipv4_inet_aton_test(false, "0.0100000000");
		ipv4_inet_aton_test(true, "03777777777");
		ipv4_inet_aton_test(true, "037777777777");
		ipv4_inet_aton_test(false, "040000000000");
		
		ipv4_inet_aton_test(false, "1.00x.1.1");
		ipv4_inet_aton_test(false, "1.0xx.1.1");
		ipv4_inet_aton_test(false, "1.xx.1.1");
		ipv4_inet_aton_test(false, "1.0x4x.1.1");
		ipv4_inet_aton_test(false, "1.x4.1.1");
		
		ipv4test(false, "1.00x.1.1");
		ipv4test(false, "1.0xx.1.1");
		ipv4test(false, "1.xx.1.1");
		ipv4test(false, "1.0x4x.1.1");
		ipv4test(false, "1.x4.1.1");
		
		ipv4test(false, "1.4.1.1%1");//ipv4 zone
		
		ipv6test(false, "1:00x:3:4:5:6:7:8");
		ipv6test(false, "1:0xx:3:4:5:6:7:8");
		ipv6test(false, "1:xx:3:4:5:6:7:8");
		ipv6test(false, "1:0x4x:3:4:5:6:7:8");
		ipv6test(false, "1:x4:3:4:5:6:7:8");
		
		ipv4testOnly(false, "1:2:3:4:5:6:7:8");
		ipv4testOnly(false, "::1");
		
		//in this test, the validation will fail unless validation options have allowEmpty
		//if you allowempty and also emptyIsLoopback, then this will evaluate to either ipv4
		//or ipv6 depending on the loopback
		//if loopback is ipv4, then ipv6 validation fails but general validation passes because ipv4 passes because loopback is ipv4
		ipv6test(false, "", false, isLenient());	
		//ipv6test(0, ""); // empty string //this needs special validation options to be valid
		
		ipv6test(1, "/0");
		ipv6test(1, "/1");
		ipv6test(1, "/127");
		ipv6test(1, "/128");
		ipv6test(0, "/129");
		
		ipv6test(1, "::/0", isNoAutoSubnets); 
		ipv6test(0, ":1.2.3.4"); //invalid
		ipv6test(1, "::1.2.3.4");
		
		ipv6test(1,"::1");// loopback, compressed, non-routable
		ipv6test(1,"::", true);// unspecified, compressed, non-routable
		ipv6test(1,"0:0:0:0:0:0:0:1");// loopback, full
		ipv6test(1,"0:0:0:0:0:0:0:0", true);// unspecified, full
		ipv6test(1,"2001:DB8:0:0:8:800:200C:417A");// unicast, full
		ipv6test(1,"FF01:0:0:0:0:0:0:101");// multicast, full
		ipv6test(1,"2001:DB8::8:800:200C:417A");// unicast, compressed
		ipv6test(1,"FF01::101");// multicast, compressed
		ipv6test(0,"2001:DB8:0:0:8:800:200C:417A:221");// unicast, full
		ipv6test(0,"FF01::101::2");// multicast, compressed
		ipv6test(1,"fe80::217:f2ff:fe07:ed62");
		
		ipv6test(0,"[a::b:c:d:1.2.3.4]");//square brackets can enclose ipv6 in host names but not addresses
		ipv6testWithZone(0,"[a::b:c:d:1.2.3.4%x]");//zones not allowed when using []
		ipv6testWithZone(true,"a::b:c:d:1.2.3.4%x"); //zones allowed
		ipv6test(0,"[2001:0000:1234:0000:0000:C1C0:ABCD:0876]");//square brackets can enclose ipv6 in host names but not addresses
		ipv6testWithZone(true,"2001:0000:1234:0000:0000:C1C0:ABCD:0876%x");//zones allowed
		ipv6testWithZone(0,"[2001:0000:1234:0000:0000:C1C0:ABCD:0876%x]");//zones not allowed when using []
		
		ipv6test(1,"2001:0000:1234:0000:0000:C1C0:ABCD:0876");
		ipv6test(1,"3ffe:0b00:0000:0000:0001:0000:0000:000a");
		ipv6test(1,"FF02:0000:0000:0000:0000:0000:0000:0001");
		ipv6test(1,"0000:0000:0000:0000:0000:0000:0000:0001");
		ipv6test(1,"0000:0000:0000:0000:0000:0000:0000:0000", true);
		ipv6test(isLenient(),"02001:0000:1234:0000:0000:C1C0:ABCD:0876"); // extra 0 not allowed!
		ipv6test(isLenient(),"2001:0000:1234:0000:00001:C1C0:ABCD:0876"); // extra 0 not allowed!
		ipv6test(0,"2001:0000:1234:0000:0000:C1C0:ABCD:0876  0"); // junk after valid address
		ipv6test(0,"0 2001:0000:1234:0000:0000:C1C0:ABCD:0876"); // junk before valid address
		ipv6test(0,"2001:0000:1234: 0000:0000:C1C0:ABCD:0876"); // internal space
		
		ipv6test(0,"3ffe:0b00:0000:0001:0000:0000:000a"); // seven segments
		ipv6test(0,"FF02:0000:0000:0000:0000:0000:0000:0000:0001"); // nine segments
		ipv6test(0,"3ffe:b00::1::a"); // double "::"
		ipv6test(0,"::1111:2222:3333:4444:5555:6666::"); // double "::"
		ipv6test(1,"2::10");
		ipv6test(1,"ff02::1");
		ipv6test(1,"fe80::");
		ipv6test(1,"2002::");
		ipv6test(1,"2001:db8::");
		ipv6test(1,"2001:0db8:1234::");
		ipv6test(1,"::ffff:0:0");
		ipv6test(1,"::1");
		ipv6test(1,"1:2:3:4:5:6:7:8");
		ipv6test(1,"1:2:3:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::8");
		ipv6test(1,"1:2:3:4::8");
		ipv6test(1,"1:2:3::8");
		ipv6test(1,"1:2::8");
		ipv6test(1,"1::8");
		ipv6test(1,"1::2:3:4:5:6:7");
		ipv6test(1,"1::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:5");
		ipv6test(1,"1::2:3:4");
		ipv6test(1,"1::2:3");
		ipv6test(1,"1::8");
		
		ipv6test(1,"::2:3:4:5:6:7:8");
		ipv6test(1,"::2:3:4:5:6:7");
		ipv6test(1,"::2:3:4:5:6");
		ipv6test(1,"::2:3:4:5");
		ipv6test(1,"::2:3:4");
		ipv6test(1,"::2:3");
		ipv6test(1,"::8");
		ipv6test(1,"1:2:3:4:5:6::");
		ipv6test(1,"1:2:3:4:5::");
		ipv6test(1,"1:2:3:4::");
		ipv6test(1,"1:2:3::");
		ipv6test(1,"1:2::");
		ipv6test(1,"1::");
		ipv6test(1,"1:2:3:4:5::7:8");
		ipv6test(0,"1:2:3::4:5::7:8"); // Double "::"
		ipv6test(0,"12345::6:7:8");
		ipv6test(1,"1:2:3:4::7:8");
		ipv6test(1,"1:2:3::7:8");
		ipv6test(1,"1:2::7:8");
		ipv6test(1,"1::7:8");
		
		// IPv4 addresses as dotted-quads
		ipv6test(1,"1:2:3:4:5:6:1.2.3.4");
		ipv6test(1,"0:0:0:0:0:0:0.0.0.0", true);
		
		ipv6test(1,"1:2:3:4:5::1.2.3.4");
		ipv6test(1,"0:0:0:0:0::0.0.0.0", true);
		
		ipv6test(1,"0::0.0.0.0", true);
		ipv6test(1,"::0.0.0.0", true);
		
		ipv6test(0, "1:2:3:4:5:6:.2.3.4");
		ipv6test(0, "1:2:3:4:5:6:1.2.3.");
		ipv6test(0, "1:2:3:4:5:6:1.2..4");
		ipv6test(1, "1:2:3:4:5:6:1.2.3.4");
		
		ipv6test(1,"1:2:3:4::1.2.3.4");
		ipv6test(1,"1:2:3::1.2.3.4");
		ipv6test(1,"1:2::1.2.3.4");
		ipv6test(1,"1::1.2.3.4");
		ipv6test(1,"1:2:3:4::5:1.2.3.4");
		ipv6test(1,"1:2:3::5:1.2.3.4");
		ipv6test(1,"1:2::5:1.2.3.4");
		ipv6test(1,"1::5:1.2.3.4");
		ipv6test(1,"1::5:11.22.33.44");
		ipv6test(0,"1::5:400.2.3.4");
		ipv6test(0,"1::5:260.2.3.4");
		ipv6test(0,"1::5:256.2.3.4");
		ipv6test(0,"1::5:1.256.3.4");
		ipv6test(0,"1::5:1.2.256.4");
		ipv6test(0,"1::5:1.2.3.256");
		ipv6test(0,"1::5:300.2.3.4");
		ipv6test(0,"1::5:1.300.3.4");
		ipv6test(0,"1::5:1.2.300.4");
		ipv6test(0,"1::5:1.2.3.300");
		ipv6test(0,"1::5:900.2.3.4");
		ipv6test(0,"1::5:1.900.3.4");
		ipv6test(0,"1::5:1.2.900.4");
		ipv6test(0,"1::5:1.2.3.900");
		ipv6test(0,"1::5:300.300.300.300");
		ipv6test(0,"1::5:3000.30.30.30");
		ipv6test(0,"1::400.2.3.4");
		ipv6test(0,"1::260.2.3.4");
		ipv6test(0,"1::256.2.3.4");
		ipv6test(0,"1::1.256.3.4");
		ipv6test(0,"1::1.2.256.4");
		ipv6test(0,"1::1.2.3.256");
		ipv6test(0,"1::300.2.3.4");
		ipv6test(0,"1::1.300.3.4");
		ipv6test(0,"1::1.2.300.4");
		ipv6test(0,"1::1.2.3.300");
		ipv6test(0,"1::900.2.3.4");
		ipv6test(0,"1::1.900.3.4");
		ipv6test(0,"1::1.2.900.4");
		ipv6test(0,"1::1.2.3.900");
		ipv6test(0,"1::300.300.300.300");
		ipv6test(0,"1::3000.30.30.30");
		ipv6test(0,"::400.2.3.4");
		ipv6test(0,"::260.2.3.4");
		ipv6test(0,"::256.2.3.4");
		ipv6test(0,"::1.256.3.4");
		ipv6test(0,"::1.2.256.4");
		ipv6test(0,"::1.2.3.256");
		ipv6test(0,"::300.2.3.4");
		ipv6test(0,"::1.300.3.4");
		ipv6test(0,"::1.2.300.4");
		ipv6test(0,"::1.2.3.300");
		ipv6test(0,"::900.2.3.4");
		ipv6test(0,"::1.900.3.4");
		ipv6test(0,"::1.2.900.4");
		ipv6test(0,"::1.2.3.900");
		ipv6test(0,"::300.300.300.300");
		ipv6test(0,"::3000.30.30.30");
		ipv6test(1,"fe80::217:f2ff:254.7.237.98");
		ipv6test(1,"::ffff:192.168.1.26");
		ipv6test(0,"2001:1:1:1:1:1:255Z255X255Y255"); // garbage instead of "." in IPv4
		ipv6test(0,"::ffff:192x168.1.26"); // ditto
		ipv6test(1,"::ffff:192.168.1.1");
		ipv6test(1,"0:0:0:0:0:0:13.1.68.3");// IPv4-compatible IPv6 address, full, deprecated
		ipv6test(1,"0:0:0:0:0:FFFF:129.144.52.38");// IPv4-mapped IPv6 address, full
		ipv6test(1,"::13.1.68.3");// IPv4-compatible IPv6 address, compressed, deprecated
		ipv6test(1,"::FFFF:129.144.52.38");// IPv4-mapped IPv6 address, compressed
		ipv6test(1,"fe80:0:0:0:204:61ff:254.157.241.86");
		ipv6test(1,"fe80::204:61ff:254.157.241.86");
		ipv6test(1,"::ffff:12.34.56.78");
		ipv6test(isLenient(),"::ffff:2.3.4");
		ipv6test(0,"::ffff:257.1.2.3");
		ipv6testOnly(0,"1.2.3.4");
		
		//stuff that might be mistaken for mixed if we parse incorrectly
		ipv6test(0,"a:b:c:d:e:f:a:b:c:d:e:f:1.2.3.4");
		ipv6test(0,"a:b:c:d:e:f:a:b:c:d:e:f:a:b.");
		ipv6test(0,"a:b:c:d:e:f:1.a:b:c:d:e:f:a");
		ipv6test(0,"a:b:c:d:e:f:1.a:b:c:d:e:f:a:b");
		ipv6test(0,"a:b:c:d:e:f:.a:b:c:d:e:f:a:b");
		
		ipv6test(0,"::a:b:c:d:e:f:1.2.3.4");
		ipv6test(0,"::a:b:c:d:e:f:a:b.");
		ipv6test(0,"::1.a:b:c:d:e:f:a");
		ipv6test(0,"::1.a:b:c:d:e:f:a:b");
		ipv6test(0,"::.a:b:c:d:e:f:a:b");
		
		ipv6test(0,"1::a:b:c:d:e:f:1.2.3.4");
		ipv6test(0,"1::a:b:c:d:e:f:a:b.");
		ipv6test(0,"1::1.a:b:c:d:e:f:a");
		ipv6test(0,"1::1.a:b:c:d:e:f:a:b");
		ipv6test(0,"1::.a:b:c:d:e:f:a:b");
		
		ipv6test(1,"1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4");
		
		// Testing IPv4 addresses represented as dotted-quads
		// Leading zero's in IPv4 addresses not allowed: some systems treat the leading "0" in ".086" as the start of an octal number
		// Update: The BNF in RFC-3986 explicitly defines the dec-octet (for IPv4 addresses) not to have a leading zero
		//ipv6test(0,"fe80:0000:0000:0000:0204:61ff:254.157.241.086");
		ipv6test(!isLenient(),"fe80:0000:0000:0000:0204:61ff:254.157.241.086");//note the 086 is treated as octal when lenient!  So the lenient in this case fails.
		ipv6test(1,"::ffff:192.0.2.128");   // this is always OK, since there's a single digit
		ipv6test(0,"XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:1.2.3.4");
		//ipv6test(0,"1111:2222:3333:4444:5555:6666:00.00.00.00");
		ipv6test(1,"1111:2222:3333:4444:5555:6666:00.00.00.00");
		//ipv6test(0,"1111:2222:3333:4444:5555:6666:000.000.000.000");
		ipv6test(1,"1111:2222:3333:4444:5555:6666:000.000.000.000");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:256.256.256.256");
		
		
		// Not testing address with subnet mask
		// ipv6test(1,"2001:0DB8:0000:CD30:0000:0000:0000:0000/60");// full, with prefix
		// ipv6test(1,"2001:0DB8::CD30:0:0:0:0/60");// compressed, with prefix
		// ipv6test(1,"2001:0DB8:0:CD30::/60");// compressed, with prefix //2
		// ipv6test(1,"::/128");// compressed, unspecified address type, non-routable
		// ipv6test(1,"::1/128");// compressed, loopback address type, non-routable
		// ipv6test(1,"FF00::/8");// compressed, multicast address type
		// ipv6test(1,"FE80::/10");// compressed, link-local unicast, non-routable
		// ipv6test(1,"FEC0::/10");// compressed, site-local unicast, deprecated
		// ipv6test(0,"124.15.6.89/60");// standard IPv4, prefix not allowed
		
		ipv6test(1,"fe80:0000:0000:0000:0204:61ff:fe9d:f156");
		ipv6test(1,"fe80:0:0:0:204:61ff:fe9d:f156");
		ipv6test(1,"fe80::204:61ff:fe9d:f156");
		ipv6test(1,"::1");
		ipv6test(1,"fe80::");
		ipv6test(1,"fe80::1");
		ipv6test(0,":");
		ipv6test(1,"::ffff:c000:280");
		
		// Aeron supplied these test cases
		
		ipv6test(0,"1111:2222:3333:4444::5555:");
		ipv6test(0,"1111:2222:3333::5555:");
		ipv6test(0,"1111:2222::5555:");
		ipv6test(0,"1111::5555:");
		ipv6test(0,"::5555:");
		
		
		ipv6test(0,":::");
		ipv6test(0,"1111:");
		ipv6test(0,":");
		
		
		ipv6test(0,":1111:2222:3333:4444::5555");
		ipv6test(0,":1111:2222:3333::5555");
		ipv6test(0,":1111:2222::5555");
		ipv6test(0,":1111::5555");
		
		
		ipv6test(0,":::5555");
		ipv6test(0,":::");
		
		
		// Additional test cases
		// from http://rt.cpan.org/Public/Bug/Display.html?id=50693
		
		ipv6test(1,"2001:0db8:85a3:0000:0000:8a2e:0370:7334");
		ipv6test(1,"2001:db8:85a3:0:0:8a2e:370:7334");
		ipv6test(1,"2001:db8:85a3::8a2e:370:7334");
		ipv6test(1,"2001:0db8:0000:0000:0000:0000:1428:57ab");
		ipv6test(1,"2001:0db8:0000:0000:0000::1428:57ab");
		ipv6test(1,"2001:0db8:0:0:0:0:1428:57ab");
		ipv6test(1,"2001:0db8:0:0::1428:57ab");
		ipv6test(1,"2001:0db8::1428:57ab");
		ipv6test(1,"2001:db8::1428:57ab");
		ipv6test(1,"0000:0000:0000:0000:0000:0000:0000:0001");
		ipv6test(1,"::1");
		ipv6test(1,"::ffff:0c22:384e");
		ipv6test(1,"2001:0db8:1234:0000:0000:0000:0000:0000");
		ipv6test(1,"2001:0db8:1234:ffff:ffff:ffff:ffff:ffff");
		ipv6test(1,"2001:db8:a::123");
		ipv6test(1,"fe80::");
		
		ipv6test(false, "123", false, isLenient());//this is passing the ipv4 side as inet_aton
		ipv6test(0,"ldkfj");
		ipv6test(0,"2001::FFD3::57ab");
		ipv6test(0,"2001:db8:85a3::8a2e:37023:7334");
		ipv6test(0,"2001:db8:85a3::8a2e:370k:7334");
		ipv6test(0,"1:2:3:4:5:6:7:8:9");
		ipv6test(0,"1::2::3");
		ipv6test(0,"1:::3:4:5");
		ipv6test(0,"1:2:3::4:5:6:7:8:9");
		
		ipv6test(1,"1111:2222:3333:4444:5555:6666:7777:8888");
		ipv6test(1,"1111:2222:3333:4444:5555:6666:7777::");
		ipv6test(1,"1111:2222:3333:4444:5555:6666::");
		ipv6test(1,"1111:2222:3333:4444:5555::");
		ipv6test(1,"1111:2222:3333:4444::");
		ipv6test(1,"1111:2222:3333::");
		ipv6test(1,"1111:2222::");
		ipv6test(1,"1111::");
		ipv6test(1,"1111:2222:3333:4444:5555:6666::8888");
		ipv6test(1,"1111:2222:3333:4444:5555::8888");
		ipv6test(1,"1111:2222:3333:4444::8888");
		ipv6test(1,"1111:2222:3333::8888");
		ipv6test(1,"1111:2222::8888");
		ipv6test(1,"1111::8888");
		ipv6test(1,"::8888");
		ipv6test(1,"1111:2222:3333:4444:5555::7777:8888");
		ipv6test(1,"1111:2222:3333:4444::7777:8888");
		ipv6test(1,"1111:2222:3333::7777:8888");
		ipv6test(1,"1111:2222::7777:8888");
		ipv6test(1,"1111::7777:8888");
		ipv6test(1,"::7777:8888");
		ipv6test(1,"1111:2222:3333:4444::6666:7777:8888");
		ipv6test(1,"1111:2222:3333::6666:7777:8888");
		ipv6test(1,"1111:2222::6666:7777:8888");
		ipv6test(1,"1111::6666:7777:8888");
		ipv6test(1,"::6666:7777:8888");
		ipv6test(1,"1111:2222:3333::5555:6666:7777:8888");
		ipv6test(1,"1111:2222::5555:6666:7777:8888");
		ipv6test(1,"1111::5555:6666:7777:8888");
		ipv6test(1,"::5555:6666:7777:8888");
		ipv6test(1,"1111:2222::4444:5555:6666:7777:8888");
		ipv6test(1,"1111::4444:5555:6666:7777:8888");
		ipv6test(1,"::4444:5555:6666:7777:8888");
		ipv6test(1,"1111::3333:4444:5555:6666:7777:8888");
		ipv6test(1,"::3333:4444:5555:6666:7777:8888");
		ipv6test(1,"::2222:3333:4444:5555:6666:7777:8888");
		
		
		ipv6test(1,"1111:2222:3333:4444:5555:6666:123.123.123.123");
		ipv6test(1,"1111:2222:3333:4444:5555::123.123.123.123");
		ipv6test(1,"1111:2222:3333:4444::123.123.123.123");
		ipv6test(1,"1111:2222:3333::123.123.123.123");
		ipv6test(1,"1111:2222::123.123.123.123");
		ipv6test(1,"1111::123.123.123.123");
		ipv6test(1,"::123.123.123.123");
		ipv6test(1,"1111:2222:3333:4444::6666:123.123.123.123");
		ipv6test(1,"1111:2222:3333::6666:123.123.123.123");
		ipv6test(1,"1111:2222::6666:123.123.123.123");
		ipv6test(1,"1111::6666:123.123.123.123");
		ipv6test(1,"::6666:123.123.123.123");
		ipv6test(1,"1111:2222:3333::5555:6666:123.123.123.123");
		ipv6test(1,"1111:2222::5555:6666:123.123.123.123");
		ipv6test(1,"1111::5555:6666:123.123.123.123");
		ipv6test(1,"::5555:6666:123.123.123.123");
		ipv6test(1,"1111:2222::4444:5555:6666:123.123.123.123");
		ipv6test(1,"1111::4444:5555:6666:123.123.123.123");
		ipv6test(1,"::4444:5555:6666:123.123.123.123");
		ipv6test(1,"1111::3333:4444:5555:6666:123.123.123.123");
		ipv6test(1,"::2222:3333:4444:5555:6666:123.123.123.123");
		
		ipv6test(0,"1::2:3:4:5:6:1.2.3.4");
		
		ipv6test(1,"::", true);
		ipv6test(1,"0:0:0:0:0:0:0:0", true);
		
		// Playing with combinations of "0" and "::"
		// NB: these are all sytactically correct, but are bad form
		//   because "0" adjacent to "::" should be combined into "::"
		ipv6test(1,"::0:0:0:0:0:0:0", true);
		ipv6test(1,"::0:0:0:0:0:0", true);
		ipv6test(1,"::0:0:0:0:0", true);
		ipv6test(1,"::0:0:0:0", true);
		ipv6test(1,"::0:0:0", true);
		ipv6test(1,"::0:0", true);
		ipv6test(1,"::0", true);
		ipv6test(1,"0:0:0:0:0:0:0::", true);
		ipv6test(1,"0:0:0:0:0:0::", true);
		ipv6test(1,"0:0:0:0:0::", true);
		ipv6test(1,"0:0:0:0::", true);
		ipv6test(1,"0:0:0::", true);
		ipv6test(1,"0:0::", true);
		ipv6test(1,"0::", true);
		
		// New invalid from Aeron
		// Invalid data
		ipv6test(0,"XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX");
		
		// Too many components
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:8888:9999");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:8888::");
		ipv6test(0,"::2222:3333:4444:5555:6666:7777:8888:9999");
		
		// Too few components
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777");
		ipv6test(0,"1111:2222:3333:4444:5555:6666");
		ipv6test(0,"1111:2222:3333:4444:5555");
		ipv6test(0,"1111:2222:3333:4444");
		ipv6test(0,"1111:2222:3333");
		ipv6test(0,"1111:2222");
		ipv6test(false, "1111", false, isLenient());// this is passing the ipv4 side for inet_aton
		//ipv6test(0,"1111");
		
		// Missing :
		ipv6test(0,"11112222:3333:4444:5555:6666:7777:8888");
		ipv6test(0,"1111:22223333:4444:5555:6666:7777:8888");
		ipv6test(0,"1111:2222:33334444:5555:6666:7777:8888");
		ipv6test(0,"1111:2222:3333:44445555:6666:7777:8888");
		ipv6test(0,"1111:2222:3333:4444:55556666:7777:8888");
		ipv6test(0,"1111:2222:3333:4444:5555:66667777:8888");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:77778888");
		
		// Missing : intended for ::
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:8888:");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:");
		ipv6test(0,"1111:2222:3333:4444:5555:");
		ipv6test(0,"1111:2222:3333:4444:");
		ipv6test(0,"1111:2222:3333:");
		ipv6test(0,"1111:2222:");
		ipv6test(0,"1111:");
		ipv6test(0,":");
		ipv6test(0,":8888");
		ipv6test(0,":7777:8888");
		ipv6test(0,":6666:7777:8888");
		ipv6test(0,":5555:6666:7777:8888");
		ipv6test(0,":4444:5555:6666:7777:8888");
		ipv6test(0,":3333:4444:5555:6666:7777:8888");
		ipv6test(0,":2222:3333:4444:5555:6666:7777:8888");
		ipv6test(0,":1111:2222:3333:4444:5555:6666:7777:8888");
		
		// :::
		ipv6test(0,":::2222:3333:4444:5555:6666:7777:8888");
		ipv6test(0,"1111:::3333:4444:5555:6666:7777:8888");
		ipv6test(0,"1111:2222:::4444:5555:6666:7777:8888");
		ipv6test(0,"1111:2222:3333:::5555:6666:7777:8888");
		ipv6test(0,"1111:2222:3333:4444:::6666:7777:8888");
		ipv6test(0,"1111:2222:3333:4444:5555:::7777:8888");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:::8888");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:::");
		
		// Double ::");
		ipv6test(0,"::2222::4444:5555:6666:7777:8888");
		ipv6test(0,"::2222:3333::5555:6666:7777:8888");
		ipv6test(0,"::2222:3333:4444::6666:7777:8888");
		ipv6test(0,"::2222:3333:4444:5555::7777:8888");
		ipv6test(0,"::2222:3333:4444:5555:7777::8888");
		ipv6test(0,"::2222:3333:4444:5555:7777:8888::");
		
		ipv6test(0,"1111::3333::5555:6666:7777:8888");
		ipv6test(0,"1111::3333:4444::6666:7777:8888");
		ipv6test(0,"1111::3333:4444:5555::7777:8888");
		ipv6test(0,"1111::3333:4444:5555:6666::8888");
		ipv6test(0,"1111::3333:4444:5555:6666:7777::");
		
		ipv6test(0,"1111:2222::4444::6666:7777:8888");
		ipv6test(0,"1111:2222::4444:5555::7777:8888");
		ipv6test(0,"1111:2222::4444:5555:6666::8888");
		ipv6test(0,"1111:2222::4444:5555:6666:7777::");
		
		ipv6test(0,"1111:2222:3333::5555::7777:8888");
		ipv6test(0,"1111:2222:3333::5555:6666::8888");
		ipv6test(0,"1111:2222:3333::5555:6666:7777::");
		
		ipv6test(0,"1111:2222:3333:4444::6666::8888");
		ipv6test(0,"1111:2222:3333:4444::6666:7777::");
		
		ipv6test(0,"1111:2222:3333:4444:5555::7777::");
		
		
		
		// Too many components"
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:8888:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:5555:6666::1.2.3.4");
		ipv6test(0,"::2222:3333:4444:5555:6666:7777:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:1.2.3.4.5");
		
		// Too few components
		ipv6test(0,"1111:2222:3333:4444:5555:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:1.2.3.4");
		ipv6test(0,"1111:2222:3333:1.2.3.4");
		ipv6test(0,"1111:2222:1.2.3.4");
		ipv6test(0,"1111:1.2.3.4");
		ipv6testOnly(0,"1.2.3.4");
		
		// Missing :
		ipv6test(0,"11112222:3333:4444:5555:6666:1.2.3.4");
		ipv6test(0,"1111:22223333:4444:5555:6666:1.2.3.4");
		ipv6test(0,"1111:2222:33334444:5555:6666:1.2.3.4");
		ipv6test(0,"1111:2222:3333:44445555:6666:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:55556666:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:5555:66661.2.3.4");
		
		// Missing .
		ipv6test(0,"1111:2222:3333:4444:5555:6666:255255.255.255");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:255.255255.255");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:255.255.255255");
		
		
		// Missing : intended for ::
		ipv6test(0,":1.2.3.4");
		ipv6test(0,":6666:1.2.3.4");
		ipv6test(0,":5555:6666:1.2.3.4");
		ipv6test(0,":4444:5555:6666:1.2.3.4");
		ipv6test(0,":3333:4444:5555:6666:1.2.3.4");
		ipv6test(0,":2222:3333:4444:5555:6666:1.2.3.4");
		ipv6test(0,":1111:2222:3333:4444:5555:6666:1.2.3.4");
		
		// :::
		ipv6test(0,":::2222:3333:4444:5555:6666:1.2.3.4");
		ipv6test(0,"1111:::3333:4444:5555:6666:1.2.3.4");
		ipv6test(0,"1111:2222:::4444:5555:6666:1.2.3.4");
		ipv6test(0,"1111:2222:3333:::5555:6666:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:::6666:1.2.3.4");
		ipv6test(0,"1111:2222:3333:4444:5555:::1.2.3.4");
		
		// Double ::
		ipv6test(0,"::2222::4444:5555:6666:1.2.3.4");
		ipv6test(0,"::2222:3333::5555:6666:1.2.3.4");
		ipv6test(0,"::2222:3333:4444::6666:1.2.3.4");
		ipv6test(0,"::2222:3333:4444:5555::1.2.3.4");
		
		ipv6test(0,"1111::3333::5555:6666:1.2.3.4");
		ipv6test(0,"1111::3333:4444::6666:1.2.3.4");
		ipv6test(0,"1111::3333:4444:5555::1.2.3.4");
		
		ipv6test(0,"1111:2222::4444::6666:1.2.3.4");
		ipv6test(0,"1111:2222::4444:5555::1.2.3.4");
		
		ipv6test(0,"1111:2222:3333::5555::1.2.3.4");
		
		
		
		// Missing parts
		ipv6test(0,"::.");
		ipv6test(0,"::..");
		ipv6test(0,"::...");
		ipv6test(0,"::1...");
		ipv6test(0,"::1.2..");
		ipv6test(0,"::1.2.3.");
		ipv6test(0,"::.2..");
		ipv6test(0,"::.2.3.");
		ipv6test(0,"::.2.3.4");
		ipv6test(0,"::..3.");
		ipv6test(0,"::..3.4");
		ipv6test(0,"::...4");
		
		
		// Extra : in front
		ipv6test(0,":1111:2222:3333:4444:5555:6666:7777::");
		ipv6test(0,":1111:2222:3333:4444:5555:6666::");
		ipv6test(0,":1111:2222:3333:4444:5555::");
		ipv6test(0,":1111:2222:3333:4444::");
		ipv6test(0,":1111:2222:3333::");
		ipv6test(0,":1111:2222::");
		ipv6test(0,":1111::");
		ipv6test(0,":::");
		ipv6test(0,":1111:2222:3333:4444:5555:6666::8888");
		ipv6test(0,":1111:2222:3333:4444:5555::8888");
		ipv6test(0,":1111:2222:3333:4444::8888");
		ipv6test(0,":1111:2222:3333::8888");
		ipv6test(0,":1111:2222::8888");
		ipv6test(0,":1111::8888");
		ipv6test(0,":::8888");
		ipv6test(0,":1111:2222:3333:4444:5555::7777:8888");
		ipv6test(0,":1111:2222:3333:4444::7777:8888");
		ipv6test(0,":1111:2222:3333::7777:8888");
		ipv6test(0,":1111:2222::7777:8888");
		ipv6test(0,":1111::7777:8888");
		ipv6test(0,":::7777:8888");
		ipv6test(0,":1111:2222:3333:4444::6666:7777:8888");
		ipv6test(0,":1111:2222:3333::6666:7777:8888");
		ipv6test(0,":1111:2222::6666:7777:8888");
		ipv6test(0,":1111::6666:7777:8888");
		ipv6test(0,":::6666:7777:8888");
		ipv6test(0,":1111:2222:3333::5555:6666:7777:8888");
		ipv6test(0,":1111:2222::5555:6666:7777:8888");
		ipv6test(0,":1111::5555:6666:7777:8888");
		ipv6test(0,":::5555:6666:7777:8888");
		ipv6test(0,":1111:2222::4444:5555:6666:7777:8888");
		ipv6test(0,":1111::4444:5555:6666:7777:8888");
		ipv6test(0,":::4444:5555:6666:7777:8888");
		ipv6test(0,":1111::3333:4444:5555:6666:7777:8888");
		ipv6test(0,":::3333:4444:5555:6666:7777:8888");
		ipv6test(0,":::2222:3333:4444:5555:6666:7777:8888");
		
		
		ipv6test(0,":1111:2222:3333:4444:5555:6666:1.2.3.4");
		ipv6test(0,":1111:2222:3333:4444:5555::1.2.3.4");
		ipv6test(0,":1111:2222:3333:4444::1.2.3.4");
		ipv6test(0,":1111:2222:3333::1.2.3.4");
		ipv6test(0,":1111:2222::1.2.3.4");
		ipv6test(0,":1111::1.2.3.4");
		ipv6test(0,":::1.2.3.4");
		ipv6test(0,":1111:2222:3333:4444::6666:1.2.3.4");
		ipv6test(0,":1111:2222:3333::6666:1.2.3.4");
		ipv6test(0,":1111:2222::6666:1.2.3.4");
		ipv6test(0,":1111::6666:1.2.3.4");
		ipv6test(0,":::6666:1.2.3.4");
		ipv6test(0,":1111:2222:3333::5555:6666:1.2.3.4");
		ipv6test(0,":1111:2222::5555:6666:1.2.3.4");
		ipv6test(0,":1111::5555:6666:1.2.3.4");
		ipv6test(0,":::5555:6666:1.2.3.4");
		ipv6test(0,":1111:2222::4444:5555:6666:1.2.3.4");
		ipv6test(0,":1111::4444:5555:6666:1.2.3.4");
		ipv6test(0,":::4444:5555:6666:1.2.3.4");
		ipv6test(0,":1111::3333:4444:5555:6666:1.2.3.4");
		ipv6test(0,":::2222:3333:4444:5555:6666:1.2.3.4");
		
		
		// Extra : at end
		ipv6test(0,"1111:2222:3333:4444:5555:6666:7777:::");
		ipv6test(0,"1111:2222:3333:4444:5555:6666:::");
		ipv6test(0,"1111:2222:3333:4444:5555:::");
		ipv6test(0,"1111:2222:3333:4444:::");
		ipv6test(0,"1111:2222:3333:::");
		ipv6test(0,"1111:2222:::");
		ipv6test(0,"1111:::");
		ipv6test(0,":::");
		ipv6test(0,"1111:2222:3333:4444:5555:6666::8888:");
		ipv6test(0,"1111:2222:3333:4444:5555::8888:");
		ipv6test(0,"1111:2222:3333:4444::8888:");
		ipv6test(0,"1111:2222:3333::8888:");
		ipv6test(0,"1111:2222::8888:");
		ipv6test(0,"1111::8888:");
		ipv6test(0,"::8888:");
		ipv6test(0,"1111:2222:3333:4444:5555::7777:8888:");
		ipv6test(0,"1111:2222:3333:4444::7777:8888:");
		ipv6test(0,"1111:2222:3333::7777:8888:");
		ipv6test(0,"1111:2222::7777:8888:");
		ipv6test(0,"1111::7777:8888:");
		ipv6test(0,"::7777:8888:");
		ipv6test(0,"1111:2222:3333:4444::6666:7777:8888:");
		ipv6test(0,"1111:2222:3333::6666:7777:8888:");
		ipv6test(0,"1111:2222::6666:7777:8888:");
		ipv6test(0,"1111::6666:7777:8888:");
		ipv6test(0,"::6666:7777:8888:");
		ipv6test(0,"1111:2222:3333::5555:6666:7777:8888:");
		ipv6test(0,"1111:2222::5555:6666:7777:8888:");
		ipv6test(0,"1111::5555:6666:7777:8888:");
		ipv6test(0,"::5555:6666:7777:8888:");
		ipv6test(0,"1111:2222::4444:5555:6666:7777:8888:");
		ipv6test(0,"1111::4444:5555:6666:7777:8888:");
		ipv6test(0,"::4444:5555:6666:7777:8888:");
		ipv6test(0,"1111::3333:4444:5555:6666:7777:8888:");
		ipv6test(0,"::3333:4444:5555:6666:7777:8888:");
		ipv6test(0,"::2222:3333:4444:5555:6666:7777:8888:");
		
		// Additional cases: http://crisp.tweakblogs.net/blog/2031/ipv6-validation-%28and-caveats%29.html
		ipv6test(1,"0:a:b:c:d:e:f::");
		ipv6test(1,"::0:a:b:c:d:e:f"); // syntactically correct, but bad form (::0:... could be combined)
		ipv6test(1,"a:b:c:d:e:f:0::");
		ipv6test(0,"':10.0.0.1");
		
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8", new Integer[9]);
		testInsertAndAppend("1.2.3.4", "5.6.7.8", new Integer[5]);
		
		testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8");
		testReplace("1.2.3.4", "5.6.7.8");
		
		testSQLMatching();
		
		testInvalidIpv4Values();
		
		testInvalidIpv6Values();
		
		testIPv4Values(new int[] {1, 2, 3, 4}, "16909060");
		testIPv4Values(new int[4], "0");
		testIPv4Values(new int[] {255, 255, 255, 255}, String.valueOf(0xffffffffL));
		
		testIPv6Values(new int[] {1, 2, 3, 4, 5, 6, 7, 8}, "5192455318486707404433266433261576");
		testIPv6Values(new int[8], "0");
		BigInteger thirtyTwo = BigInteger.valueOf(0xffffffffL);
		BigInteger one28 = thirtyTwo.shiftLeft(96).or(thirtyTwo.shiftLeft(64).or(thirtyTwo.shiftLeft(32).or(thirtyTwo)));
		testIPv6Values(new int[] {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff}, one28.toString());
		
		
		testSub("10.0.0.0/22", "10.0.1.0/24", isNoAutoSubnets ?  new String[] {"10.0.0.0/22"} : new String[] {"10.0.0.0/24", "10.0.2.0/23"});
		
		testIntersect("1:1::/32", "1:1:1:1:1:1:1:1", isNoAutoSubnets ? null : "1:1:1:1:1:1:1:1");//1:1:0:0:0:0:0:0/32
		testIntersect("1:1::/32", "1:1::/16", "1:1::/32", !allPrefixesAreSubnets); //1:1::/16 1:1:0:0:0:0:0:0/32
		testIntersect("1:1::/32", "1:1::/48", "1:1::/48");
		testIntersect("1:1::/32", "1:1::/64", "1:1::/64");
		testIntersect("1:1::/32", "1:1:2:2::/64", isNoAutoSubnets ? null : "1:1:2:2::/64");
		testIntersect("1:1::/32", "1:0:2:2::/64", null);
		testIntersect("10.0.0.0/22", "10.0.0.0/24", "10.0.0.0/24");//[10.0.0.0/24, 10.0.2.0/23]
		testIntersect("10.0.0.0/22", "10.0.1.0/24", isNoAutoSubnets ? null : "10.0.1.0/24");//[10.0.1-3.0/24]
		
		testToPrefixBlock("1:3::3:4", "1:3::3:4");
		testToPrefixBlock("1.3.3.4", "1.3.3.4");
		
		testMaxHost("1.2.3.4", allPrefixesAreSubnets ? "255.255.255.255" : "255.255.255.255/0");
		testMaxHost("1.2.255.255/16", allPrefixesAreSubnets ? "1.2.255.255" : "1.2.255.255/16");
		
		testMaxHost("1:2:3:4:5:6:7:8", allPrefixesAreSubnets ? "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0");
		testMaxHost("1:2:ffff:ffff:ffff:ffff:ffff:ffff/64", allPrefixesAreSubnets ? "1:2:ffff:ffff:ffff:ffff:ffff:ffff" : "1:2:ffff:ffff:ffff:ffff:ffff:ffff/64");
		testMaxHost("1:2:3:4:5:6:7:8/64", allPrefixesAreSubnets ? "1:2:3:4:ffff:ffff:ffff:ffff" : "1:2:3:4:ffff:ffff:ffff:ffff/64");
		testMaxHost("1:2:3:4:5:6:7:8/128", allPrefixesAreSubnets ? "1:2:3:4:5:6:7:8" : "1:2:3:4:5:6:7:8/128");
		
		testZeroHost("1.2.3.4", allPrefixesAreSubnets ? "0.0.0.0" : "0.0.0.0/0");
		testZeroHost("1.2.0.0/16", allPrefixesAreSubnets ? "1.2.0.0" : "1.2.0.0/16");
		
		testZeroHost("1:2:3:4:5:6:7:8", allPrefixesAreSubnets ? "::" : "::/0");
		testZeroHost("1:2::/64", allPrefixesAreSubnets ? "1:2::" : "1:2::/64");
		testZeroHost("1:2:3:4:5:6:7:8/64", allPrefixesAreSubnets ? "1:2:3:4::" : "1:2:3:4::/64");
		testZeroHost("1:2:3:4:5:6:7:8/128", allPrefixesAreSubnets ? "1:2:3:4:5:6:7:8" : "1:2:3:4:5:6:7:8/128");

		testPrefixBlocks("1.2.3.4", false, false);
		testPrefixBlocks("1.2.3.4/16", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("1.2.0.0/16", isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("1.2.3.4/0", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("1.2.3.3/31", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("1.2.3.4/31", isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("1.2.3.4/32", true, true);
		
		testPrefixBlocks("1.2.3.4", 8, false, false);
		testPrefixBlocks("1.2.3.4/16", 8, false, false);
		testPrefixBlocks("1.2.0.0/16", 8, false, false);
		testPrefixBlocks("1.2.3.4/0", 8, allPrefixesAreSubnets, false);
		testPrefixBlocks("1.2.3.4/8", 8, allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("1.2.3.4/31", 8, false, false);
		testPrefixBlocks("1.2.3.4/32", 8, false, false);
		
		testPrefixBlocks("1.2.3.4", 24, false, false);
		testPrefixBlocks("1.2.3.4/16", 24, allPrefixesAreSubnets, false);
		testPrefixBlocks("1.2.0.0/16", 24, isAutoSubnets, false);
		testPrefixBlocks("1.2.3.4/0", 24, allPrefixesAreSubnets, false);
		testPrefixBlocks("1.2.3.4/24", 24, allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("1.2.3.4/31", 24, false, false);
		testPrefixBlocks("1.2.3.4/32", 24, false, false);

		testPrefixBlocks("a:b:c:d:e:f:a:b", false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/64", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d::/64", isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("a:b:c:d:e::/64", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c::/64", isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/0", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/127", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/128", true, true);
		
		testPrefixBlocks("a:b:c:d:e:f:a:b", 0, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/64", 0, false, false);
		testPrefixBlocks("a:b:c:d::/64", 0, false, false);
		testPrefixBlocks("a:b:c:d:e::/64", 0, false, false);
		testPrefixBlocks("a:b:c::/64", 0, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/0", 0, allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/127", 0, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/128", 0, false, false);
		
		testPrefixBlocks("a:b:c:d:e:f:a:b", 63, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/64", 63, false, false);
		testPrefixBlocks("a:b:c:d::/64", 63, false, false);
		testPrefixBlocks("a:b:c:d:e::/64", 63, false, false);
		testPrefixBlocks("a:b:c::/64", 63, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/0", 63, allPrefixesAreSubnets, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/127", 63, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/128", 63, false, false);
		
		testPrefixBlocks("a:b:c:d:e:f:a:b", 64, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/64", 64, allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d::/64", 64, isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("a:b:c:d:e::/64", 64, allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c::/64", 64, isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/0", 64, allPrefixesAreSubnets, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/127", 64, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/128", 64, false, false);
		
		testPrefixBlocks("a:b:c:d:e:f:a:b", 65, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/64", 65, allPrefixesAreSubnets, false);
		testPrefixBlocks("a:b:c:d::/64", 65, isAutoSubnets, false);
		testPrefixBlocks("a:b:c:d:e::/64", 65, allPrefixesAreSubnets, false);
		testPrefixBlocks("a:b:c::/64", 65, isAutoSubnets, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/0", 65, allPrefixesAreSubnets, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/127", 65, false, false);
		testPrefixBlocks("a:b:c:d:e:f:a:b/128", 65, false, false);

		testPrefixBlocks("a:b:c:d:e:f:a:b", 128, true, true);
		testPrefixBlocks("a:b:c:d:e:f:a:b/64", 128, true, !allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d::/64", 128, true, !isAutoSubnets);
		testPrefixBlocks("a:b:c:d:e::/64", 128, true, !allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c::/64", 128, true, !isAutoSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/0", 128, true, !allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/127", 128, true, !allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:e:f:a:b/128", 128, true, true);
		
		testSplitBytes("1.2.3.4");
		testSplitBytes("1.2.3.4/16");
		testSplitBytes("1.2.3.4/0");
		testSplitBytes("1.2.3.4/32");
		testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb");
		testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb/64");
		testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb/0");
		testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb/128");
		
		
		testByteExtension("255.255.255.255", new byte[][] {
			new byte[] {0, 0, -1, -1, -1, -1},
			new byte[] {0, -1, -1, -1, -1},
			new byte[] {-1, -1, -1, -1},
			new byte[] {-1, -1},
			new byte[] {-1}
		});
		testByteExtension("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", new byte[][] {
			new byte[] {0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			new byte[] {0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			new byte[] {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			new byte[] {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
			new byte[] {-1, -1, -1},
			new byte[] {-1, -1},
			new byte[] {-1}
		});
		testByteExtension("0.0.0.255", new byte[][] {
			new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, -1},
			new byte[] {0, 0, 0, 0, 0, 0, 0, 0, -1},
			new byte[] {0, 0, 0, 0, -1},
			new byte[] {0, 0, 0, -1},
			new byte[] {0, -1},
		});
		testByteExtension("::ff", new byte[][] {
			new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1},
			new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1},
			new byte[] {0, -1},
		});
		testByteExtension("0.0.0.127", new byte[][] {
			new byte[] {0, 0, 0, 0, 0, 127},
			new byte[] {0, 0, 0, 0, 127},
			new byte[] {0, 0, 0, 127},
			new byte[] {0, 127},
			new byte[] {127},
		});
		testByteExtension("::7f", new byte[][] {
			new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127},
			new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127},
			new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127},
			new byte[] {0, 0, 127},
			new byte[] {0, 127},
			new byte[] {127},
		});
		testByteExtension("255.255.255.128", new byte[][] {
			new byte[] {-1, -1, -1, -1, -1, -128},
			new byte[] {-1, -1, -1, -1, -128},
			new byte[] {0, 0, -1, -1, -1, -128},
			new byte[] {0, -1, -1, -1, -128},
			new byte[] {-1, -1, -1, -128},
			new byte[] {-1, -128},
			new byte[] {-128}
		});
		testByteExtension("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff80", new byte[][] {
			new byte[] {0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128},
			new byte[] {0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128},
			new byte[] {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128},
			new byte[] {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128},
			new byte[] {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128},
			new byte[] {-1, -1, -128},
			new byte[] {-1, -128},
			new byte[] {-128}
		});
		testByteExtension("ffff:ffff:ffff:ffff:ffff:ffff:ffff:8000", new byte[][] {
			new byte[] {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128, 0},
			new byte[] {0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128, 0},
			new byte[] {0, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128, 0},
			new byte[] {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128, 0},
			new byte[] {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -128, 0},
			new byte[] {-1, -128, 0},
			new byte[] {-128, 0}
		});
		testByteExtension("1.2.3.4", new byte[][] {
			new byte[] {1, 2, 3, 4},
			new byte[] {0, 1, 2, 3, 4},
		});
		testByteExtension("102:304:506:708:90a:b0c:d0e:f10", new byte[][] {
			new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		});

		testLargeDivs(new byte[][] {
			new byte[] {1, 2, 3, 4, 5}, 
			new byte[] {6, 7, 8, 9, 10, 11, 12}, 
			new byte[] {13, 14, 15, 16}
		});
		testLargeDivs(new byte[][] {
			new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		});
		testLargeDivs(new byte[][] {
			new byte[] {1, 2, 3, 4, 5}, 
			//new byte[] {},
			new byte[] {6, 7, 8, 9, 10, 11, 12}, 
			new byte[] {13, 14, 15, 16}
		});
		testLargeDivs(new byte[][] {
			new byte[] {1}, new byte[] {2}, new byte[] {3}, new byte[] {4}, new byte[] {5}, 
			new byte[] {6, 7}, new byte[] {8}, new byte[] {9}, new byte[] {10}, new byte[] {11}, new byte[] {12}, 
			new byte[] {13}, new byte[] {14}, new byte[] {15}, new byte[] {16}
		});
		testLargeDivs(new byte[][] {
			new byte[] {1}, 
			new byte[] {2, 3}, 
			new byte[] {4}
		});
		
			
		testIncrement("1.2.3.4", 0, "1.2.3.4");
		testIncrement("1.2.3.4", 1, "1.2.3.5");
		testIncrement("1.2.3.4", -1, "1.2.3.3");
		testIncrement("1.2.3.4", -4, "1.2.3.0");
		testIncrement("1.2.3.4", -5, "1.2.2.255");
		testIncrement("0.0.0.4", -5, null);
		testIncrement("1.2.3.4", 251, "1.2.3.255");
		testIncrement("1.2.3.4", 252, "1.2.4.0");
		testIncrement("1.2.3.4", 256, "1.2.4.4");
		testIncrement("1.2.3.4", 256, "1.2.4.4");
		testIncrement("1.2.3.4", 65536, "1.3.3.4");
		testIncrement("1.2.3.4", 16777216, "2.2.3.4");
		testIncrement("1.2.3.4", 4261412864L, "255.2.3.4");
		testIncrement("1.2.3.4", 4278190080L, null);
		testIncrement("1.2.3.4", 4278058236L, null);
		testIncrement("255.0.0.4", -4278190084L, "0.0.0.0");
		testIncrement("255.0.0.4", -4278190085L, null);
		
		testIncrement("ffff:ffff:ffff:ffff:f000::0", 1, "ffff:ffff:ffff:ffff:f000::1");
		testIncrement("ffff:ffff:ffff:ffff:f000::0", -1, "ffff:ffff:ffff:ffff:efff:ffff:ffff:ffff");
		testIncrement("ffff:ffff:ffff:ffff:8000::", Long.MIN_VALUE, "ffff:ffff:ffff:ffff::");
		testIncrement("ffff:ffff:ffff:ffff:7fff:ffff:ffff:ffff", Long.MIN_VALUE, "ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff");
		testIncrement("ffff:ffff:ffff:ffff:7fff:ffff:ffff:fffe", Long.MIN_VALUE, "ffff:ffff:ffff:fffe:ffff:ffff:ffff:fffe");
		testIncrement("::8000:0:0:0", Long.MIN_VALUE, "::");
		testIncrement("::7fff:ffff:ffff:ffff", Long.MIN_VALUE, null);
		testIncrement("::7fff:ffff:ffff:ffff", Long.MIN_VALUE, null);
		testIncrement("::7fff:ffff:ffff:fffe", Long.MIN_VALUE, null);
		testIncrement("ffff:ffff:ffff:ffff:8000::0", Long.MAX_VALUE, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		testIncrement("ffff:ffff:ffff:ffff:8000::1", Long.MAX_VALUE, null);
		testIncrement("::1", 1, "::2");
		testIncrement("::1", 0, "::1");
		testIncrement("::1", -1, "::");
		testIncrement("::1", -2, null);
		testIncrement("::2", 1, "::3");
		testIncrement("::2", -1, "::1");
		testIncrement("::2", -2, "::");
		testIncrement("::2", -3, null);
		
		testIncrement("1::1", 0, "1::1");
		testIncrement("1::1", 1, "1::2");
		testIncrement("1::1", -1, "1::");
		testIncrement("1::1", -2, "::ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		testIncrement("1::2", 1, "1::3");
		testIncrement("1::2", -1, "1::1");
		testIncrement("1::2", -2, "1::");
		testIncrement("1::2", -3, "::ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		
		testIncrement("::fffe", 2, "::1:0");
		testIncrement("::ffff", 2, "::1:1");
		testIncrement("::1:ffff", 2, "::2:1");
		testIncrement("::1:ffff", -2, "::1:fffd");
		testIncrement("::1:ffff", -0x10000, "::ffff");
		testIncrement("::1:ffff", -0x10001, "::fffe");
		
		//a b x y
		testRangeJoin("1.2.3.4", "1.2.4.3", "1.2.4.5", "1.2.5.6", null, null);
		testRangeIntersect("1.2.3.4", "1.2.4.3", "1.2.4.5", "1.2.5.6", null, null);
		testRangeSubtract("1.2.3.4", "1.2.4.3", "1.2.4.5", "1.2.5.6", "1.2.3.4", "1.2.4.3");
		
		
		//a x b y
		testRangeJoin("1.2.3.4", "1.2.4.5", "1.2.4.3", "1.2.5.6", "1.2.3.4", "1.2.5.6");
		testRangeIntersect("1.2.3.4", "1.2.4.5", "1.2.4.3", "1.2.5.6", "1.2.4.3", "1.2.4.5");
		testRangeSubtract("1.2.3.4", "1.2.4.5", "1.2.4.3", "1.2.5.6", "1.2.3.4", "1.2.4.2");
		
		//a x y b
		testRangeJoin("1.2.3.4", "1.2.5.6", "1.2.4.3", "1.2.4.5", "1.2.3.4", "1.2.5.6");
		testRangeIntersect("1.2.3.4", "1.2.5.6", "1.2.4.3", "1.2.4.5", "1.2.4.3", "1.2.4.5");
		testRangeSubtract("1.2.3.4", "1.2.5.6", "1.2.4.3", "1.2.4.5", "1.2.3.4", "1.2.4.2", "1.2.4.6", "1.2.5.6");
		
		//a b x y
		testRangeJoin("1:2:3:4::", "1:2:4:3::", "1:2:4:5::", "1:2:5:6::", null, null);
		testRangeIntersect("1:2:3:4::", "1:2:4:3::", "1:2:4:5::", "1:2:5:6::", null, null);
		testRangeSubtract("1:2:3:4::", "1:2:4:3::", "1:2:4:5::", "1:2:5:6::", "1:2:3:4::", "1:2:4:3::");
		
		//a x b y
		testRangeJoin("1:2:3:4::", "1:2:4:5::", "1:2:4:3::", "1:2:5:6::", "1:2:3:4::", "1:2:5:6::");
		testRangeIntersect("1:2:3:4::", "1:2:4:5::", "1:2:4:3::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::");
		testRangeSubtract("1:2:3:4::", "1:2:4:5::", "1:2:4:3::", "1:2:5:6::", "1:2:3:4::", "1:2:4:2:ffff:ffff:ffff:ffff");
		
		//a x y b
		testRangeJoin("1:2:3:4::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::", "1:2:3:4::", "1:2:5:6::");
		testRangeIntersect("1:2:3:4::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::", "1:2:4:3::", "1:2:4:5::");
		testRangeSubtract("1:2:3:4::", "1:2:5:6::", "1:2:4:3::", "1:2:4:5::", "1:2:3:4::", "1:2:4:2:ffff:ffff:ffff:ffff", "1:2:4:5::1", "1:2:5:6::");	

		testCustomNetwork(prefixConfiguration);
	}
}


