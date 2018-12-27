package inet.ipaddr.test;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.StringOptions;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringException;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.sql.MySQLTranslator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSection.CompressOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.test.IPAddressTest.HostKey;
import inet.ipaddr.test.IPAddressTest.IPAddressStringKey;


public class IPAddressTest extends TestBase {

	IPAddressTest(AddressCreator creator) {
		super(creator);
	}
	
	static abstract class LookupKey<T extends Comparable<T>> implements Comparable<LookupKey<T>>, Serializable {
		
		private static final long serialVersionUID = 1L;
		
		String keyString;
		T options;
		
		static class LookupKeyComparator<T extends Comparable<T>> implements Comparator<T> {
			
			@Override
			public int compare(T o1, T o2) {
				return o1 == null ? -1 : (o2 == null ? 1 : o1.compareTo(o2));
			}
		}
		
		LookupKey(String x) {
			this(x, null);
		}
		
		LookupKey(String x, T opts) {
			if(x == null) {
				x = "";
			}
			this.keyString = x;
			this.options = opts;
		}
		
		abstract int compareOptions(T otherOptions);
		
		@Override
		public int compareTo(LookupKey<T> o) {
			int comparison = keyString.compareTo(o.keyString);
			if(comparison == 0) {
				comparison = compareOptions(o.options);
			}
			return comparison;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof LookupKey<?>) {
				LookupKey<?> other = (LookupKey<?>) o;
				return keyString.equals(other.keyString) && Objects.equals(options, other.options);
			}
			return false;
		}
		
		@Override
		public int hashCode() {
//			if(options != null) {
//				int optsHash = options.hashCode();
//				return (optsHash << 5) - optsHash + keyString.hashCode();
//			}
//			return keyString.hashCode();
			int hash = keyString.hashCode(); //not sure which hash is better, seems to be close, but I think this is slightly better
			if(options != null) {
				hash *= options.hashCode();
			}
			return hash;
		}
	}
	

	static class IPAddressStringKey extends LookupKey<IPAddressStringParameters> {
	
		private static final long serialVersionUID = 1L;
		private static final Comparator<IPAddressStringParameters> comparator = new LookupKeyComparator<IPAddressStringParameters>();
		
		
		IPAddressStringKey(String x) {
			this(x, null);
		}
		
		IPAddressStringKey(String x, IPAddressStringParameters opts) {
			super(x, opts);
		}
		
		@Override
		int compareOptions(IPAddressStringParameters otherOptions){
			return Objects.compare(options, otherOptions, comparator);
		}
	}
	
	static class HostKey extends LookupKey<HostNameParameters> {
		
		private static final long serialVersionUID = 1L;
		private static final Comparator<HostNameParameters> comparator = new LookupKeyComparator<HostNameParameters>();
		
		HostKey(String x) {
			this(x, null);
		}
		
		HostKey(String x, HostNameParameters opts) {
			super(x, opts);
		}
		
		@Override
		int compareOptions(HostNameParameters otherOptions){
			return Objects.compare(options, otherOptions, comparator);
		}
	}
	
	static class IPAddressKey implements Comparable<IPAddressKey>, Serializable {
		
		private static final long serialVersionUID = 1L;
		
		byte bytes[];
		
		IPAddressKey(byte bytes[]) {
			this.bytes = bytes;
		}
		
		static int getIPv4Addr(byte addr[]) {
			return addr[3] & 0xFF
        		| ((addr[2] << 8) & 0xFF00)
        		| ((addr[1] << 16) & 0xFF0000)
        		| ((addr[0] << 24) & 0xFF000000);
		}
		
		@Override
		public int compareTo(IPAddressKey o) {
			int comparison = bytes.length - bytes.length;
			if(comparison == 0) {
				if(bytes.length <= 4) {
					comparison = getIPv4Addr(bytes) - getIPv4Addr(o.bytes);
				} else {
					for(int i=0; i<bytes.length; i++) {
						comparison = bytes[i] = o.bytes[i];
						if(comparison != 0) {
							break;
						}
					}
				}
			}
			return comparison;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof IPAddressKey) {
				return Arrays.equals(bytes, ((IPAddressKey) o).bytes);
			}
			return false;
		}
		
		@Override
		public int hashCode() {
			return Arrays.hashCode(bytes);
		}
	}

	void testResolved(String original, String expected) {
		IPAddressString origAddress = createAddress(original);
		IPAddress resolvedAddress = origAddress.isIPAddress() ? origAddress.getAddress() : createHost(original).resolve();
		IPAddressString expectedAddress = createAddress(expected);
		boolean result = (resolvedAddress == null) ? (expected == null) : resolvedAddress.equals(expectedAddress.getAddress());
		if(!result) {
			addFailure(new Failure("resolved was " + resolvedAddress + " original was " + original, origAddress));
		}
		incrementTestCount();
	}
	
	void testCount(String original, int number) {
		IPAddressString w = createAddress(original);
		testCount(w, number);
	}
	
	void testCount(IPAddressString w, int number) {
		IPAddress val = w.getAddress();
		BigInteger count = val.getCount();
		if(!count.equals(BigInteger.valueOf(number))) {
			addFailure(new Failure("count was " + count, w));
		} else {
			Iterator<? extends IPAddress> addrIterator = val.iterator();
			int counter = 0;
			Set<IPAddress> set = new HashSet<IPAddress>();
			IPAddress next = null;
			while(addrIterator.hasNext()) {
				next = addrIterator.next();
				if(counter == 0) {
					if(!next.equals(val.getLowest())) {
						addFailure(new Failure("lowest: " + val.getLowest(), next));
					}
				}
				set.add(next);
				counter++;
			}
			if(set.size() != number || counter != number) {
				addFailure(new Failure("set count was " + set.size() + " instead of expected " + number, w));
			} else {
				if(!next.equals(val.getHighest())) {
					addFailure(new Failure("highest: " + val.getHighest(), next));
				} else {
					if(counter == 1 && !val.getHighest().equals(val.getLowest())) {
						addFailure(new Failure("highest: " + val.getHighest() + " lowest: " + val.getLowest(), next));
					}
				}
			}
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
		IPAddress masked = orig.toSubnet(maskAddr);
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
				params = new IPv6StringOptions.Builder().setCompressOptions(opts).toParams();
			} else {
				params = new IPv6StringOptions.Builder().toParams();
			}
			normalized = val.toNormalizedString(keepMixed, params);
			if(!normalized.equals(expected)) {
				addFailure(new Failure("normalization was " + normalized, w));
			}
		} else if(w.isIPv4()) {
			IPv4Address val = (IPv4Address) w.getAddress();
			normalized = val.toNormalizedString();
			if(!normalized.equals(expected)) {
				addFailure(new Failure("normalization was " + normalized, w));
			}
		} else {
			addFailure(new Failure("normalization failed on " + original, w));
		}
		incrementTestCount();
	}
	
	void testCompressed(String original, String expected) {
		IPAddressString w = createAddress(original);
		String normalized;
		if(w.isIPv6()) {
			IPv6Address val = (IPv6Address) w.getAddress();
			normalized = val.toCompressedString();
		} else if(w.isIPv4()) {
			IPv4Address val = (IPv4Address) w.getAddress();
			normalized = val.toNormalizedString();
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
		String normalized = w.getAddress().toCanonicalString();
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
			normalized = val.toNormalizedString(false, new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(opts).toParams());
			if(!normalized.equals(expectedNoCompression)) {
				addFailure(new Failure("mixed was " + normalized + " expected was " + expectedNoCompression, w));
			}
		}
		incrementTestCount();
	}
	
	void testRadices(String original, String expected, int radix) {
		IPAddressString w = createAddress(original);
		IPAddress val = w.getAddress();
		StringOptions options = new StringOptions.Builder().setRadix(radix).toParams();
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
		boolean oneWay = (evenOdd % 2 == 0);
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
		} catch(IPAddressTypeException e) {
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
				byte[] b3 = addr.isIPv4() ? addr.getSegments().getBytes() : addr.toIPv6().toMappedIPv4Segments().getBytes();
				if(!Arrays.equals(b, b3)) {
					failed = true;
					addFailure(new Failure("bytes on addr " + inetAddress, addr));
					//addr.toMappedIPv4Segments().getBytes();
				}
			}
		} catch(UnknownHostException e) {
			failed = true;
			addFailure(new Failure("bytes on addr " + e, addr));
		}
		return !failed;
	}
	
	void testMaskBytes(String cidr2, IPAddressString w2)
			throws IPAddressStringException {
		int index = cidr2.indexOf('/');
		IPAddressString w3 = createAddress(cidr2.substring(0, index));
		try {
			InetAddress inetAddress = null;
			inetAddress = InetAddress.getByName(w3.toString());//no wildcards allowed here
			byte[] b = inetAddress.getAddress();
			byte[] b2 = w3.toAddress().getBytes();
			if(!Arrays.equals(b, b2)) {
				addFailure(new Failure("bytes on addr " + inetAddress, w3));
			} else {
				byte b3[] = w2.toAddress().getLowestBytes();
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
		}
		incrementTestCount();
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
		} catch(IPAddressStringException e) {
			return expectedPass;
		}
	}
	
	boolean isNotExpectedForPrefix(boolean expectedPass, IPAddressString addr) {
		try {
			addr.validate();
			return !expectedPass;
		} catch(IPAddressStringException e) {
			return expectedPass;
		}
	}
	
	public String convertToMask(IPAddressString str, IPVersion version) throws IPAddressStringException {
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
		} catch(IPAddressStringException e) {
			return expectedPass;
		} catch(IPAddressTypeException e) {
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
		
		IPAddressPart parts[] = ad.getParts(ad.isIPv6() ? IPv6StringBuilderOptions.ALL_OPTS : IPv4StringBuilderOptions.ALL_OPTS);
		if(parts.length != expectedPartCount) {
			addFailure(new Failure("Part count " + parts.length + " does not match expected " + expectedPartCount, ad));
		}
		incrementTestCount();
		
		IPv4StringBuilderOptions convertIPv6Opts = new IPv4StringBuilderOptions(IPv4StringBuilderOptions.IPV6_CONVERSIONS);
		IPv6StringBuilderOptions convertIPv4Opts = new IPv6StringBuilderOptions(IPv6StringBuilderOptions.IPV4_CONVERSIONS);
		if(ad.isIPv4()) {
			IPAddressPart partsConverted[] = ad.getParts(convertIPv6Opts);
			if(partsConverted.length == 0) {
				addFailure(new Failure("converted count does not match expected", ad));
			} else {
				IPv6AddressSection converted = (IPv6AddressSection) partsConverted[0];
				partsConverted = new IPv6Address(converted).getParts(convertIPv4Opts);
				IPv4AddressSection convertedBack = (IPv4AddressSection) partsConverted[0];
				if(!ad.getSegments().equals(convertedBack)) {
					addFailure(new Failure("converted " + convertedBack + " does not match expected", ad));
				}
			}
		} else {
			if(ad.isIPv4Convertible()) {
				IPAddressPart partsConverted[] = ad.getParts(convertIPv4Opts);
				if(partsConverted.length == 0) {
					addFailure(new Failure("converted count does not match expected", ad));
				} else {
					IPv4AddressSection converted = (IPv4AddressSection) partsConverted[0];
					partsConverted = new IPv4Address(converted).getParts(convertIPv6Opts);
					IPv6AddressSection convertedBack = (IPv6AddressSection) partsConverted[0];
					if(!ad.getSegments().equals(convertedBack)) {
						addFailure(new Failure("converted " + convertedBack + " does not match expected", ad));
					}
				}
			} else {
				IPAddressPart partsConverted[] = ad.getParts(convertIPv4Opts);
				if(partsConverted.length > 0) {
					addFailure(new Failure("converted count does not match expected", ad));
				}
			}
		}
		incrementTestCount();
		
		if(fullTest || expectedAll < 100) {
			IPAddressPartStringCollection allCollection = ad.toAllStringCollection();
			IPAddressPart collParts[] = allCollection.getParts(new IPAddressPart[allCollection.getPartCount()]);
			if(!new HashSet<IPAddressPart>(Arrays.asList(parts)).equals(new HashSet<IPAddressPart>(Arrays.asList(collParts)))) {
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
		} else {
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
		Integer maskPrefix = address.getMaskPrefixLength(network);
		Integer otherMaskPrefix = address.getMaskPrefixLength(!network);
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
		boolean val = ((address.getBytes()[0] % 2) == 0);
		if(checkNotMask(address, val)) {
			checkNotMask(address, !val);
		}
	}
	
	boolean secondTry;
	
	private synchronized boolean checkMask(IPAddress address, int prefixBits, boolean network) {
		Integer maskPrefix = address.getMaskPrefixLength(network);
		Integer otherMaskPrefix = address.getMaskPrefixLength(!network);
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
					addressWithNoPrefix = address.toSubnet(address.getNetwork().getNetworkMask(address.getNetworkPrefixLength()));
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
			} catch(IPAddressStringException e) {
				addFailure(new Failure("failed conversion: " + e.getMessage(), address));
				return false;
			} catch(RuntimeException e) {
				addFailure(new Failure("failed conversion: " + e.getMessage(), address));
				return false;
			}
		}
		
		incrementTestCount();
		if(!secondTry) {
			secondTry = true;
			byte bytes[] = address.getLowestBytes();
			IPAddress another = network ? IPAddress.from(bytes, prefixBits) : IPAddress.from(bytes);
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
					IPAddress maskAddress = IPAddress.network(version).getNetworkMask(prefix, false);
					return maskAddress.toNormalizedString();
				} catch(IPAddressTypeException e) {
					//if validation vails, fall through and return mask string
				}
			}
		}
		//Note that here I could normalize the mask to be a full one with an else
		return maskString;
	}
	
	void testMasksAndPrefixes() {
		for(int i=0; i<=128; i++) {
			IPv6AddressNetwork network = IPv6Address.network();
			IPv6Address ipv6HostMask = network.getHostMask(i);
			if(checkMask(ipv6HostMask, i, false)) {
				IPv6Address ipv6NetworkMask = network.getNetworkMask(i);
				if(checkMask(ipv6NetworkMask, i, true)) {
					if(i <= 32) {
						IPv4AddressNetwork ipv4network = IPv4Address.network();
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
	
	void testMasks(String cidr1, String normalizedString) {
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
					addFailure(new Failure("failed " + w2, w2));
				} else {
					testMaskBytes(normalizedString, w2);
				}
			}
		} catch(IPAddressStringException e) {
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
		try {
			IPAddress w = createAddress(cidr1).toAddress();
			IPAddress w2 = createAddress(cidr2).toAddress();
			if(!w.contains(w2) && !conversionContains(w, w2)) {
				addFailure(new Failure("failed " + w2, w));
			} else {
				if(equal ? !(w2.contains(w) || conversionContains(w2, w)) : (w2.contains(w) || conversionContains(w2, w))) {
					addFailure(new Failure("failed " + w, w2));
					if(equal) {
						System.out.println(!(w2.contains(w) || conversionContains(w2, w)));
					} else {
						System.out.println(w2.contains(w) || conversionContains(w2, w));
					}
				}
			}
		} catch(IPAddressStringException e) {
			addFailure(new Failure("failed " + e, new IPAddressString(cidr1)));
		}
		incrementTestCount();
	}
	
	void testNotContains(String cidr1, String cidr2) {
		try {
			IPAddress w = createAddress(cidr1).toAddress();
			IPAddress w2 = createAddress(cidr2).toAddress();
			if(w.contains(w2)) {
				addFailure(new Failure("failed " + w2, w));
			} else if(w2.contains(w)) {
				addFailure(new Failure("failed " + w, w2));
			}
		} catch(IPAddressStringException e) {
			addFailure(new Failure("failed " + e, new IPAddressString(cidr1)));
		}
		incrementTestCount();
	}
	
	void printStrings(IPAddressSection section) {
		String strs[] = section.toStandardStringCollection().toStrings();
		int count = 0;
		System.out.println(section);
		for(String str: strs) {
			System.out.println("\t" + ++count + ": " + str);
		}
		
	}

	void testSplit(String address, int bits, String network, String networkNoRange, String networkWithPrefix, int networkStringCount, String host, int hostStringCount) {
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
				IPAddress maskAddress = section.getNetwork().getNetworkMask(bits);
				IPAddressSection maskSection = maskAddress.getNetworkSection(bits);
				IPAddressSection s = section.toSubnet(maskSection);
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
		incrementTestCount();
	}
	
	private static boolean isSameAllAround(IPAddress supplied, IPAddress internal) {
		return 
				supplied.equals(internal)
				&& internal.equals(supplied)
				&& Objects.equals(internal.getNetworkPrefixLength(), supplied.getNetworkPrefixLength())
				&& internal.getMinPrefix() == supplied.getMinPrefix()
				&& Objects.equals(internal.getEquivalentPrefix(), supplied.getEquivalentPrefix())
				&& internal.getCount().equals(supplied.getCount());
//				&& Arrays.deepEquals(internal.getZeroSegments(), supplied.getZeroSegments())
//				&& Arrays.deepEquals(internal.getZeroRangeSegments(), supplied.getZeroRangeSegments());
	}
	
	void testNetmasks(int prefix, String ipv4NetworkAddress, String ipv4NetworkAddressNoPrefix, String ipv4HostAddress, String ipv6NetworkAddress, String ipv6NetworkAddressNoPrefix, String ipv6HostAddress) {
		IPv6AddressNetwork ipv6network = IPv6Address.network();
		IPv4AddressNetwork ipv4network = IPv4Address.network();
		IPAddressString w2 = createAddress(ipv6NetworkAddress);
		IPAddressString w = createAddress(ipv4NetworkAddress);
		if (prefix <= IPv6Address.BIT_COUNT) {
			IPAddressString w2NoPrefix = createAddress(ipv6NetworkAddressNoPrefix);
			try {
				//these calls should not throw
				IPAddressString.validateNetworkPrefixLength(IPVersion.IPV6, "" + prefix);
				IPv6Address addr6 = ipv6network.getNetworkMask(prefix);
				IPv6Address addr6NoPrefix = ipv6network.getNetworkMask(prefix, false);
				IPAddress w2Value = w2.toAddress();
				IPAddress w2ValueNoPrefix = w2NoPrefix.toAddress();
				boolean one;
				if((one = !isSameAllAround(w2Value, addr6)) || !isSameAllAround(w2ValueNoPrefix, addr6NoPrefix)) {
					addFailure(one ? new Failure("failed " + addr6, w2Value) : new Failure("failed " + addr6NoPrefix, w2ValueNoPrefix));
				} else {
					addr6 = ipv6network.getHostMask(prefix);
					w2 = createAddress(ipv6HostAddress);
					try {
						w2Value = w2.toAddress();
						if(!isSameAllAround(w2Value, addr6)) {
							addFailure(new Failure("failed " + addr6, w2));
						} else if (prefix <= IPv4Address.BIT_COUNT) {
							IPAddressString wNoPrefix = createAddress(ipv4NetworkAddressNoPrefix);
							
							try {
								IPAddressString.validateNetworkPrefixLength(IPVersion.IPV4, "" + prefix);
								IPv4Address addr4 = ipv4network.getNetworkMask(prefix);
								IPv4Address addr4NoPrefix = ipv4network.getNetworkMask(prefix, false);
								IPAddress wValue = w.toAddress();
								IPAddress wValueNoPrefix = wNoPrefix.toAddress();
								if((one = !isSameAllAround(wValue, addr4)) || !isSameAllAround(wValueNoPrefix, addr4NoPrefix)) {
									addFailure(one ? new Failure("failed " + addr4, wValue) : new Failure("failed " + addr4NoPrefix, wValueNoPrefix));
								} else {
									addr4 = ipv4network.getHostMask(prefix);
									w = createAddress(ipv4HostAddress);
									try {
										wValue = w.toAddress();
										if(!isSameAllAround(wValue, addr4)) {
											addFailure(new Failure("failed " + addr4, w));
										} 
									} catch(IPAddressStringException e) {
										addFailure(new Failure("failed " + addr4, w));
									}
								}
							} catch(IPAddressStringException e) {
								addFailure(new Failure("failed prefix val", w));
							} catch(IPAddressTypeException e) {
								addFailure(new Failure("failed prefix val", w));
							}
						} else { //prefix > IPv4Address.BIT_COUNT
							try {
								w.toAddress(); //this should throw
								addFailure(new Failure("succeeded with invalid prefix", w));
							} catch(IPAddressStringException e) {
								try {
									ipv4network.getNetworkMask(prefix);//this should throw
									addFailure(new Failure("succeeded with invalid prefix", new IPAddressString("/" + prefix)));
								} catch(IPAddressTypeException e2) {	
								}
							}
						}
					} catch(IPAddressStringException e) {
						addFailure(new Failure("failed " + addr6, w2));
					}
				}
			} catch(IPAddressStringException e) {
				addFailure(new Failure("failed prefix val", w2));
			} catch(IPAddressTypeException e) {
				addFailure(new Failure("failed prefix val", w2));
			}
		} else {
			try {
				w2.toAddress();
				addFailure(new Failure("succeeded with invalid prefix", w2));
			} catch(IPAddressStringException e) {
				try {
					w.toAddress();
					addFailure(new Failure("succeeded with invalid prefix", w));
				} catch(IPAddressStringException e4) {
					try {
						ipv6network.getNetworkMask(prefix);//this should throw
						addFailure(new Failure("succeeded with invalid prefix", new IPAddressString("/" + prefix)));
					} catch(IPAddressTypeException e2) {
						try {
							ipv4network.getNetworkMask(prefix);//this should throw
							addFailure(new Failure("succeeded with invalid prefix", new IPAddressString("/" + prefix)));
						} catch(IPAddressTypeException e3) {	
						}
					}
				}
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
		} catch(IPAddressStringException e) {
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
		if(matches != h1.equals(h2) && matches != conversionMatches(h1, h2)) {
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
				network = w.getSegments();
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
		} catch(IPAddressStringException e) {
			addFailure(new Failure("failed " + e, new IPAddressString(addr)));
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
			Integer equiv = h1.getEquivalentPrefix();
			if(equiv == null ? (equivPrefix != null) : (!equivPrefix.equals(equiv))) {
				addFailure(new Failure("failed: prefix expected: " + equivPrefix + " prefix got: " + equiv, h1));
			} else {
				IPAddress prefixed = h1.toPrefixedEquivalent();
				String bareHost;
				int index = host.indexOf('/');
				if(index == -1) {
					bareHost = host;
				} else {
					bareHost = host.substring(0, index);
				}
				IPAddressString direct = createAddress(bareHost + '/' + equivPrefix);
				if(equiv == null ? prefixed != null : !direct.getAddress().equals(prefixed)) {
					addFailure(new Failure("failed: prefix expected: " + direct, prefixed));
				} else {
					int minPref = h1.getMinPrefix();
					if(minPref != minPrefix) {
						addFailure(new Failure("failed: prefix expected: " + minPrefix + " prefix got: " + minPref, h1));
					} else {
						IPAddress minPrefixed = h1.toPrefixedMin();
						index = host.indexOf('/');
						if(index == -1) {
							bareHost = host;
						} else {
							bareHost = host.substring(0, index);
						}
						direct = createAddress(bareHost + '/' + minPrefix);
						if(!direct.getAddress().equals(minPrefixed)) {
							addFailure(new Failure("failed: prefix expected: " + direct, minPrefixed));
						}
					}
				}
			}
		} catch(IPAddressStringException e) {
			addFailure(new Failure("failed " + e, str));
		}
		incrementTestCount();
	}
	
	void testSubnet(String addressStr, String maskStr, int prefix, 
			String normalizedPrefixSubnetString,
			String normalizedSubnetString, 
			String normalizedPrefixString) {
		boolean isValidWithPrefix = normalizedPrefixSubnetString != null;
		boolean isValidMask = normalizedSubnetString != null;
		IPAddressString str = createAddress(addressStr);
		IPAddressString maskString = createAddress(maskStr);
		try {
			IPAddress value = str.toAddress();
			try {
				IPAddress mask = maskString.toAddress();
				IPAddress subnet3 = value.toSubnet(prefix);
				String string3 = subnet3.toNormalizedString();
				if(!string3.equals(normalizedPrefixString)) {
					addFailure(new Failure("failed normalizedPrefixString: " + string3 + " expected: " + normalizedPrefixString, subnet3));
				} else {
					try {
						IPAddress subnet = value.toSubnet(mask, prefix);
						if(!isValidWithPrefix) {
							addFailure(new Failure("failed to throw with mask " + mask + " and prefix " + prefix, value));
						} else {
							String string = subnet.toNormalizedString();
							if(!string.equals(normalizedPrefixSubnetString)) {
								addFailure(new Failure("failed: " + string + " expected: " + normalizedPrefixSubnetString, subnet));
							} else {
								try {
									IPAddress subnet2 = value.toSubnet(mask);
									if(!isValidMask) {
										addFailure(new Failure("failed to throw with mask " + mask, value));
									} else {
										String string2 = subnet2.toNormalizedString();
										if(!string2.equals(normalizedSubnetString)) {
											addFailure(new Failure("failed: " + string2 + " expected: " + normalizedSubnetString, subnet2));
										}
									}
								} catch(IPAddressTypeException e) {
									if(isValidMask) {
										addFailure(new Failure("failed with mask " + mask + " " + e, value));
									}
								}
							}
						}
					} catch(IPAddressTypeException e) {
						if(isValidWithPrefix) {
							addFailure(new Failure("failed with mask " + mask + " and prefix " + prefix + ": " + e, value));
						} else {
							try {
								IPAddress subnet2 = value.toSubnet(mask);
								if(!isValidMask) {
									addFailure(new Failure("failed to throw with mask " + mask, value));
								} else {
									String string2 = subnet2.toNormalizedString();
									if(!string2.equals(normalizedSubnetString)) {
										addFailure(new Failure("failed: " + normalizedSubnetString + " expected: " + string2, subnet2));
									}
								}
							} catch(IPAddressTypeException e2) {
								if(isValidMask) {
									addFailure(new Failure("failed with mask " + mask + " " + e2, value));
								}
							}
						}
					}
				} 
			} catch(IPAddressStringException e) {
				addFailure(new Failure("failed " + e, maskString));
			}
		} catch(IPAddressStringException e) {
			addFailure(new Failure("failed " + e, str));
		}
		incrementTestCount();
	}
	
	@Override
	void runTest() {
		testEquivalentPrefix("1.2.3.4", 32);
		testEquivalentPrefix("1.2.3.4/1", 1);
		testEquivalentPrefix("1.2.3.4/15", 15);
		testEquivalentPrefix("1.2.3.4/16", 16);
		testEquivalentPrefix("1.2.3.4/32", 32);
		
		testEquivalentPrefix("1:2::/32", 32);
		testEquivalentPrefix("1:2::/1", 1);
		testEquivalentPrefix("1:2::/31", 31);
		testEquivalentPrefix("1:2::/34", 34);
		testEquivalentPrefix("1:2::/128", 128);
		
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
		testMatches(true, "11.11.0.11/16", "11.720896/16", true);
		testMatches(true, "11.0.0.11/16", "184549376/16", true);
		testMatches(true, "11.0.0.11/16", "0xb000000/16", true);
		testMatches(true, "11.0.0.11/16", "01300000000/16", true);
		
		testMatches(true, "1:2::/32", "1:2::/ffff:ffff::");
		testMatches(true, "1:2::/1", "1:2::/8000::");
		testMatches(true, "1:2::/31", "1:2::/ffff:fffe::");

		testMatches(true, "0.2.3.0", "1.2.3.4/0.255.255.0");
		testMatches(true, "1.2.3.4/16", "1.2.3.4/255.255.0.0");
		testMatches(true, "1.2.3.4/15", "1.2.3.4/255.254.0.0");
		testMatches(true, "1.2.3.4/17", "1.2.3.4/255.255.128.0");

		testMatches(false, "0.2.3.4", "1.2.3.4/0.255.255.0");
		testMatches(false, "1.2.3.0", "1.2.3.4/0.255.255.0");
		testMatches(false, "1.2.3.4", "1.2.3.4/0.255.255.0");
		testMatches(false, "1.1.3.4/16", "1.2.3.4/255.255.0.0");

		testMatches(false, "1.1.3.4/15", "1.2.3.4/255.254.0.0");
		testMatches(false, "1.1.3.4/17", "1.2.3.4/255.255.128.0");

		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:1.2.3.4");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:6:0.0.0.0", "1:2:3:4:5:6::");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/1:2:3:4:5:0:0.0.0.0", "1:2:3:4:5::");
		
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%12", "1:2:3:4:5:6:102:304%12");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%a", "1:2:3:4:5:6:102:304%a");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%", "1:2:3:4:5:6:102:304%");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4%%", "1:2:3:4:5:6:102:304%%"); //we don't validate the zone itself, so the % reappearing as the zone itself is ok
				
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/64", "1:2:3:4::/64");
		
		//more stuff with prefix in mixed part 1:2:3:4:5:6:1.2.3.4/128
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/96", "1:2:3:4:5:6::/96");
		testMatches(true, "1:2:3:4:5:6:255.2.3.4/97", "1:2:3:4:5:6:8000::/97");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/112", "1:2:3:4:5:6:102::/112");
		testMatches(true, "1:2:3:4:5:6:1.2.255.4/115", "1:2:3:4:5:6:102:e000/115");
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/128", "1:2:3:4:5:6:102:304/128");
		
		
		ipv4test(true, "1.2.3.4/255.1.0.0");
		ipv4test(false, "1.2.3.4/1::1");//mask mismatch
		ipv6test(true, "1:2::/1:2::");
		ipv6test(false, "1:2::/1:2::/16");
		ipv6test(false, "1:2::/1.2.3.4");//mask mismatch
		
		//second arg must be the normalized string
		testMasks("9.129.237.26/0", "0.0.0.0/0"); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
		testMasks("9.129.237.26/1", "0.0.0.0/1");
		testMasks("9.129.237.26/4", "0.0.0.0/4");
		testMasks("9.129.237.26/5", "8.0.0.0/5");
		testMasks("9.129.237.26/7", "8.0.0.0/7");
		testMasks("9.129.237.26/8", "9.0.0.0/8");
		testMasks("9.129.237.26/9", "9.128.0.0/9");
		testMasks("9.129.237.26/15", "9.128.0.0/15");
		testMasks("9.129.237.26/16", "9.129.0.0/16");
		testMasks("9.129.237.26/30", "9.129.237.24/30");
		testMasks("9.129.237.26/32", "9.129.237.26/32");
		
		testMasks("ffff::ffff/0", "0:0:0:0:0:0:0:0/0"); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
		testMasks("ffff::ffff/1", "8000:0:0:0:0:0:0:0/1");
		testMasks("ffff::ffff/30", "ffff:0:0:0:0:0:0:0/30");
		testMasks("ffff::ffff/32", "ffff:0:0:0:0:0:0:0/32");
		testMasks("ffff::ffff/126", "ffff:0:0:0:0:0:0:fffc/126");
		testMasks("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff/128");
		//testMasks("ffff::ffff/129", "ffff:0:0:0:0:0:0:ffff/129");
		
		testMasksAndPrefixes();
		
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
		testContains("9.129.237.26/32", "9.129.237.26", true);
		testNotContains("9.129.237.26/32", "9.128.237.26");

		testContains("0.0.0.0/0", "1.2.3.4", false);
		testContains("0.0.0.0/1", "127.2.3.4", false);
		testContains("0.0.0.0/4", "15.2.3.4", false);
		testContains("0.0.0.0/4", "9.129.237.26/16", false);
		testContains("8.0.0.0/5", "15.2.3.4", false);
		testContains("8.0.0.0/7", "9.2.3.4", false);
		testContains("9.0.0.0/8", "9.2.3.4", false);
		testContains("9.128.0.0/9", "9.255.3.0", false);
		testContains("9.128.0.0/15", "9.128.3.4", false);
		testContains("9.129.0.0/16", "9.129.3.4", false);
		testContains("9.129.237.24/30", "9.129.237.27", false);
		testContains("9.129.237.24/30", "9.129.237.27/31", false);
		testContains("9.129.237.26/32", "9.129.237.26", true);

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
		testContains("9.129.237.26/32", "9.129.237.26/32", true);
		
		testContains("::ffff:1.2.3.4", "1.2.3.4", true);//ipv4 mapped
		testContains("::ffff:1.2.3.4/112", "1.2.3.4", false);
		testContains("::ffff:1.2.3.4/112", "1.2.3.4/16", true);

		testContains("ffff::ffff/0", "a:b:c:d:e:f:a:b", false);
		testContains("ffff::ffff/1", "8aaa:b:c:d:e:f:a:b", false);
		testContains("ffff::ffff/30", "ffff:3:c:d:e:f:a:b", false);
		testContains("ffff::ffff/32", "ffff:0:ffff:d:e:f:a:b", false);
		testContains("ffff::ffff/126", "ffff:0:0:0:0:0:0:ffff", false);
		testContains("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff", true);
		
		testContains("0:0:0:0:0:0:0:0/0", "a:b:c:d:e:f:a:b", false);
		testContains("8000:0:0:0:0:0:0:0/1", "8aaa:b:c:d:e:f:a:b", false);
		testNotContains("8000:0:0:0:0:0:0:0/1", "aaa:b:c:d:e:f:a:b");
		testContains("ffff:0:0:0:0:0:0:0/30", "ffff:3:c:d:e:f:a:b", false);
		testNotContains("ffff:0:0:0:0:0:0:0/30", "ffff:4:c:d:e:f:a:b");
		testContains("ffff:0:0:0:0:0:0:0/32", "ffff:0:ffff:d:e:f:a:b", false);
		testNotContains("ffff:0:0:0:0:0:0:0/32", "ffff:1:ffff:d:e:f:a:b");
		testContains("ffff:0:0:0:0:0:0:fffc/126", "ffff:0:0:0:0:0:0:ffff", false);
		testContains("ffff:0:0:0:0:0:0:ffff/128", "ffff:0:0:0:0:0:0:ffff", true);
		
		testContains("ffff::ffff/0", "0:0:0:0:0:0:0:0/0", true);
		testContains("ffff::ffff/1", "8000:0:0:0:0:0:0:0/1", true);
		testContains("ffff::ffff/30", "ffff:0:0:0:0:0:0:0/30", true);
		testContains("ffff::ffff/32", "ffff:0:0:0:0:0:0:0/32", true);
		testContains("ffff::ffff/126", "ffff:0:0:0:0:0:0:fffc/126", true);
		testContains("ffff::ffff/128", "ffff:0:0:0:0:0:0:ffff/128", true);
		
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
		
		testSubnet("1.2.3.4", "0.0.255.255", 16 /* mask is valid with prefix */, "0.0.0.0/16" /* mask is valid alone */, "0.0.3.4", "1.2.0.0/16" /* prefix alone */);
		testSubnet("1.2.3.4", "0.0.255.255", 17, "0.0.0.0/17" , "0.0.3.4", "1.2.0.0/17");
		testSubnet("1.2.128.4", "0.0.255.255", 17, "0.0.128.0/17" , "0.0.128.4", "1.2.128.0/17");
		testSubnet("1.2.3.4", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.3.4", "1.2.0.0/15");
		testSubnet("1.1.3.4", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.3.4", "1.0.0.0/15");
		testSubnet("1.2.128.4", "0.0.255.255", 15, "0.0.0.0/15" , "0.0.128.4", "1.2.0.0/15");
		
		testSubnet("1.2.3.4/15", "0.0.255.255", 16, "0.0.0.0/16", "0.0.*.*", "1.2.0.0/15");//second to last is 0.0.0.0/15 and I don't know why. we are applying the mask only.  I can see how the range becomes /16 but why the string look ike that?
		testSubnet("1.2.3.4/15", "0.0.255.255", 17, "0.0.*.0/17" , "0.0.*.*", "1.2.0.0/15");
		testSubnet("1.2.128.4/15", "0.0.255.255", 17, "0.0.*.0/17" , "0.0.*.*", "1.2.0.0/15");
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
		testSubnet("1.2.128.4/16", "255.255.128.0", 17, "1.2.*.0/17" , null, "1.2.0.0/16");
		testSubnet("1.2.3.4/16", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
		testSubnet("1.1.3.4/16", "255.255.0.0", 15, "1.0.0.0/15" , "1.1.0.0", "1.0.0.0/15");
		testSubnet("1.2.128.4/16", "255.255.0.0", 15, "1.2.0.0/15" , "1.2.0.0", "1.2.0.0/15");
		
		testSubnet("1.2.3.4/15", "255.255.0.0", 16, "1.2-3.0.0/16", "1.2-3.0.0", "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.255.0.0", 17, "1.2-3.0.0/17" , "1.2-3.0.0", "1.2.0.0/15");
		testSubnet("1.2.128.4/15", "255.255.0.0", 17, "1.2-3.0.0/17" , "1.2-3.0.0", "1.2.0.0/15");
		testSubnet("1.2.128.4/15", "255.255.128.0", 17, "1.2-3.*.0/17", null, "1.2.0.0/15");
		testSubnet("1.2.128.4/15", "255.255.128.0", 18, null, null, "1.2.0.0/15");
		testSubnet("1.2.128.4/15", "255.255.192.0", 18, "1.2-3.*.0/18", null, "1.2.0.0/15");
		
		testSubnet("1.2.3.4/12", "255.254.0.0", 16, null, null, "1.0.0.0/12");
		testSubnet("1.2.3.4/12", "255.243.0.255", 16, "1.0-3.0.0/16", "1.0-3.0.*", "1.0.0.0/12");
		testSubnet("1.2.3.4/12", "255.255.0.0", 16, "1.0-15.0.0/16", "1.0-15.0.0", "1.0.0.0/12");
		testSubnet("1.2.3.4/12", "255.240.0.0", 16, "1.0.0.0/16", "1.0.0.0", "1.0.0.0/12");
		testSubnet("1.2.3.4/12", "255.248.0.0", 13, IPAddressSegment.ADJUST_RANGES_BY_PREFIX ? "1.0-8.0.0/13" : "1.0-15.0.0/13", null, "1.0.0.0/12");
		
		testSubnet("1.2.128.4/15", "255.254.128.0", 17, "1.2.*.0/17", null, "1.2.0.0/15");
		testSubnet("1.2.128.4/15", "255.252.128.0", 17, "1.0.*.0/17", null, "1.2.0.0/15");
		testSubnet("1.2.128.4/15", "255.252.128.0", 18, null, null, "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.255.127.0", 15, "1.2.0.0/15", "1.2-3.0-127.0", "1.2.0.0/15");
		testSubnet("1.1.3.4/15", "255.255.0.0", 15, "1.0.0.0/15" , "1.0-1.0.0", "1.0.0.0/15");
		testSubnet("1.2.128.4/15", "255.255.0.255", 15, "1.2.0.0/15" , "1.2-3.0.*", "1.2.0.0/15");
		
		testSubnet("1.2.3.4", "255.254.255.255", 15, "1.2.0.0/15", "1.2.3.4", "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.254.255.255", 15, "1.2.0.0/15", "1.2.*.*", "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.255.254.255", 15, "1.2.0.0/15", null, "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.254.0.255", 15, "1.2.0.0/15", "1.2.0.*", "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.255.254.255", 16, "1.2-3.0.0/16", null, "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.255.254.255", 23, "1.2-3.*.0/23", null, "1.2.0.0/15"); 
		testSubnet("1.2.3.4/23", "255.255.254.255", 23, "1.2.2.0/23", "1.2.2.*", "1.2.2.0/23");
		testSubnet("1.2.3.4/23", "255.255.254.255", 15, "1.2.0.0/15", "1.2.2.*", "1.2.0.0/15");
		testSubnet("1.2.3.4/15", "255.255.254.255", 24, null, null, "1.2.0.0/15");
		testSubnet("1.2.3.4/17", "255.255.255.255", 15, "1.2.0.0/15", "1.2.0-127.*", "1.2.0.0/15");
		testSubnet("1.2.3.4/17", "255.255.254.255", 24, null, null, "1.2.0.0/17");
		testSubnet("1.2.3.4/17", "255.255.254.255", 23, IPAddressSegment.ADJUST_RANGES_BY_PREFIX ? "1.2.0-126.0/23" : "1.2.0-127.0/23", null, "1.2.0.0/17");
		testSubnet("1.2.3.4/17", "255.255.254.255", 22, IPAddressSegment.ADJUST_RANGES_BY_PREFIX ? "1.2.0-124.0/22" : "1.2.0-127.0/22", null, "1.2.0.0/17");
		
		testSubnet("::/8", "ffff::", 128, "0-ff:0:0:0:0:0:0:0/128", "0-ff:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:0/8");
		testSubnet("::/8", "fff0::", 128, null, null, "0:0:0:0:0:0:0:0/8");
		testSubnet("::/8", "fff0::", 12, IPAddressSegment.ADJUST_RANGES_BY_PREFIX ? "0-f0:0:0:0:0:0:0:0/12" : "0-ff:0:0:0:0:0:0:0/12", null, "0:0:0:0:0:0:0:0/8");

		testSplit("9.129.237.26", 0, "", "", "", 1, "9.129.237.26", 2); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
//		testSplit("9.129.237.26", 1, "0.0.0.0", 1");
//		testSplit("9.129.237.26", 4, "0.0.0.0", 4");
//		testSplit("9.129.237.26", 5, "8.0.0.0", 5");
//		testSplit("9.129.237.26", 7, "8.0.0.0", 7");
		testSplit("9.129.237.26", 8, "9", "9", "9/8", 2, "129.237.26", 2);
//		testSplit("9.129.237.26", 9, "9.128.0.0", 9");
//		testSplit("9.129.237.26", 15, "9.128.0.0", 15");
		testSplit("9.129.237.26", 16, "9.129", "9.129", "9.129/16", 2, "237.26", 2);
//		testSplit("9.129.237.26", 30, "9.129.237.24", 30");
		testSplit("9.129.237.26", 31, "9.129.237.26-27", "9.129.237.26", "9.129.237.26/31", 2, "0", 2);
		testSplit("9.129.237.26", 32, "9.129.237.26", "9.129.237.26", "9.129.237.26/32", 2, "", 1);
		
		testSplit("1.2.3.4", 4, "0-15", "0", "0/4", 2, "1.2.3.4", 2);
		testSplit("255.2.3.4", 4, "240-255", "240", "240/4", 1, "15.2.3.4", 2);
		
		
		testSplit("9:129::237:26", 0, "", "", "", 1, "9:129:0:0:0:0:237:26", 12); //compare the two for equality.  compare the bytes of the second one with the bytes of the second one having no mask.
//		testSplit("9.129.237.26", 1, "0.0.0.0", 1");
//		testSplit("9.129.237.26", 4, "0.0.0.0", 4");
//		testSplit("9.129.237.26", 5, "8.0.0.0", 5");
//		testSplit("9.129.237.26", 7, "8.0.0.0", 7");
		//testSplit("9:129::237:26", 8, "9", "129:0:0:0:0:237:26");
//		testSplit("9.129.237.26", 9, "9.128.0.0", 9");
//		testSplit("9.129.237.26", 15, "9.128.0.0", 15");
		testSplit("9:129::237:26", 16, "9", "9", "9/16", 2, "129:0:0:0:0:237:26", 12);
		testSplit("9:129::237:26", 31, "9:128-129", "9:128", "9:128/31", 2, "1:0:0:0:0:237:26", 12);
		
		testSplit("9:129::237:26", 32, "9:129", "9:129", "9:129/32", 2, "0:0:0:0:237:26", 10);
		testSplit("9:129::237:26", 33, "9:129:0-7fff", "9:129:0", "9:129:0/33", 2, "0:0:0:0:237:26", 10);
		testSplit("9:129::237:26", 63, "9:129:0:0-1", "9:129:0:0", "9:129:0:0/63", 4, "0:0:0:237:26", 10);
		testSplit("9:129::237:26", 64, "9:129:0:0", "9:129:0:0", "9:129:0:0/64", 4, "0:0:237:26", 10);
		testSplit("9:129::237:26", 96, "9:129:0:0:0:0", "9:129:0:0:0:0", "9:129:0:0:0:0/96", 4, "237:26", 4);
		testSplit("9:129::237:26", 111, "9:129:0:0:0:0:236-237", "9:129:0:0:0:0:236", "9:129:0:0:0:0:236/111", 12, "1:26", 4);
		testSplit("9:129::237:26", 112, "9:129:0:0:0:0:237", "9:129:0:0:0:0:237", "9:129:0:0:0:0:237/112", 12, "26", 4);
		testSplit("9:129::237:26", 113, "9:129:0:0:0:0:237:0-7fff", "9:129:0:0:0:0:237:0", "9:129:0:0:0:0:237:0/113", 12, "26", 4);
		testSplit("9:129::237:ffff", 113, "9:129:0:0:0:0:237:8000-ffff", "9:129:0:0:0:0:237:8000", "9:129:0:0:0:0:237:8000/113", 12, "7fff", 3);
		testSplit("9:129::237:26", 127, "9:129:0:0:0:0:237:26-27", "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26/127", 12, "0", 5); //previously when splitting host we would have just one ipv4 segment, but now we have two ipv4 segments
		testSplit("9:129::237:26", 128, "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26", "9:129:0:0:0:0:237:26/128", 12, "", 1);
		
		int USE_UPPERCASE = 2;
		
		testSplit("a:b:c:d:e:f:a:b", 4, "0-fff", "0", "0/4", 2, "a:b:c:d:e:f:a:b", 6 * USE_UPPERCASE);
		testSplit("ffff:b:c:d:e:f:a:b", 4, "f000-ffff", "f000", "f000/4", 1 * USE_UPPERCASE, "fff:b:c:d:e:f:a:b", 6 * USE_UPPERCASE);
		testSplit("ffff:b:c:d:e:f:a:b", 2, "c000-ffff", "c000", "c000/2", 1 * USE_UPPERCASE, "3fff:b:c:d:e:f:a:b", 6 * USE_UPPERCASE);
		
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
		testVariantCounts("::1", 2, 2, IPv6Address.getStandardLoopbackStrings().length, 1298);//this confirms that IPv6Address.getStandardLoopbackStrings() is being initialized properly
		testVariantCounts("::ffff:1.2.3.4", 6, 4, 20, 1409, 1320);//ipv4 mapped
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
		testVariantCounts("1.2.3.4", 6, 1, 2, 419, 89, 16);
		testVariantCounts("0.0.0.0", 6, 1, 2, 484, 90, 16);
		testVariantCounts("1111:2222:aaaa:4444:5555:6666:7070:700a", 2,  1 * USE_UPPERCASE, 1 * USE_UPPERCASE + 2 * USE_UPPERCASE, 1 * USE_UPPERCASE + 2 * USE_UPPERCASE);//this one can be capitalized when mixed 
		testVariantCounts("1111:2222:3333:4444:5555:6666:7070:700a", 2, 2, 1 * USE_UPPERCASE + 2, 1 * USE_UPPERCASE + 2);//this one can only be capitalized when not mixed, so the 2 mixed cases are not doubled
		
		
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
		
		ipv4test(false, ""); //this needs special validation options to be valid
		
		ipv4test(true, "1.2.3.4");
		ipv4test(false, "[1.2.3.4]");//only ipv6 can be in the square brackets
		
		ipv4test(!true, "a");
		
		ipv4test(!true, "1.2.3");
		
		ipv4test(!true, "a.2.3.4");
		ipv4test(!true, "1.a.3.4");
		ipv4test(!true, "1.2.a.4");
		ipv4test(!true, "1.2.3.a");
		
		ipv4test(!true, ".2.3.4");
		ipv4test(!true, "1..3.4");
		ipv4test(!true, "1.2..4");
		ipv4test(!true, "1.2.3.");
		
		ipv4test(!true, "256.2.3.4");
		ipv4test(!true, "1.256.3.4");
		ipv4test(!true, "1.2.256.4");
		ipv4test(!true, "1.2.3.256");
		
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
		
		ipv4test(!true, "0000.0.0.0");
		ipv4test(!true, "0.0000.0.0");
		ipv4test(!true, "0.0.0000.0");
		ipv4test(!true, "0.0.0.0000");
		
		ipv4test(!true, ".0.0.0");
		ipv4test(!true, "0..0.0");
		ipv4test(!true, "0.0..0");
		ipv4test(!true, "0.0.0.");
		
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
		
		ipv6test(false, "1:00x:3:4:5:6:7:8");
		ipv6test(false, "1:0xx:3:4:5:6:7:8");
		ipv6test(false, "1:xx:3:4:5:6:7:8");
		ipv6test(false, "1:0x4x:3:4:5:6:7:8");
		ipv6test(false, "1:x4:3:4:5:6:7:8");
		
		ipv4testOnly(!true, "1:2:3:4:5:6:7:8");
		ipv4testOnly(!true, "::1");
		
		ipv6test(0, ""); // empty string //this needs special validation options to be valid
		
		ipv6test(1, "/0");
		ipv6test(1, "/1");
		ipv6test(1, "/127");
		ipv6test(1, "/128");
		ipv6test(0, "/129");
		
		ipv6test(1, "::/0"); //toAddress() should work on this
		ipv6test(0, ":1.2.3.4"); //invalid
		ipv6test(1, "::1.2.3.4"); //toAddress() should work on this
		
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
		ipv6test(0,"02001:0000:1234:0000:0000:C1C0:ABCD:0876"); // extra 0 not allowed!
		ipv6test(0,"2001:0000:1234:0000:00001:C1C0:ABCD:0876"); // extra 0 not allowed!
		//ipv6test(1," 2001:0000:1234:0000:0000:C1C0:ABCD:0876"); // leading space
		//ipv6test(1,"2001:0000:1234:0000:0000:C1C0:ABCD:0876 "); // trailing space
		//ipv6test(1," 2001:0000:1234:0000:0000:C1C0:ABCD:0876  "); // leading and trailing space
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
		ipv6test(0,"::ffff:2.3.4");
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
		ipv6test(1,"fe80:0000:0000:0000:0204:61ff:254.157.241.086");
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
		
		ipv6test(0,"123");
		ipv6test(0,"ldkfj");
		ipv6test(0,"2001::FFD3::57ab");
		ipv6test(0,"2001:db8:85a3::8a2e:37023:7334");
		ipv6test(0,"2001:db8:85a3::8a2e:370k:7334");
		ipv6test(0,"1:2:3:4:5:6:7:8:9");
		ipv6test(0,"1::2::3");
		ipv6test(0,"1:::3:4:5");
		ipv6test(0,"1:2:3::4:5:6:7:8:9");
		
		// New from Aeron
		ipv6test(1,"1111:2222:3333:4444:5555:6666:7777:8888");
		ipv6test(1,"1111:2222:3333:4444:5555:6666:7777::");
		ipv6test(1,"1111:2222:3333:4444:5555:6666::");
		ipv6test(1,"1111:2222:3333:4444:5555::");
		ipv6test(1,"1111:2222:3333:4444::");
		ipv6test(1,"1111:2222:3333::");
		ipv6test(1,"1111:2222::");
		ipv6test(1,"1111::");
		// ipv6test(1,"::");     //duplicate
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
		ipv6test(0,"1111");
		
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

		testSQLMatching();
	}
}

interface AddressCreator {
	HostName createHost(HostKey key);
	
	IPAddressString createAddress(IPAddressStringKey key);
	
	IPAddress createAddress(byte bytes[]);
}
