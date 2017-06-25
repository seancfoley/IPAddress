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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;
import java.util.function.Function;

import inet.ipaddr.Address;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.AddressTypeException;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressNetwork.HostIdentifierStringCache;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection.CompressOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.test.MACAddressTest.MACAddressStringKey;
import inet.ipaddr.test.TestBase.HostKey;
import inet.ipaddr.test.TestBase.IPAddressStringKey;

public abstract class TestBase {
	
	static class Failure {
		HostIdentifierString addr;
		Address addrValue;
		AddressSegmentSeries series;
		String str;
		StackTraceElement[] stack;
		Class<? extends TestBase> testClass;
		
		Failure(String str) {
			this.str = str;
		}
		
		Failure(boolean pass, HostIdentifierString addr) {
			this.addr = addr;
		}
		
		Failure(String str, AddressSegmentSeries addr) {
			this.str = str;
			this.series = addr;
		}

		Failure(boolean pass, Address addr) {
			this.addrValue = addr;
		}
		
		Failure(String str, HostIdentifierString addr) {
			this.str = str;
			this.addr = addr;
		}
		
		Failure(String str, Address addr) {
			this.str = str;
			this.addrValue = addr;
		}
		
		String getObjectDescriptor() {
			if(addr != null) {
				return addr.toString();
			}
			if(addrValue != null) {
				return addrValue.toString();
			}
			if(series != null) {
				return series.toString();
			}
			return "<unknown>";
		}
		
		@Override
		public String toString() {
			if(str == null) {
				return getObjectDescriptor();
			}
			return str + " " + getObjectDescriptor();
		}
	}
	
	static class Failures {
		ArrayList<Failure> failures = new ArrayList<Failure>();
		int numTested;
		
		void addFailure(Failure failure, Class<? extends TestBase> testClass) {
			failures.add(failure);
			failure.stack = new Throwable().getStackTrace();
			failure.testClass = testClass;
		}
		
		void incrementTestCount() {
			numTested++;
		}
		
		synchronized void add(Failures fails) {
			numTested += fails.numTested;
			failures.addAll(fails.failures);
		}
		
		void report() {
			String failurestr = "";
			int failurestrCount = 0;
			
			for(Failure f : failures) {
				String addrStrng = f.getObjectDescriptor(); 	
				failurestr += ' ';
				if(f.str != null && f.str.length() > 0) {
					failurestr += f.str;
					failurestr += ", ";
				}
				failurestr += addrStrng;
				failurestrCount++;
			}
			
			int numFailed = failures.size();
			showMessage("test count: " + numTested);
			showMessage("fail count: " + numFailed);
			if(failurestrCount > 0) {
				showMessage("Failed:\n" + failurestr);
			}
			
		}
	}
	
	static class Perf {
		ArrayList<Long> runTimes = new ArrayList<Long>();
		
		void addTime(long time) {
			runTimes.add(time);
		}
		
		void report() {
			if(runTimes.isEmpty()) {
				return;
			}
			String str = "";
			int count = 0;
			for(Long time : runTimes) {
				//str += "" + ++count + ". " + time + " milliseconds" + System.lineSeparator();
				str += "" + ++count + ". " + (time / 1000000) + " milliseconds" + System.lineSeparator();
			}
			showMessage("times:" + System.lineSeparator() + str);
		}
	}
	
	static void showMessage(String s) {
		System.out.println(s);
	}
	
	static abstract class LookupKey<T extends Comparable<T>> implements Comparable<LookupKey<T>>, Serializable {
		
		private static final long serialVersionUID = 3L;
		
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
			int hash = keyString.hashCode(); //not sure which hash is better, seems to be close, but I think this is slightly better
			if(options != null) {
				hash *= options.hashCode();
			}
			return hash;
		}
	}
	

	static class IPAddressStringKey extends LookupKey<IPAddressStringParameters> {
	
		private static final long serialVersionUID = 3L;
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
		
		private static final long serialVersionUID = 3L;
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
		
		private static final long serialVersionUID = 3L;
		
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
	
	protected static final HostNameParameters HOST_OPTIONS = new HostNameParameters.Builder().
			allowEmpty(false).
			setEmptyAsLoopback(false).
			setNormalizeToLowercase(true).
			allowBracketedIPv6(true).
			allowBracketedIPv4(true).getAddressOptionsBuilder().
				allowPrefix(true).
				allowMask(true).
				setRangeOptions(RangeParameters.NO_RANGE).
				allow_inet_aton(false).
				allowEmpty(false).
				setEmptyAsLoopback(false).
				allowAll(false).
				allowPrefixOnly(true).
				allowSingleSegment(false).
				getIPv4AddressParametersBuilder().
						allowLeadingZeros(true).
						allowUnlimitedLeadingZeros(false).
						allowPrefixLengthLeadingZeros(true).
						allowPrefixesBeyondAddressSize(false).
						allowWildcardedSeparator(false).
						//allowWildcardedSeparator(true).
						getParentBuilder().
				getIPv6AddressParametersBuilder().
						allowLeadingZeros(true).
						allowUnlimitedLeadingZeros(false).
						allowPrefixLengthLeadingZeros(true).
						allowPrefixesBeyondAddressSize(false).
						//allowWildcardedSeparator(true).
						allowWildcardedSeparator(false).
						allowMixed(true).
						allowZone(true).
						getParentBuilder().getParentBuilder().toParams();
	
	protected static final IPAddressStringParameters ADDRESS_OPTIONS = HOST_OPTIONS.toAddressOptionsBuilder().toParams();
	
	protected static final MACAddressStringParameters MAC_ADDRESS_OPTIONS = new MACAddressStringParameters.Builder().
			allowEmpty(false).
			allowAll(false).
			//allowSingleSegment(false).
			getFormatBuilder().
				setRangeOptions(RangeParameters.NO_RANGE).
				allowLeadingZeros(true).
				allowUnlimitedLeadingZeros(false).
				allowWildcardedSeparator(false).
				allowShortSegments(true).
			getParentBuilder().
			toParams();

	protected static final HostNameParameters HOST_INET_ATON_WILDCARD_AND_RANGE_OPTIONS = new HostNameParameters.Builder().
			allowEmpty(false).
			setEmptyAsLoopback(false).
			setNormalizeToLowercase(true).
			allowBracketedIPv6(true).
			allowBracketedIPv4(true).getAddressOptionsBuilder().
				allowPrefix(true).
				allowMask(true).
				setRangeOptions(RangeParameters.WILDCARD_AND_RANGE).
				allow_inet_aton(true).
				allowEmpty(false).
				setEmptyAsLoopback(false).
				allowAll(false).
				allowPrefixOnly(false).
				getIPv4AddressParametersBuilder().
						allowPrefixLengthLeadingZeros(true).
						allowPrefixesBeyondAddressSize(false).
						allowWildcardedSeparator(true).
						getParentBuilder().getParentBuilder().toParams();
	
	protected static final IPAddressStringParameters INET_ATON_WILDCARD_AND_RANGE_OPTIONS = HOST_INET_ATON_WILDCARD_AND_RANGE_OPTIONS.toAddressOptionsBuilder().toParams();
			
	protected static final HostNameParameters HOST_INET_ATON_OPTIONS = HOST_OPTIONS.toBuilder().getAddressOptionsBuilder().
			allow_inet_aton(true).allowSingleSegment(true).getParentBuilder().toParams();

	boolean fullTest = false;
	final Failures failures = new Failures();
	final Perf perf = new Perf();
	private final AddressCreator addressCreator;
	
	TestBase(AddressCreator creator) {
		this.addressCreator = creator;
	}

	protected HostName createHost(HostKey key) {
		return addressCreator.createHost(key);
	}
	
	protected IPAddressString createAddress(IPAddressStringKey key) {
		return addressCreator.createAddress(key);
	}
	
	protected MACAddressString createMACAddress(MACAddressStringKey key) {
		return addressCreator.createMACAddress(key);
	}

	protected IPAddress createAddress(byte bytes[]) {
		return addressCreator.createAddress(bytes);
	}
	
	protected IPv4Address createAddress(int val) {
		return addressCreator.createAddress(val);
	}
	
	protected MACAddress createMACAddress(byte bytes[]) {
		return addressCreator.createMACAddress(bytes);
	}
	
	protected MACAddress createMACAddress(long val, boolean extended) {
		return addressCreator.createMACAddress(val, extended);
	}

	protected HostName createHost_inet_aton(String x) {
		return createHost(new HostKey(x, HOST_INET_ATON_OPTIONS));
	}
	
	protected HostName createHost(String x) {
		return createHost(new HostKey(x, HOST_OPTIONS));
	}
	
	protected HostName createHost(String x, HostNameParameters options) {
		return createHost(new HostKey(x, options));
	}
	
	protected IPAddressString createInetAtonAddress(String x) {
		return createAddress(x, INET_ATON_WILDCARD_AND_RANGE_OPTIONS);
	}
	
	protected IPAddressString createAddress(String x, IPAddressStringParameters opts) {
		IPAddressStringKey key = new IPAddressStringKey(x, opts);
		return createAddress(key);
	}

	protected IPAddressString createAddress(String x) {
		return createAddress(new IPAddressStringKey(x, ADDRESS_OPTIONS));
	}
	
	protected MACAddressString createMACAddress(String x, MACAddressStringParameters opts) {
		MACAddressStringKey key = new MACAddressStringKey(x, opts);
		return createMACAddress(key);
	}
	
	protected MACAddressString createMACAddress(String x) {
		return createMACAddress(new MACAddressStringKey(x, MAC_ADDRESS_OPTIONS));
	}
	
	void addFailure(Failure failure) {
		failures.addFailure(failure, getClass());
	}
	
	void incrementTestCount() {
		failures.incrementTestCount();
	}
	
	void report() {
		showMessage(getClass().getSimpleName());
		perf.report();
		failures.report();
		showMessage("Done: " + getClass().getSimpleName() + "\n");
	}
	
	abstract void runTest();
	
	void testPrefixes(AddressSegmentSeries original, 
			int prefix, int adjustment, 
			AddressSegmentSeries next,
			AddressSegmentSeries previous,
			AddressSegmentSeries adjusted,
			AddressSegmentSeries prefixSet,
			AddressSegmentSeries prefixApplied) {
		AddressSegmentSeries removed = original.removePrefixLength();
		if(original.isPrefixed()) {
			int prefLength = original.getPrefixLength();
			int bitsSoFar = 0;
			for(int i = 0; i < removed.getSegmentCount(); i++) {
				int prevBitsSoFar = bitsSoFar;
				AddressSegment seg = removed.getSegment(i);
				bitsSoFar += seg.getBitCount();
				if(prefLength >= bitsSoFar) {
					if(!seg.equals(original.getSegment(i))) {
						addFailure(new Failure("removed prefix: " + removed, original));
						break;
					}
				} else if(prefLength <= prevBitsSoFar) {
					if(!seg.isZero()) {
						addFailure(new Failure("removed prefix all: " + removed, original));
						break;
					}
				} else {
					int segPrefix = prefLength - prevBitsSoFar;
					int mask = ~0 << (seg.getBitCount() - segPrefix);
					int lower = seg.getLowerSegmentValue();
					int upper = seg.getUpperSegmentValue();
					if((lower & mask) != lower || (upper & mask) != upper) {
						addFailure(new Failure("prefix app: " + removed, original));
						break;
					}
				}
			}
		} else if(!removed.equals(original)) {
			addFailure(new Failure("prefix removed: " + removed, original));
		}
		if(!original.adjustPrefixBySegment(true).equals(next)) {
			addFailure(new Failure("prefix next: " + original.adjustPrefixBySegment(true), next));
		} else if(!original.adjustPrefixBySegment(false).equals(previous)) {
			addFailure(new Failure("prefix previous: " + original.adjustPrefixBySegment(false), previous));
		} else if(!original.adjustPrefixLength(adjustment).equals(adjusted)) {
			addFailure(new Failure("prefix adjusted: " + original.adjustPrefixLength(adjustment), adjusted));
		} else if(!original.setPrefixLength(prefix).equals(prefixSet)) {
			addFailure(new Failure("prefix set: " + original.setPrefixLength(prefix), prefixSet));
		} else if(!original.applyPrefixLength(prefix).equals(prefixApplied)) {
			addFailure(new Failure("prefix applied: " + original.applyPrefixLength(prefix), prefixApplied));
		}
	}
	
	void testPrefix(AddressSegmentSeries original, Integer prefixLength, int minPrefix, Integer equivalentPrefix) {
		if(!Objects.equals(original.getPrefixLength(), prefixLength)) {
			addFailure(new Failure("prefix: " + original.getPrefixLength() + " expected: " + prefixLength, original));
		} else if(!Objects.equals(original.getMinPrefix(), minPrefix)) {
			addFailure(new Failure("min prefix: " + original.getMinPrefix() + " expected: " + minPrefix, original));
		} else if(!Objects.equals(original.getEquivalentPrefix(), equivalentPrefix)) {
			addFailure(new Failure("equivalent prefix: " + original.getEquivalentPrefix() + " expected: " + equivalentPrefix, original));
		}
	}
	
	void testReverse(AddressSegmentSeries series, boolean bitsReversedIsSame, boolean bitsReversedPerByteIsSame) {
		AddressSegmentSeries segmentsReversed = series.reverseSegments();
		for(int i = 0; i < series.getSegmentCount(); i++) {
			if(!series.getSegment(i).equals(segmentsReversed.getSegment(series.getDivisionCount() - i - 1))) {
				addFailure(new Failure("reversal: " + series, series));
			}
		}
		AddressSegmentSeries bytesReversed = segmentsReversed.reverseBytes().reverseBytesPerSegment();
		if(!series.equals(bytesReversed)) {
			addFailure(new Failure("bytes reversal: " + series, series));
		}
		
		AddressSegmentSeries bitsReversed = series.reverseBits(false);
		if(bitsReversedIsSame ? !series.equals(bitsReversed) : series.equals(bitsReversed)) {
			addFailure(new Failure("bit reversal 2a: " + series, series));
		}
		bitsReversed = bitsReversed.reverseBits(false);
		if(!series.equals(bitsReversed)) {
			addFailure(new Failure("bit reversal 2: " + series, series));
		}
		
		AddressSegmentSeries bitsReversed2 = series.reverseBits(true);
		if(bitsReversedPerByteIsSame ? !series.equals(bitsReversed2) : series.equals(bitsReversed2)) {
			addFailure(new Failure("bit reversal 3a: " + series, series));
		}
		bitsReversed2 = bitsReversed2.reverseBits(true);
		if(!series.equals(bitsReversed2)) {
			addFailure(new Failure("bit reversal 3: " + series, series));
		}
		
		byte bytes[] = series.getBytes();
		AddressSegmentSeries bitsReversed3 = series.reverseBytes().reverseBytesPerSegment();
		for(int i = 0, j = bytes.length - 1; i < bitsReversed3.getSegmentCount(); i++) {
			AddressSegment seg = bitsReversed3.getSegment(i);
			byte segBytes[] = seg.getBytes();
			for(int k = seg.getByteCount() - 1; k >= 0; k--) {
				if(segBytes[k] != bytes[j--]) {
					addFailure(new Failure("reversal 4: " + series, series));
				}
			}
		}
	}
	
	void testIPv6Strings(IPAddressString w, IPAddress ipAddr,  
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
		
		testStrings(w, ipAddr, normalizedString, normalizedWildcardString, canonicalWildcardString, sqlString, fullString, compressedString, canonicalString, subnetString, subnetString, compressedWildcardString, reverseDNSString, uncHostString, singleHex, singleOctal);
		
		//now test some IPv6-only strings
		testIPv6OnlyStrings(w, (IPv6Address) ipAddr, mixedStringNoCompressMixed,
				mixedStringNoCompressHost, mixedStringCompressCoveredHost, mixedString, base85String);
	}

	private void testIPv6OnlyStrings(IPAddressString w, IPv6Address ipAddr,
			String mixedStringNoCompressMixed,
			String mixedStringNoCompressHost,
			String mixedStringCompressCoveredHost,
			String mixedString,
			String base85String) {

		String base85 = ipAddr.toBase85String();
		
		String m = ipAddr.toMixedString();
		
		CompressOptions compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.COVERED_BY_HOST);
		IPv6StringOptions mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toParams();
		String mixedCompressCoveredHost = ipAddr.toNormalizedString(mixedParams);
		
		compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.NO_HOST);
		mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toParams();
		String mixedNoCompressHost = ipAddr.toNormalizedString(mixedParams);
		
		compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.NO);
		mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toParams();
		String mixedNoCompressMixed = ipAddr.toNormalizedString(mixedParams);

		confirmAddrStrings(ipAddr, m, mixedCompressCoveredHost, mixedNoCompressHost, mixedNoCompressMixed, base85);
		
		boolean nMatch = m.equals(mixedString);
		if(!nMatch) {
			addFailure(new Failure("failed expected: " + mixedString + " actual: " + m, w));
		} else {
			boolean mccMatch = mixedCompressCoveredHost.equals(mixedStringCompressCoveredHost);
			if(!mccMatch) {
				addFailure(new Failure("failed expected: " + mixedStringCompressCoveredHost + " actual: " + mixedCompressCoveredHost, w));
			} else {
				boolean msMatch = mixedNoCompressHost.equals(mixedStringNoCompressHost);
				if(!msMatch) {
					addFailure(new Failure("failed expected: " + mixedStringNoCompressHost + " actual: " + mixedNoCompressHost, w));
				} else {
					boolean mncmMatch = mixedNoCompressMixed.equals(mixedStringNoCompressMixed);
					if(!mncmMatch) {
						addFailure(new Failure("failed expected: " + mixedStringNoCompressMixed + " actual: " + mixedNoCompressMixed, w));
					} else {
						boolean b85Match = base85.equals(base85String);
						if(!b85Match) {
							addFailure(new Failure("failed expected: " + base85String + " actual: " + base85, w));
						}
					}
				}
			}
		}
		incrementTestCount();
	}
	
	boolean confirmAddrStrings(MACAddress macAddr, String ...strs) {
		for(String str : strs) {
			MACAddressString addrString = new MACAddressString(str);
			MACAddress addr = addrString.getAddress();
			if(!macAddr.equals(addr)) {
				addFailure(new Failure("failed produced string: " + str, macAddr));
				return false;
			}
		}
		incrementTestCount();
		return true;
	}
	
	private static final IPAddressStringParameters DEFAULT_BASIC_VALIDATION_OPTIONS = new IPAddressStringParameters.Builder().toParams();
	
	boolean confirmAddrStrings(IPAddress ipAddr, String ...strs) {
		for(String str : strs) {
			IPAddressString addrString = createAddress(str, DEFAULT_BASIC_VALIDATION_OPTIONS);
			IPAddress addr = addrString.getAddress();
			if(!ipAddr.equals(addr)) {
				addFailure(new Failure("failed produced string: " + str, ipAddr));
				return false;
			}
		}
		incrementTestCount();
		return true;
	}
	
	boolean confirmAddrStrings(IPAddress ipAddr, IPAddressString ...strs) {
		for(IPAddressString str : strs) {
			IPAddress addr = str.getAddress();
			if(!ipAddr.equals(addr)) {
				addFailure(new Failure("failed produced string: " + str, ipAddr));
				return false;
			}
		}
		incrementTestCount();
		return true;
	}
	
	boolean confirmHostStrings(IPAddress ipAddr, String ...strs) {
		for(String str : strs) {
			HostName hostName = new HostName(str);
			IPAddress a = hostName.getAddress();
			if(!ipAddr.equals(a)) {
				addFailure(new Failure("failed produced string: " + str, ipAddr));
				return false;
			}
			String again = hostName.toNormalizedString();
			hostName = new HostName(again);
			a = hostName.getAddress();
			if(!ipAddr.equals(a)) {
				//System.out.println(ipAddr + " " + str + " " + again + " " + a);
				//new HostName(str).toNormalizedString();
				addFailure(new Failure("failed produced string: " + str, ipAddr));
				return false;
			}
		}
		incrementTestCount();
		return true;
	}
	
	boolean confirmHostStrings(IPAddress ipAddr, HostName ...strs) {
		for(HostName str : strs) {
			IPAddress a = str.getAddress();
			if(!ipAddr.equals(a)) {
				addFailure(new Failure("failed produced string: " + str, ipAddr));
				return false;
			}
			String again = str.toNormalizedString();
			str = new HostName(again);
			a = str.getAddress();
			if(!ipAddr.equals(a)) {
				//System.out.println(ipAddr + " " + str + " " + a);
				addFailure(new Failure("failed produced string: " + str, ipAddr));
				return false;
			}
		}
		incrementTestCount();
		return true;
	}

	void testMACStrings(MACAddressString w,
			MACAddress ipAddr,
			String normalizedString, //toColonDelimitedString
			String compressedString,
			String canonicalString, //toDashedString
			String dottedString,
			String spaceDelimitedString,
			String singleHex) {
		// testing: could test a leading zero split digit non-reverse string - a funky range string with split digits and leading zeros, like 100-299.*.10-19.4-7 which should be 1-2.0-9.0-9.*.*.*.0.1.0-9.0.0.4-7
		String c = ipAddr.toCompressedString();
		String canonical = ipAddr.toCanonicalString();
		String d = ipAddr.toDashedString();
		String n = ipAddr.toNormalizedString();
		String cd = ipAddr.toColonDelimitedString();
		String sd = ipAddr.toSpaceDelimitedString();

		String hex, hexNoPrefix;
		
		try {
			hex = ipAddr.toHexString(true);
			confirmAddrStrings(ipAddr, hex);
		} catch(AddressTypeException | IllegalStateException e) {
			boolean isMatch = singleHex == null;
			if(!isMatch) {
				addFailure(new Failure("failed expected: " + singleHex + " actual: " + e, w));
			}
		}
		try {
			hexNoPrefix = ipAddr.toHexString(false);
			boolean isMatch = singleHex.equals(hexNoPrefix);
			if(!isMatch) {
				addFailure(new Failure("failed expected: " + singleHex + " actual: " + hexNoPrefix, w));
			}
			confirmAddrStrings(ipAddr, hexNoPrefix);//For ipv4, no 0x means decimal
		} catch(AddressTypeException | IllegalStateException e) {
			boolean isMatch = singleHex == null;
			if(!isMatch) {
				addFailure(new Failure("failed expected non-null, actual: " + e, w));
			}
		}
		
		confirmAddrStrings(ipAddr, c, canonical, d, n, cd, sd);
		
		boolean nMatch = normalizedString.equals(n);
		if(!nMatch) {
			addFailure(new Failure("failed expected: " + normalizedString + " actual: " + n, w));
		} else {
			boolean nwMatch = normalizedString.equals(cd);
			if(!nwMatch) {
				addFailure(new Failure("failed expected: " + normalizedString + " actual: " + cd, w));
			}  else {
				boolean cawMatch = spaceDelimitedString.equals(sd);
				if(!cawMatch) {
					addFailure(new Failure("failed expected: " + spaceDelimitedString + " actual: " + sd, w));
				} else {
					boolean cMatch = compressedString.equals(c);
					if(!cMatch) {
						addFailure(new Failure("failed expected: " + compressedString + " actual: " + c, w));
					} else {
						boolean sMatch;
						String dotted = null;
						try {
							dotted = ipAddr.toDottedString();
							confirmAddrStrings(ipAddr, dotted);
							sMatch = dotted.equals(dottedString);
						} catch(AddressTypeException e) {
							sMatch = (dottedString == null);
						}
						if(!sMatch) {
							addFailure(new Failure("failed expected: " + dottedString + " actual: " + dotted, w));
						} else {
							boolean dashedMatch = canonicalString.equals(d);
							if(!dashedMatch) {
								addFailure(new Failure("failed expected: " + canonicalString + " actual: " + d, w));
							} else {
								boolean canonicalMatch = canonicalString.equals(canonical);
								if(!canonicalMatch) {
									addFailure(new Failure("failed expected: " + canonicalString + " actual: " + canonical, w));
								}
							}
						}
					}
				}
			}
		}
		incrementTestCount();
	}
	
	void testHostAddress(String addressStr) {
		IPAddressString str = createAddress(addressStr);
		IPAddress address = str.getAddress();
		if(address != null) {
			IPAddress hostAddress = str.getHostAddress();
			int prefixIndex = addressStr.indexOf(IPAddress.PREFIX_LEN_SEPARATOR);
			if(prefixIndex < 0) {
				if(!address.equals(hostAddress) || !address.contains(hostAddress)) {
					addFailure(new Failure("failed host address with no prefix: " + hostAddress + " expected: " + address, str));
				}
			} else {
				String substr = addressStr.substring(0, prefixIndex);
				IPAddressString str2 = createAddress(substr);
				IPAddress address2 = str2.getAddress();
				if(!address2.equals(hostAddress)) {
					addFailure(new Failure("failed host address: " + hostAddress + " expected: " + address2, str));
				}
			}
		}
	}

	void testStrings(IPAddressString w,
			IPAddress ipAddr,
			String normalizedString,
			String normalizedWildcardString,
			String canonicalWildcardString,
			String sqlString,
			String fullString,
			String compressedString,
			String canonicalString,
			String subnetString,
			String cidrString,
			String compressedWildcardString,
			String reverseDNSString,
			String uncHostString,
			String singleHex,
			String singleOctal) {
		// testing: could test a leading zero split digit non-reverse string - a funky range string with split digits and leading zeros, like 100-299.*.10-19.4-7 which should be 1-2.0-9.0-9.*.*.*.0.1.0-9.0.0.4-7
		testHostAddress(w.toString());
		
		String c = ipAddr.toCompressedString();
		String canonical = ipAddr.toCanonicalString();
		String s = ipAddr.toSubnetString();
		String cidr = ipAddr.toPrefixLengthString();
		String n = ipAddr.toNormalizedString();
		String nw = ipAddr.toNormalizedWildcardString();
		String caw = ipAddr.toCanonicalWildcardString();
		String cw = ipAddr.toCompressedWildcardString();
		String sql = ipAddr.toSQLWildcardString();
		String full = ipAddr.toFullString();
		String rDNS = ipAddr.toReverseDNSLookupString();
		String unc = ipAddr.toUNCHostName();
		
		String hex, hexNoPrefix, octal;
		
		try {
			hex = ipAddr.toHexString(true);
			boolean isMatch = singleHex.equals(hex);
			if(!isMatch) {
				addFailure(new Failure("failed expected: " + singleHex + " actual: " + hex, w));
			}
			confirmAddrStrings(ipAddr, hex);
		} catch(AddressTypeException | IllegalStateException e) {
			boolean isMatch = singleHex == null;
			if(!isMatch) {
				addFailure(new Failure("failed expected: " + singleHex + " actual: " + e, w));
			}
		}
		try {
			hexNoPrefix = ipAddr.toHexString(false);
			if(ipAddr.isIPv6()) {
				confirmAddrStrings(ipAddr, hexNoPrefix);//For ipv4, no 0x means decimal
			}
		} catch(AddressTypeException | IllegalStateException e) {
			boolean isMatch = singleHex == null;
			if(!isMatch) {
				addFailure(new Failure("failed expected non-null, actual: " + e, w));
			}
		}
		try {
			octal = ipAddr.toOctalString(true);
			boolean isMatch = singleOctal.equals(octal);
			if(!isMatch) {
				addFailure(new Failure("failed expected: " + singleOctal + " actual: " + octal, w));
			}
			if(ipAddr.isIPv4()) {
				confirmAddrStrings(ipAddr, octal);
			}
		} catch(AddressTypeException | IllegalStateException e) {
			boolean isMatch = singleOctal == null;
			if(!isMatch) {
				addFailure(new Failure("failed expected: " + singleOctal + " actual: " + e, w));
			}
		}
		
		try {
			String binary = ipAddr.toBinaryString();
			for(int i = 0; i < binary.length(); i++) {
				char c2 = binary.charAt(i);
				if(c2 == '%') {
					break;
				}
				if(c2 != '0' && c2 != '1' && c2 != '-') {
					addFailure(new Failure("failed expected non-null binary string but got: " + binary, w));
				}
			}
		} catch(AddressTypeException | IllegalStateException e) {
			boolean isMatch = singleHex == null;//iff hex is null is binary null
			if(!isMatch) {
				addFailure(new Failure("failed expected non-null binary string but got: " + e, w));
			}
		}
		

		confirmAddrStrings(ipAddr, c, canonical, s, cidr, n, nw, caw, cw);
		if(ipAddr.isIPv6()) {
			confirmAddrStrings(ipAddr, full);
		} else {
			IPAddressStringParameters params = new IPAddressStringParameters.Builder().allow_inet_aton(false).toParams();
			IPAddressString fullAddrString = new IPAddressString(full, params);
			confirmAddrStrings(ipAddr, fullAddrString);
		}
		confirmHostStrings(ipAddr, rDNS, unc);//these two are valid hosts with embedded addresses
		confirmHostStrings(ipAddr, c, canonical, s, cidr, n, nw, caw, cw);
		if(ipAddr.isIPv6()) {
			confirmHostStrings(ipAddr, full);
		} else {
			HostNameParameters params = new HostNameParameters.Builder().getAddressOptionsBuilder().allow_inet_aton(false).getParentBuilder().toParams();
			HostName fullAddrString = new HostName(full, params);
			confirmHostStrings(ipAddr, fullAddrString);
		}
		
		boolean nMatch = normalizedString.equals(n);
		if(!nMatch) {
			addFailure(new Failure("failed expected: " + normalizedString + " actual: " + n, w));
		} else {
			boolean nwMatch = normalizedWildcardString.equals(nw);
			if(!nwMatch) {
				addFailure(new Failure("failed expected: " + normalizedWildcardString + " actual: " + nw, w));
			}  else {
				boolean cawMatch = canonicalWildcardString.equals(caw);
				if(!cawMatch) {
					addFailure(new Failure("failed expected: " + canonicalWildcardString + " actual: " + caw, w));
				} else {
					boolean cMatch = compressedString.equals(c);
					if(!cMatch) {
						addFailure(new Failure("failed expected: " + compressedString + " actual: " + c, w));
					} else {
						boolean sMatch = subnetString.equals(s);
						if(!sMatch) {
							addFailure(new Failure("failed expected: " + subnetString + " actual: " + s, w));
						} else {
							boolean cwMatch = compressedWildcardString.equals(cw);
							if(!cwMatch) {
								addFailure(new Failure("failed expected: " + compressedWildcardString + " actual: " + cw, w));
							} else {
								boolean wMatch = sqlString.equals(sql);
								if(!wMatch) {
									addFailure(new Failure("failed expected: " + sqlString + " actual: " + sql, w));
								} else {
									boolean cidrMatch = cidrString.equals(cidr);
									if(!cidrMatch) {
										addFailure(new Failure("failed expected: " + cidrString + " actual: " + cidr, w));
									} else {
										boolean canonicalMatch = canonicalString.equals(canonical);
										if(!canonicalMatch) {
											addFailure(new Failure("failed expected: " + canonicalString + " actual: " + canonical, w));
										} else {
											boolean fullMatch = fullString.equals(full);
											if(!fullMatch) {
												addFailure(new Failure("failed expected: " + fullString + " actual: " + full, w));
											} else {
												boolean rdnsMatch = reverseDNSString.equals(rDNS);
												if(!rdnsMatch) {
													addFailure(new Failure("failed expected: " + reverseDNSString + " actual: " + rDNS, w));
												} else {
													boolean uncMatch = uncHostString.equals(unc);
													if(!uncMatch) {
														addFailure(new Failure("failed expected: " + uncHostString + " actual: " + unc, w));
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		incrementTestCount();
	}

	void hostLabelsTest(String x, String labels[]) {
		HostName host = createHost(x);
		hostLabelsTest(host, labels);
	}
	
	void hostLabelsTest(HostName host, String labels[]) {
		if(host.getNormalizedLabels().length != labels.length) {
			addFailure(new Failure("normalization length " + host.getNormalizedLabels().length, host));
		} else {
			for(int i = 0; i < labels.length; i++) {
				if(!labels[i].equals(host.getNormalizedLabels()[i])) {
					addFailure(new Failure("normalization label " + host.getNormalizedLabels()[i] + " not expected label " + labels[i], host));
					break;
				}
			}
		}
		incrementTestCount();
	}
	
	void testCache(String strs[], HostIdentifierStringCache<? extends HostIdentifierString> cache, Function<String, ? extends HostIdentifierString> producer, boolean testSize, boolean useBytes) {
		for(String str: strs) {
			if(useBytes) {
				IPAddressString first = (IPAddressString) producer.apply(str);
				IPAddress firstAddr = first.getAddress();
				if(firstAddr == null) {
					cache.get(str);
				} else {
					if(firstAddr.isIPv6()) {
						cache.get(firstAddr.getIPVersion(), 
								HostIdentifierStringCache.getValueProvider(firstAddr.getBytes()),
								HostIdentifierStringCache.getValueProvider(firstAddr.getUpperBytes()),
								firstAddr.getPrefixLength(),
								firstAddr.toIPv6().getZone());
					} else {
						cache.get(firstAddr.getIPVersion(), 
							HostIdentifierStringCache.getValueProvider(firstAddr.getBytes()),
							HostIdentifierStringCache.getValueProvider(firstAddr.getUpperBytes()),
							firstAddr.getPrefixLength());
					}
					IPAddressString second = (IPAddressString) producer.apply(str);
					//this tests cacheNormalizedString where we create the normalized string first, then stick it in the address,
					//rather than creating it from the address
					//the normalized string must be the same either way, so this tests that
					if(!first.toNormalizedString().equals(second.toNormalizedString())) {
						addFailure(new Failure("failed normalized string mismatch: " + first.toNormalizedString() + " and " + second.toNormalizedString()));
					}
				}
			} else {
				cache.get(str);
			}
		}
		if(testSize && !useBytes) {
			int size = cache.getBackingMap().size();
			for(String str: strs) {
				cache.get(str);
			}
			if(size != cache.getBackingMap().size()) {
				synchronized(this) {
					addFailure(new Failure("failed cache size mismatch: " + size + " and " + cache.getBackingMap().size()));
				}
			} 
		}
		
		//The identity set size is a little bigger because two equal addresses can have two different normalized strings due to prefix.  But that is OK.
		//TreeSet<HostIdentifierString> set = new TreeSet<HostIdentifierString>();
		//IdentityHashMap<HostIdentifierString, Class<?>> setMap = new IdentityHashMap<HostIdentifierString, Class<?>>();
		for(String str: strs) {
			HostIdentifierString string = cache.get(str);
			//set.add(string);
			//setMap.put(string, getClass());
			HostIdentifierString second = producer.apply(str);
			if(!string.equals(second)) {
				synchronized(this) {
					addFailure(new Failure("failed cache mismatch: " + string + " and " + second, string));
				}
			}
		}
		//System.out.println("cache size is " + cache.getBackingMap().size() + " array size is " + strs.length + " set size is " + set.size() + " identity set size is " + setMap.size());
	}
}

interface AddressCreator {
	HostName createHost(HostKey key);
	
	IPAddressString createAddress(IPAddressStringKey key);
	
	IPAddress createAddress(byte bytes[]);
	
	IPv4Address createAddress(int val);
	
	MACAddressString createMACAddress(MACAddressStringKey key);
	
	MACAddress createMACAddress(byte bytes[]);
	
	MACAddress createMACAddress(long val, boolean extended);
}
