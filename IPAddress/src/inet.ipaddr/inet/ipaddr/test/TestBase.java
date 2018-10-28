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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import inet.ipaddr.Address;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork.HostIdentifierStringGenerator;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.HostName;
import inet.ipaddr.HostNameParameters;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPAddressValueProvider;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork.IPAddressStringGenerator;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.MACAddressStringParameters;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSection.CompressOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.test.MACAddressTest.MACAddressStringKey;
import inet.ipaddr.test.TestBase.HostKey;
import inet.ipaddr.test.TestBase.IPAddressStringKey;

public abstract class TestBase {

	public static PrefixConfiguration prefixConfiguration;
			
	static class Failure {
		HostIdentifierString addr;
		Address addrValue;
		AddressSegmentSeries series;
		IPAddressSeqRange range;
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
		
		Failure(String str, IPAddressSeqRange range) {
			this.str = str;
			this.range = range;
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
			if(range != null) {
				return range.toString();
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
		
		private static final long serialVersionUID = 4L;
		
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
		
		@Override
		public String toString() {
			return keyString;
		}
	}
	

	static class IPAddressStringKey extends LookupKey<IPAddressStringParameters> {
	
		private static final long serialVersionUID = 4L;
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
		
		private static final long serialVersionUID = 4L;
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
		
		private static final long serialVersionUID = 4L;
		
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
			int comparison = bytes.length - o.bytes.length;
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
			allowPort(true).
			allowService(true).
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
						allowWildcardedSeparator(true).
						getParentBuilder().
				getIPv6AddressParametersBuilder().
						allowLeadingZeros(true).
						allowUnlimitedLeadingZeros(false).
						allowPrefixLengthLeadingZeros(true).
						allowPrefixesBeyondAddressSize(false).
						allowWildcardedSeparator(true).
						allowMixed(true).
						allowZone(true).
						getParentBuilder().getParentBuilder().toParams();

	protected static final IPAddressStringParameters ADDRESS_OPTIONS = HOST_OPTIONS.toAddressOptionsBuilder().toParams();
	
	protected static final MACAddressStringParameters MAC_ADDRESS_OPTIONS = new MACAddressStringParameters.Builder().
			allowEmpty(false).
			allowAll(false).
			getFormatBuilder().
				setRangeOptions(RangeParameters.NO_RANGE).
				allowLeadingZeros(true).
				allowUnlimitedLeadingZeros(false).
				allowWildcardedSeparator(true).
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
				allowAll(true).
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
	Failures failures = new Failures();
	Perf perf = new Perf();
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
		showMessage("Done: " + getClass().getSimpleName());
	}
	
	abstract void runTest();
	
	static class ExpectedPrefixes {
		Integer next;
		Integer previous;
		Integer adjusted;
		Integer set;
		Integer applied;
		
		ExpectedPrefixes(boolean isMac, Integer original, int bitLength, int segmentBitLength, int set, int adjustment) {
			if(original == null) {
				next = null;
				previous = isMac ? bitLength - segmentBitLength : bitLength;//bitLength is not a possible prefix with MAC (a prefix of bitlength is interpreted as null prefix length)
				adjusted = adjustment > 0 ? null : bitLength + adjustment;
				applied = this.set = set;
			} else {
				next = original == bitLength ? null : Math.min(bitLength, ((original + segmentBitLength) / segmentBitLength) * segmentBitLength);
				previous = Math.max(0, ((original - 1) / segmentBitLength) * segmentBitLength);
				int adj = Math.max(0, original + adjustment);
				adjusted = adj > bitLength ? null : adj;
				this.set = set;
				applied = Math.min(original, set);
			}
		}
		
		boolean compare(Integer next, Integer previous, Integer adjusted, Integer set, Integer applied) {
			return Objects.equals(next, this.next) &&
					Objects.equals(previous, this.previous) &&
					Objects.equals(adjusted, this.adjusted) &&
					Objects.equals(set, this.set) &&
					Objects.equals(applied, this.applied);
		}
		
		String print(Integer next, Integer previous, Integer adjusted, Integer set, Integer applied) {
			return print(next, this.next, "next") + "\n" +
					print(previous, this.previous, "previous") + "\n" +
					print(adjusted, this.adjusted, "adjusted") + "\n" +
					print(set, this.set, "set") + "\n" +
					print(applied, this.applied, "applied");
		}
		
		String print(Integer result, Integer expected, String label) {
			return "expected " + label + ": " + expected + " result: " + result;
		}
	}

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
					int lower = seg.getSegmentValue();
					int upper = seg.getUpperSegmentValue();
					if((lower & mask) != lower || (upper & mask) != upper) {
						removed = original.removePrefixLength();
						addFailure(new Failure("prefix app: " + removed + " " + (lower & mask) + " " + (upper & mask), original));
						break;
					}
				}
			}
		} else if(!removed.equals(original)) {
			addFailure(new Failure("prefix removed: " + removed, original));
		}
		AddressSegmentSeries adjustedSeries = original.adjustPrefixBySegment(true);
		Integer nextPrefix = adjustedSeries.getPrefixLength();
		if(!adjustedSeries.equals(next)) {
			addFailure(new Failure("prefix next: " + adjustedSeries, next));
		} else {
			adjustedSeries = original.adjustPrefixBySegment(false);
			Integer prevPrefix = adjustedSeries.getPrefixLength();
			if(!adjustedSeries.equals(previous)) {
				addFailure(new Failure("prefix previous: " + adjustedSeries, previous));
			} else {
				adjustedSeries = original.adjustPrefixLength(adjustment);
				Integer adjustedPrefix = adjustedSeries.getPrefixLength();
				if(!adjustedSeries.equals(adjusted)) {
					//original.adjustPrefixLength(adjustment);
					addFailure(new Failure("prefix adjusted: " + adjustedSeries, adjusted));
				} else {
					adjustedSeries = original.setPrefixLength(prefix);
					Integer setPrefix = adjustedSeries.getPrefixLength();
					if(!adjustedSeries.equals(prefixSet)) {
						addFailure(new Failure("prefix set: " + adjustedSeries, prefixSet));
					} else {
						adjustedSeries = original.applyPrefixLength(prefix);
						Integer appliedPrefix = adjustedSeries.getPrefixLength();
						if(!adjustedSeries.equals(prefixApplied)) {
							addFailure(new Failure("prefix applied: " + adjustedSeries, prefixApplied));
						} else {
							ExpectedPrefixes expected = new ExpectedPrefixes(original instanceof MACAddress, original.getPrefixLength(), original.getBitCount(), original.getBitsPerSegment(), prefix, adjustment);
							if(!expected.compare(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix)) {
								//System.out.println(expected.print(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix));
								//System.out.println();
								addFailure(new Failure(expected.print(nextPrefix, prevPrefix, adjustedPrefix, setPrefix, appliedPrefix)));
							} 
//							else {
//								System.out.println("all good");
//								System.out.println();
//							}
						}
					}
				}
			}
		}
	}
	
	void testPrefix(AddressSegmentSeries original, Integer prefixLength, int minPrefix, Integer equivalentPrefix) {
		if(!Objects.equals(original.getPrefixLength(), prefixLength)) {
			addFailure(new Failure("prefix: " + original.getPrefixLength() + " expected: " + prefixLength, original));
		} else if(!Objects.equals(original.getMinPrefixLengthForBlock(), minPrefix)) {
			addFailure(new Failure("min prefix: " + original.getMinPrefixLengthForBlock() + " expected: " + minPrefix, original));
		} else if(!Objects.equals(original.getPrefixLengthForSingleBlock(), equivalentPrefix)) {
			addFailure(new Failure("equivalent prefix: " + original.getPrefixLengthForSingleBlock() + " expected: " + equivalentPrefix, original));
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

		try {
			String base85 = null;
			try {
				base85 = ipAddr.toBase85String();
				boolean b85Match = base85.equals(base85String);
				if(!b85Match) {
					addFailure(new Failure("failed expected: " + base85String + " actual: " + base85, w));
				}
			} catch(IncompatibleAddressException e) {
				boolean isMatch = base85String == null;
				if(!isMatch) {
					addFailure(new Failure("failed expected non-null, actual: " + e, w));
				}
			}
			
			String m = ipAddr.toMixedString();
			
			CompressOptions compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.COVERED_BY_HOST);
			IPv6StringOptions mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toOptions();
			String mixedCompressCoveredHost = ipAddr.toNormalizedString(mixedParams);
			
			compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.NO_HOST);
			mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toOptions();
			String mixedNoCompressHost = ipAddr.toNormalizedString(mixedParams);
			
			compressOpts = new CompressOptions(true, CompressOptions.CompressionChoiceOptions.ZEROS_OR_HOST, CompressOptions.MixedCompressionOptions.NO);
			mixedParams = new IPv6StringOptions.Builder().setMakeMixed(true).setCompressOptions(compressOpts).toOptions();
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
						}
					}
				}
			}
		} catch(IncompatibleAddressException e) {
			addFailure(new Failure("unexpected throw " + e.toString()));
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
			if(str == null) {
				continue;
			}
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
	
	boolean confirmHostStrings(IPAddress ipAddr, boolean omitZone, String ...strs) {
		for(String str : strs) {
			HostName hostName = new HostName(str);
			IPAddress a = hostName.getAddress();
			if(omitZone) {
				IPv6Address ipv6Addr = ipAddr.toIPv6();
				ipAddr = new IPv6Address(ipv6Addr.getSection());
			}
			if(!ipAddr.equals(a)) {
				addFailure(new Failure("failed produced string: " + str, ipAddr));
				return false;
			}
			String again = hostName.toNormalizedString();
			hostName = new HostName(again);
			a = hostName.getAddress();
			if(!ipAddr.equals(a)) {
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
		} catch(IncompatibleAddressException | IllegalStateException e) {
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
		} catch(IncompatibleAddressException | IllegalStateException e) {
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
						} catch(IncompatibleAddressException e) {
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
		try {
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
			} catch(IncompatibleAddressException | IllegalStateException e) {
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
			} catch(IncompatibleAddressException | IllegalStateException e) {
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
			} catch(IncompatibleAddressException | IllegalStateException e) {
				boolean isMatch = singleOctal == null;
				if(!isMatch) {
					addFailure(new Failure("failed expected: " + singleOctal + " actual: " + e, w));
				}
			}
			
			try {
				String binary = ipAddr.toBinaryString();
				for(int i = 0; i < binary.length(); i++) {
					char c2 = binary.charAt(i);
					if(c2 == '%' || c2 == '/') {//in most cases we handle prefixed strings by printing the whole address as a range.
						//however, for prefixed non-multiple addresses we still have the prefix
						int next = binary.indexOf('-', i + 1);
						if(next >= 0) {
							i = next + 1;
						} else {
							if(c2 == '/' && binary.length() - i > 4) {
								addFailure(new Failure("failed binary prefix: " + binary, w));
							}
							break;
						}
					}
					if(c2 != '0' && c2 != '1' && c2 != '-') {
						addFailure(new Failure("failed expected non-null binary string but got: " + binary, w));
						break;
					}
				}
			} catch(IncompatibleAddressException | IllegalStateException e) {
				boolean isMatch = singleHex == null;//iff hex is null is binary null
				if(!isMatch) {
					addFailure(new Failure("failed expected non-null binary string but got: " + e, w));
				}
			}
			
	
			confirmAddrStrings(ipAddr, c, canonical, s, cidr, n, nw, caw, cw);
			if(ipAddr.isIPv6()) {
				confirmAddrStrings(ipAddr, full);
				confirmHostStrings(ipAddr, true, rDNS);//these two are valid hosts with embedded addresses
				confirmHostStrings(ipAddr, false, unc);//these two are valid hosts with embedded addresses
			} else {
				IPAddressStringParameters params = new IPAddressStringParameters.Builder().allow_inet_aton(false).toParams();
				IPAddressString fullAddrString = new IPAddressString(full, params);
				confirmAddrStrings(ipAddr, fullAddrString);
				confirmHostStrings(ipAddr, false, rDNS, unc);//these two are valid hosts with embedded addresses
			}
			confirmHostStrings(ipAddr, false, c, canonical, s, cidr, n, nw, caw, cw);
			if(ipAddr.isIPv6()) {
				confirmHostStrings(ipAddr, false, full);
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
		} catch(RuntimeException e) {
			addFailure(new Failure("unexpected throw: " + e));
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
	
	void testCache(String strs[], HostIdentifierStringGenerator<? extends HostIdentifierString> cache, Function<String, ? extends HostIdentifierString> producer, boolean testSize, boolean useBytes) {
		for(String str: strs) {
			if(useBytes) {
				IPAddressString first = (IPAddressString) producer.apply(str);
				IPAddress firstAddr = first.getAddress();
				if(firstAddr == null) {
					cache.get(str);
				} else {
					cache.get(new IPAddressValueProvider() {

						@Override
						public SegmentValueProvider getValues() {
							return IPAddressStringGenerator.getValueProvider(firstAddr.getBytes());
						}

						@Override
						public SegmentValueProvider getUpperValues() {
							return IPAddressStringGenerator.getValueProvider(firstAddr.getUpperBytes());
						}

						@Override
						public Integer getPrefixLength() {
							return firstAddr.getPrefixLength();
						}

						@Override
						public String getZone() {
							return firstAddr.isIPv6() ? firstAddr.toIPv6().getZone() : null;
						}

						@Override
						public IPVersion getIPVersion() {
							return firstAddr.getIPVersion();
						}

						@Override
						public int getSegmentCount() {
							return firstAddr.getSegmentCount();
						}
						
					});
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
		
		for(String str: strs) {
			HostIdentifierString string = cache.get(str);
			HostIdentifierString second = producer.apply(str);
			if(!string.equals(second)) {
				synchronized(this) {
					addFailure(new Failure("failed cache mismatch: " + string + " and " + second, string));
					//string.equals(second);
				}
			}
		}
	}
	
	void testReplace(Address front, Address back, String fronts[], String backs[], char sep, boolean isMac) {
		int bitsPerSegment = front.getBitsPerSegment();
		int segmentCount = front.getSegmentCount();
		boolean isIpv4 = !isMac && segmentCount == IPv4Address.SEGMENT_COUNT;
		StringBuilder prefixes = new StringBuilder("[\n");//currently unused
		for(int replaceTargetIndex = 0; replaceTargetIndex < fronts.length; replaceTargetIndex++) {
			if(replaceTargetIndex > 0) {
				prefixes.append(",\n");
			}
			prefixes.append("[");
			for(int replaceCount = 0; replaceCount < fronts.length - replaceTargetIndex; replaceCount++) {
				if(replaceCount > 0) {
					prefixes.append(",\n");
				}
				prefixes.append("    [");
				StringBuilder lowest = new StringBuilder();
				for(int replaceSourceIndex = 0; replaceSourceIndex < backs.length - replaceCount; replaceSourceIndex++) {
					//We are replacing replaceCount segments in front at index replaceTargetIndex with the same number of segments starting at replaceSourceIndex in back
					StringBuilder str = new StringBuilder();
					int k = 0;
					for(; k < replaceTargetIndex; k++) {
						if(str.length() > 0) {
							str.append(sep);
						}
						str.append(fronts[k]);
					}
					int current = k;
					int limit = replaceCount + current;
					for(; k < limit; k++) {
						if(str.length() > 0) {
							str.append(sep);
						}
						str.append(backs[replaceSourceIndex + k - current]);
					}
					for(; k < segmentCount; k++) {
						if(str.length() > 0) {
							str.append(sep);
						}
						str.append(fronts[k]);
					}
					Integer prefix;
					boolean frontPrefixed = front.isPrefixed();
					if(frontPrefixed && front.getPrefixLength() <= replaceTargetIndex * bitsPerSegment && (isMac || replaceTargetIndex > 0)) {//when replaceTargetIndex is 0, slight difference between mac and ipvx, for ipvx we do not account for a front prefix of 0
						prefix = front.getPrefixLength();
					} else if(back.isPrefixed() && back.getPrefixLength() <= (replaceSourceIndex + replaceCount) * bitsPerSegment && (isMac || replaceCount > 0)) {//when replaceCount 0, slight difference between mac and ipvx, for ipvx we do not account for a back prefix
						prefix = (replaceTargetIndex * bitsPerSegment) + Math.max(0, back.getPrefixLength() - (replaceSourceIndex * bitsPerSegment));
					} else if(frontPrefixed) {
						if(front.getPrefixLength() <= (replaceTargetIndex + replaceCount) * bitsPerSegment) {
							prefix = (replaceTargetIndex + replaceCount) * bitsPerSegment;
						} else {
							prefix = front.getPrefixLength();
						}
					} else {
						prefix = null;
					}
					String replaceStr = (isMac ? "MAC" : (isIpv4 ? "IPv4" : "IPv6")) + " replacing " + replaceCount + " segments in " + front + " at index " + replaceTargetIndex + 
							" with segments from " + back + " starting at " + replaceSourceIndex;
					
					Address new1, new2;
					if(isMac) {
						new1 = ((MACAddress) front).replace(replaceTargetIndex, replaceTargetIndex + replaceCount, (MACAddress) back, replaceSourceIndex);
						HostIdentifierString hostIdStr = createMACAddress(str.toString());
						new2 = hostIdStr.getAddress();
						if(prefix != null) {
							new2 = new2.setPrefixLength(prefix, false);
						}
					} else {
						if(prefix != null) {
							str.append('/').append(prefix);
						}
						HostIdentifierString hostIdStr = createAddress(str.toString());
						new2 = hostIdStr.getAddress();
						if(isIpv4) {
							new1 = ((IPv4Address) front).replace(replaceTargetIndex, replaceTargetIndex + replaceCount, (IPv4Address) back, replaceSourceIndex);
						} else {
							new1 = ((IPv6Address) front).replace(replaceTargetIndex, replaceTargetIndex + replaceCount, (IPv6Address) back, replaceSourceIndex);
						}
					}
					if(!new1.equals(new2)) {
						String failStr = "Replacement was " + new1 + " expected was " + new2 + " " + replaceStr;
						addFailure(new Failure(failStr, front));
						
						//this was debug
						//IPv6AddressSection frontSection = ((IPv6Address) front).getSection();
						//IPv6AddressSection backSection = ((IPv6Address) back).getSection();
						//frontSection.replace(replaceTargetIndex, replaceTargetIndex + replaceCount, backSection, replaceSourceIndex, replaceSourceIndex + replaceCount);
					}
					if(lowest.length() > 0) {
						lowest.append(',');
					}
					lowest.append(prefix);
				}
				prefixes.append(lowest).append(']');
			}
			prefixes.append(']');
		}
		prefixes.append(']');
	}

	void testAppendAndInsert(Address front, Address back, String fronts[], String backs[], char sep, Integer expectedPref[], boolean isMac) {
		if(front.getSegmentCount() >= expectedPref.length) {
			throw new IllegalArgumentException();
		}
		int extra = 0;
		if(isMac) {
			extra = MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT - front.getSegmentCount();
		}
		int bitsPerSegment = front.getBitsPerSegment();
		boolean isIpv4 = !isMac && front.getSegmentCount() == IPv4Address.SEGMENT_COUNT;
		for(int i = 0; i < fronts.length; i++) {
			StringBuilder str = new StringBuilder();
			int k = 0;
			for(; k < i; k++) {
				if(str.length() > 0) {
					str.append(sep);
				}
				str.append(fronts[k]);
			}
			for(; k < fronts.length; k++) {
				if(str.length() > 0) {
					str.append(sep);
				}
				str.append(backs[k]);
			}
			HostIdentifierString hostIdStr = null;
			
			//Split up into two sections to test append
			AddressSection frontSection = front.getSection(0, i);
			AddressSection backSection = back.getSection(i);
			AddressSection backSectionInvalid = null;
			AddressSection frontSectionInvalid = null;
			if(i - (1 + extra) >= 0 && i + 1 + extra <= front.getSegmentCount()) {
				backSectionInvalid = back.getSection(i - (1 + extra));
				frontSectionInvalid = front.getSection(0, i + 1 + extra);
			}

			//Split up even further into 3 sections to test insert
			List<AddressSection[]> splits = new ArrayList<AddressSection[]>(front.getSegmentCount() + 3);
			for(int m = 0; m <= frontSection.getSegmentCount(); m++) {
				AddressSection sub1 = frontSection.getSection(0, m);
				AddressSection sub2 = frontSection.getSection(m, frontSection.getSegmentCount());
				splits.add(new AddressSection[] {sub1, sub2, backSection});
			}
			for(int m = 0; m <= backSection.getSegmentCount(); m++) {
				AddressSection sub1 = backSection.getSection(0, m);
				AddressSection sub2 = backSection.getSection(m, backSection.getSegmentCount());
				splits.add(new AddressSection[] {frontSection, sub1, sub2});
			}
			//now you can insert the middle one after appending the first and last
			//Keep in mind that inserting the first one is like a prepend, which is like an append
			//Inserting the last one is an append
			//We already test append pretty good
			//So really, just insert the middle one after appending first and last
			List<Address> splitsJoined = new ArrayList<Address>(splits.size());
			try {
				Address mixed, mixed2;
				if(isMac) {
					hostIdStr = createMACAddress(str.toString());
					mixed = hostIdStr.getAddress();
					if(front.isPrefixed() && front.getPrefixLength() <= i * bitsPerSegment) {
						mixed = mixed.setPrefixLength(front.getPrefixLength(), false);
					} else if(back.isPrefixed()) {
						mixed = mixed.setPrefixLength(Math.max(i * bitsPerSegment, back.getPrefixLength()), false);
					}
					MACAddressSection sec = ((MACAddressSection) frontSection).append((MACAddressSection) backSection);
					mixed2 = ((MACAddress) back).getNetwork().getAddressCreator().createAddress(sec);
					if(frontSectionInvalid != null && backSectionInvalid != null) {
						try {
							((MACAddressSection) frontSection).append((MACAddressSection) backSectionInvalid);
							addFailure(new Failure("invalid segment length should have failed in join of " + frontSection + " with " + backSectionInvalid, front));
						} catch(AddressValueException e) {
							//pass
						}
						try {
							((MACAddressSection) frontSectionInvalid).append((MACAddressSection) backSection);
							addFailure(new Failure("invalid segment length should have failed in join of " + frontSectionInvalid + " with " + backSection, front));
						} catch(AddressValueException e) {
							//pass
						}
					}
					for(int o = 0; o < splits.size(); o++) {
						AddressSection split[] = splits.get(o);
						AddressSection f = split[0];
						AddressSection g = split[1];
						AddressSection h = split[2];
						sec = ((MACAddressSection) f).append((MACAddressSection) h);
						if(h.isPrefixed() && h.getPrefixLength() == 0 && !f.isPrefixed()) {
							sec = sec.appendToPrefix((MACAddressSection) g);
						} else {
							sec = sec.insert(f.getSegmentCount(), (MACAddressSection) g);
						}
						MACAddress mixed3 = ((MACAddress) back).getNetwork().getAddressCreator().createAddress(sec);
						splitsJoined.add(mixed3);
					}
				} else {
					if(front.isPrefixed() && front.getPrefixLength() <= i * bitsPerSegment && i > 0) {
						str.append('/').append(front.getPrefixLength());
					} else if(back.isPrefixed()) {
						str.append('/').append(Math.max(i * bitsPerSegment, back.getPrefixLength()));
					}
					hostIdStr = createAddress(str.toString());
					mixed = hostIdStr.getAddress();
					
					
					if(isIpv4) {
						IPv4AddressSection sec = ((IPv4AddressSection) frontSection).append((IPv4AddressSection) backSection);
						mixed2 = ((IPv4Address) back).getNetwork().getAddressCreator().createAddress(sec);
						if(frontSectionInvalid != null && backSectionInvalid != null) {
							try {
								((IPv4AddressSection) frontSection).append((IPv4AddressSection) backSectionInvalid);
								addFailure(new Failure("invalid segment length should have failed in join of " + frontSection + " with " + backSectionInvalid, front));
							} catch(AddressValueException e) {
								//pass
							}
							try {
								((IPv4AddressSection) frontSectionInvalid).append((IPv4AddressSection) backSection);
								addFailure(new Failure("invalid segment length should have failed in join of " + frontSectionInvalid + " with " + backSection, front));
							} catch(AddressValueException e) {
								//pass
							}
						}
						for(int o = 0; o < splits.size(); o++) {
							AddressSection split[] = splits.get(o);
							AddressSection f = split[0];
							AddressSection g = split[1];
							AddressSection h = split[2];
							sec = ((IPv4AddressSection) f).append((IPv4AddressSection) h);
							if(h.isPrefixed() && h.getPrefixLength() == 0 && !f.isPrefixed()) {
								sec = sec.appendToNetwork((IPv4AddressSection) g);
							} else {
								sec = sec.insert(f.getSegmentCount(), (IPv4AddressSection) g);
							}
							IPv4Address mixed3 = ((IPv4Address) back).getNetwork().getAddressCreator().createAddress(sec);
							splitsJoined.add(mixed3);
						}
					} else {
						IPv6AddressSection sec = ((IPv6AddressSection) frontSection).append((IPv6AddressSection) backSection);
						mixed2 = ((IPv6Address) back).getNetwork().getAddressCreator().createAddress(sec);
						if(frontSectionInvalid != null && backSectionInvalid != null) {
							try {
								((IPv6AddressSection) frontSection).append((IPv6AddressSection) backSectionInvalid);
								addFailure(new Failure("invalid segment length should have failed in join of " + frontSection + " with " + backSectionInvalid, front));
							} catch(AddressValueException e) {
								//pass
							}
							try {
								((IPv6AddressSection) frontSectionInvalid).append((IPv6AddressSection) backSection);
								addFailure(new Failure("invalid segment length should have failed in join of " + frontSectionInvalid + " with " + backSection, front));
							} catch(AddressValueException e) {
								//pass
							}
						}
						
						for(int o = 0; o < splits.size(); o++) {
							AddressSection split[] = splits.get(o);
							AddressSection f = split[0];
							AddressSection g = split[1];
							AddressSection h = split[2];
							sec = ((IPv6AddressSection) f).append((IPv6AddressSection) h);
							if(h.isPrefixed() && h.getPrefixLength() == 0 && !f.isPrefixed()) {
								sec = sec.appendToNetwork((IPv6AddressSection) g);
							} else {
								sec = sec.insert(f.getSegmentCount(), (IPv6AddressSection) g);
							}
							IPv6Address mixed3 = ((IPv6Address) back).getNetwork().getAddressCreator().createAddress(sec);
							splitsJoined.add(mixed3);
						}
					}
				}
				if(!mixed.equals(mixed2)) {
					addFailure(new Failure("mixed was " + mixed + " expected was " + mixed2, mixed));
				}
				if(!Objects.equals(expectedPref[i], mixed.getPrefixLength())) {
					addFailure(new Failure("mixed prefix was " + mixed.getPrefixLength() + " expected was " + expectedPref[i], mixed));
				}
				if(!Objects.equals(expectedPref[i], mixed2.getPrefixLength())) {
					addFailure(new Failure("mixed2 prefix was " + mixed2.getPrefixLength() + " expected was " + expectedPref[i], mixed2));
				}
				for(int o = 0; o < splitsJoined.size(); o++) {
					Address mixed3 = splitsJoined.get(o);
					if(!mixed.equals(mixed3)) {
						addFailure(new Failure("mixed was " + mixed3 + " expected was " + mixed, mixed3));
					}
					if(!mixed3.equals(mixed2)) {
						addFailure(new Failure("mixed was " + mixed3 + " expected was " + mixed2, mixed3));
					}
					if(!Objects.equals(expectedPref[i], mixed3.getPrefixLength())) {
						addFailure(new Failure("mixed3 prefix was " + mixed3.getPrefixLength() + " expected was " + expectedPref[i], mixed3));
					}
				}
			} catch(IncompatibleAddressException e) {
				if(expectedPref[i] == null || expectedPref[i] >= 0) {
					addFailure(new Failure("expected prefix " + expectedPref[i] + ", but append failed due to prefix for " + frontSection + " and " + backSection, hostIdStr));
				}
			} catch(IllegalArgumentException e) {
				if(expectedPref[i] == null || expectedPref[i] >= 0) {
					addFailure(new Failure("expected prefix " + expectedPref[i] + ", but append failed due to prefix for " + frontSection + " and " + backSection, hostIdStr));
				}
			}
		}
		incrementTestCount();
	}
	
	void testIncrement(Address orig, long increment, Address expectedResult) {
		testIncrement(orig, increment, expectedResult, true);
	}
	
	void testIncrement(Address orig, long increment, Address expectedResult, boolean first) {
		try {
			Address result = orig.increment(increment);
			if(expectedResult == null) {
				addFailure(new Failure("increment mismatch result " +  result + " vs none expected", orig));
			} else {
				if(!result.equals(expectedResult)) {
					addFailure(new Failure("increment mismatch result " +  result + " vs expected " + expectedResult, orig));
				}
				if(first && !orig.isMultiple() && increment > Long.MIN_VALUE) {//negating Long.MIN_VALUE results in same address
					testIncrement(expectedResult, -increment, orig, false);
				}
			}
		} catch(AddressValueException e) {
			if(expectedResult != null) {
				addFailure(new Failure("increment mismatch exception " +  e + ", expected " + expectedResult, orig));
			}
		}
		incrementTestCount();
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
