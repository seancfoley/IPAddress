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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

import inet.ipaddr.Address;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6Address;


public class IPAddressRangeTest extends IPAddressTest {
	
	static final IPAddressStringParameters WILDCARD_AND_RANGE_ADDRESS_OPTIONS = ADDRESS_OPTIONS.toBuilder().allowAll(true).setRangeOptions(RangeParameters.WILDCARD_AND_RANGE).toParams();
	static final IPAddressStringParameters WILDCARD_ONLY_ADDRESS_OPTIONS = WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().setRangeOptions(RangeParameters.WILDCARD_ONLY).toParams();
	private static final IPAddressStringParameters NO_RANGE_ADDRESS_OPTIONS = WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().setRangeOptions(RangeParameters.NO_RANGE).toParams();
	
	private static final IPAddressStringParameters INET_ATON_WILDCARD_OPTS = INET_ATON_WILDCARD_AND_RANGE_OPTIONS.toBuilder().setRangeOptions(RangeParameters.WILDCARD_ONLY).toParams();
	private static IPAddressStringParameters optionsCache[][] = new IPAddressStringParameters[3][3];

	IPAddressRangeTest(AddressCreator creator) {
		super(creator);
	}
	
	void testIPv4Strings(IPAddressString w, IPAddress ipAddr, String normalizedString, String normalizedWildcardString, String sqlString, String fullString, String octalString, String hexString, String reverseDNSString,
			String singleHex,
			String singleOctal) {
		testStrings(w, ipAddr, normalizedString, normalizedWildcardString, normalizedWildcardString, sqlString, fullString, 
				normalizedString, normalizedString, normalizedWildcardString, normalizedString, normalizedWildcardString, reverseDNSString, normalizedString,
				singleHex, singleOctal);
	
		//now test some IPv4-only strings
		testIPv4OnlyStrings(w, (IPv4Address) ipAddr, octalString, hexString);
		testInetAtonCombos(w, (IPv4Address) ipAddr);
	}
	
	private void testIPv4OnlyStrings(IPAddressString w, IPv4Address ipAddr, String octalString, String hexString) {
		String oct = ipAddr.toInetAtonString(IPv4Address.inet_aton_radix.OCTAL);
		String hex = ipAddr.toInetAtonString(IPv4Address.inet_aton_radix.HEX);
		
		boolean octMatch = oct.equals(octalString);
		if(!octMatch) {
			addFailure(new Failure("failed expected: " + octalString + " actual: " + oct, w));
		} else {
			boolean hexMatch = hex.equals(hexString);
			if(!hexMatch) {
				addFailure(new Failure("failed expected: " + hexString + " actual: " + hex, w));
			}
		}
		incrementTestCount();
	}
	
	void testInetAtonCombos(IPAddressString w, IPv4Address ipAddr) {
		for(IPv4Address.inet_aton_radix radix : IPv4Address.inet_aton_radix.values()) {
			for(int i = 0; i < IPv4Address.SEGMENT_COUNT; i++) {
				try {
					String str = ipAddr.toInetAtonString(radix, i);
					IPAddressString parsed = new IPAddressString(str, INET_ATON_WILDCARD_AND_RANGE_OPTIONS);
					try {
						IPAddress parsedValue = parsed.getAddress();
						if(!ipAddr.equals(parsedValue)) {
							addFailure(new Failure("failed expected: " + ipAddr + " actual: " + parsedValue, w));
						} else {
							int pos;
							int count = 0;
							while ((pos = str.indexOf(IPv4Address.SEGMENT_SEPARATOR)) >= 0) {
								str = str.substring(pos + 1);
								count++;
							}
							if(IPv4Address.SEGMENT_COUNT - 1 - i != count) {
								addFailure(new Failure("failed expected separator count: " + (IPv4Address.SEGMENT_COUNT - 1 - i) + " actual separator count: " + count, w));
							}
						}
					} catch(RuntimeException e) {
						//e.printStackTrace();
						addFailure(new Failure("failed expected: " + ipAddr + " actual: " + e.getMessage(), w));
					}
				} catch(IncompatibleAddressException e) {
					//verify this case: joining segments results in a joined segment that is not a contiguous range
					IPv4AddressSection section =  ipAddr.getSection();
					boolean verifiedIllegalJoin = false;
					for(int j = section.getSegmentCount() - i - 1; j < section.getSegmentCount() - 1; j++) {
						if(section.getSegment(j).isMultiple()) {
							for(j++; j < section.getSegmentCount(); j++) {
								if(!section.getSegment(j).isFullRange()) {
									verifiedIllegalJoin = true;
									break;
								}
							}
						}
					}
					if(!verifiedIllegalJoin) {
						addFailure(new Failure("failed expected: " + ipAddr + " actual: " + e.getMessage(), w));
					}
				}
				incrementTestCount();
			}
		}
	}

	@Override
	protected IPAddressString createInetAtonAddress(String x) {
		IPAddressStringParameters opts;
		if(x.indexOf(IPAddress.RANGE_SEPARATOR) != -1) {
			opts = INET_ATON_WILDCARD_AND_RANGE_OPTIONS;
		} else {
			opts = INET_ATON_WILDCARD_OPTS;
		}
		return createAddress(x, opts);
	}
	
	@Override
	protected IPAddressString createAddress(String x) {
		if(x.indexOf(IPAddress.RANGE_SEPARATOR) != -1) {
			return createAddress(x, WILDCARD_AND_RANGE_ADDRESS_OPTIONS);
		}
		return createAddress(x, WILDCARD_ONLY_ADDRESS_OPTIONS);
	}
	
	protected IPAddressString createAddress(String x, RangeParameters ipv4RangeOptions, RangeParameters ipv6RangeOptions) {
		IPAddressStringParameters validationOptions = getOpts(ipv4RangeOptions, ipv6RangeOptions);
		return createAddress(x, validationOptions);
	}
	
	private static IPAddressStringParameters getOpts(RangeParameters ipv4RangeOptions, RangeParameters ipv6RangeOptions) {
		int cacheIndex, subCacheIndex;
		if(ipv4RangeOptions.equals(RangeParameters.NO_RANGE)) {
			cacheIndex = 0;
		} else if(ipv4RangeOptions.equals(RangeParameters.WILDCARD_ONLY)) {
			cacheIndex = 1;
		} else if(ipv4RangeOptions.equals(RangeParameters.WILDCARD_AND_RANGE)) {
			cacheIndex = 2;
		} else {
			return WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().getIPv4AddressParametersBuilder().setRangeOptions(ipv4RangeOptions).getParentBuilder().
				getIPv6AddressParametersBuilder().setRangeOptions(ipv6RangeOptions).getParentBuilder().toParams();
		}
		if(ipv6RangeOptions.equals(RangeParameters.NO_RANGE)) {
			subCacheIndex = 0;
		} else if(ipv6RangeOptions.equals(RangeParameters.WILDCARD_ONLY)) {
			subCacheIndex = 1;
		} else if(ipv6RangeOptions.equals(RangeParameters.WILDCARD_AND_RANGE)) {
			subCacheIndex = 2;
		} else {
			return WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().getIPv4AddressParametersBuilder().setRangeOptions(ipv4RangeOptions).getParentBuilder().
				getIPv6AddressParametersBuilder().setRangeOptions(ipv6RangeOptions).getParentBuilder().toParams();
		}
		IPAddressStringParameters optionsSubCache[] = optionsCache[cacheIndex];
		IPAddressStringParameters res = optionsSubCache[subCacheIndex];
		if(res == null) {
			optionsSubCache[subCacheIndex] = res = WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().getIPv4AddressParametersBuilder().setRangeOptions(ipv4RangeOptions).getParentBuilder().
					getIPv6AddressParametersBuilder().setRangeOptions(ipv6RangeOptions).getParentBuilder().toParams();
		}
		return res;
	}
	
	private static IPAddressStringParameters getOpts(RangeParameters options) {
		if(options.equals(RangeParameters.NO_RANGE)) {
			return NO_RANGE_ADDRESS_OPTIONS;
		} else if(options.equals(RangeParameters.WILDCARD_ONLY)) {
			return WILDCARD_ONLY_ADDRESS_OPTIONS;
		} else if(options.equals(RangeParameters.WILDCARD_AND_RANGE)) {
			return WILDCARD_AND_RANGE_ADDRESS_OPTIONS;
		}
		return WILDCARD_AND_RANGE_ADDRESS_OPTIONS.toBuilder().setRangeOptions(options).toParams();
	}
	
	protected IPAddressString createAddress(String x, RangeParameters options) {
		return createAddress(x, getOpts(options));
	}
	
	void ipv4test(boolean pass, String x, RangeParameters ipv4RangeOptions, RangeParameters ipv6RangeOptions) {
		ipv4test(pass, x, false, ipv4RangeOptions, ipv6RangeOptions);
	}
	
	void ipv4test(boolean pass, String x, RangeParameters rangeOptions) {
		ipv4test(pass, x, false, rangeOptions);
	}
	
	void ipv4test(boolean pass, String x, boolean isZero, RangeParameters rangeOptions) {
		iptest(pass, x, isZero, false, true, rangeOptions);
	}
	
	void ipv4test(boolean pass, String x, boolean isZero, RangeParameters ipv4RangeOptions, RangeParameters ipv6RangeOptions) {
		iptest(pass, x, isZero, false, true, ipv4RangeOptions, ipv6RangeOptions);
	}
	
	void ipv6test(boolean pass, String x, RangeParameters options) {
		ipv6test(pass, x, false, options);
	}
	
	void ipv6test(boolean pass, String x, RangeParameters ipv4Options, RangeParameters ipv6Options) {
		ipv6test(pass, x, false, ipv4Options, ipv6Options);
	}
	
	void ipv6test(boolean pass, String x, boolean isZero, RangeParameters options) {
		iptest(pass, x, isZero, false, false, options);
	}
	
	void ipv6test(boolean pass, String x, boolean isZero, RangeParameters ipv4Options, RangeParameters ipv6Options) {
		iptest(pass, x, isZero, false, false, ipv4Options, ipv6Options);
	}
	
	void iptest(boolean pass, String x, boolean isZero, boolean notBoth, boolean ipv4Test, RangeParameters ipv4RangeOptions, RangeParameters ipv6RangeOptions) {
		IPAddressString addr = createAddress(x, ipv4RangeOptions, ipv6RangeOptions);
		if(iptest(pass, addr, isZero, notBoth, ipv4Test)) {
			//do it a second time to test the caching
			iptest(pass, addr, isZero, notBoth, ipv4Test);
		}
	}
	
	void iptest(boolean pass, String x, boolean isZero, boolean notBoth, boolean ipv4Test, RangeParameters rangeOptions) {
		IPAddressString addr = createAddress(x, rangeOptions);
		if(iptest(pass, addr, isZero, notBoth, ipv4Test)) {
			//do it a second time to test the caching
			iptest(pass, addr, isZero, notBoth, ipv4Test);
		}
	}
	
	@Override
	void ipv6testWithZone(int pass, String x) {
		return;
	}
	
	@Override
	void ipv6testWithZone(boolean pass, String x) {
		return;
	}
	
	@Override
	boolean testBytes(IPAddress origAddr) {
		boolean failed = false;
		if(origAddr.isMultiple()) {
			try {
				origAddr.getBytes();
			} catch(IncompatibleAddressException e) {
				failed = true;
			}
		} else {
			failed = !super.testBytes(origAddr);
		}
		return !failed;
	}
	
	@Override
	void testMaskBytes(String cidr2, IPAddressString w2)
			throws AddressStringException {
		IPAddress addr = w2.toAddress();
		testBytes(addr);
	}
	
	void testPrefixCount(String original, long number) {
		IPAddressString w = createAddress(original);
		testPrefixCount(this, w, number);
	}
	
	static void testPrefixCount(TestBase testBase, HostIdentifierString w, long number) {
		Address val = w.getAddress();
		boolean isIp = val instanceof IPAddress;
		boolean isPrefixed = val.isPrefixed();
		BigInteger count = val.getPrefixCount();
		if(!count.equals(BigInteger.valueOf(number))) {
			testBase.addFailure(new Failure("count was " + count + " instead of expected count " + number, w));
		} else {
			int loopCount = 0;
			BigInteger totalCount = val.getCount();
			BigInteger countedCount = BigInteger.ZERO;
			while(++loopCount < 2) {
				boolean isBlock = loopCount == 1;
				Iterator<? extends Address> addrIterator = isBlock ? val.prefixBlockIterator() : val.prefixIterator();
				long counter = 0;
				Set<Address> set = new HashSet<Address>();
				Address previous = null;
				Address next = null;
				while(addrIterator.hasNext()) {
					next = addrIterator.next();
					if(isBlock || (previous != null && addrIterator.hasNext())) {
						if(isPrefixed ? !next.isPrefixBlock() : next.isPrefixBlock()) {
							testBase.addFailure(new Failure("not prefix block next: " + next, next));
							break;
						}
						if(isPrefixed ? !next.isSinglePrefixBlock() : next.isPrefixBlock()) {
							testBase.addFailure(new Failure("not single prefix block next: " + next, next));
							break;
						}
					} else if(!isBlock) {
						countedCount = countedCount.add(next.getCount());
					}
					if(isIp && previous != null && ((IPAddress) next).intersect((IPAddress) previous) != null) {
						testBase.addFailure(new Failure("intersection of " + previous + " when iterating: " + ((IPAddress) next).intersect((IPAddress) previous), next));
						break;
					}
					set.add(next);
					//System.out.println(next);
					counter++;
					previous = next;
				}
				if((number < Integer.MAX_VALUE && set.size() != number) || counter != number) {
					testBase.addFailure(new Failure("set count was " + set.size() + " instead of expected " + number, w));
				} else if (number < 0) {
					testBase.addFailure(new Failure("unexpected zero count ", val));
				} else if (!isBlock && !countedCount.equals(totalCount)){
					testBase.addFailure(new Failure("count mismatch, expected " + totalCount + " got " + countedCount, val));
				}
			}
		}
		testBase.incrementTestCount();
	}

	void testCount(String original, long number, long excludeZerosNumber, RangeParameters rangeOptions) {
		IPAddressString w = createAddress(original, rangeOptions);
		testCount(this, w, number, excludeZerosNumber);
	}
	
	void testCount(String original, long number, long excludeZerosNumber) {
		IPAddressString w = createAddress(original);
		testCount(this, w, number, excludeZerosNumber);
	}
	
	static void testCount(TestBase testBase, HostIdentifierString w, long number, long excludeZerosNumber) {
		testCount(testBase, w, number, false);
		if(excludeZerosNumber >= 0) {
			testCount(testBase, w, excludeZerosNumber, true);
		}
	}
	
	void testCount(String original, BigInteger number, BigInteger excludeZerosNumber) {
		IPAddressString w = createAddress(original);
		testCount(this, w, number, false);
		if(excludeZerosNumber.signum() != -1) {
			testCount(this, w, excludeZerosNumber, true);
		}
	}
	
	static void testCount(TestBase testBase, IPAddressString w, BigInteger number, boolean excludeZeroHosts) {
		IPAddress val = w.getAddress();
		BigInteger count = excludeZeroHosts ? val.getNonZeroHostCount() : val.getCount();
		if(!count.equals(number)) {
			testBase.addFailure(new Failure("big count was " + count, w));
		}
		testBase.incrementTestCount();
	}
	
	static void testCount(TestBase testBase, HostIdentifierString w, long number, boolean excludeZeroHosts) {
		Address val = w.getAddress();
		BigInteger count = excludeZeroHosts ? ((IPAddress)val).getNonZeroHostCount() : val.getCount();
		if(!count.equals(BigInteger.valueOf(number))) {
			testBase.addFailure(new Failure("count was " + count + " instead of expected count " + number, w));
		} else {
			Iterator<? extends Address> addrIterator = excludeZeroHosts ? ((IPAddress)val).nonZeroHostIterator() : val.iterator();
			long counter = 0;
			Set<Address> set = new HashSet<Address>();
			Address next = null;
			while(addrIterator.hasNext()) {
				next = addrIterator.next();
				if(counter == 0) {
					Address lower = excludeZeroHosts ? ((IPAddress)val).getLowerNonZeroHost() : val.getLower();
					if(!next.equals(lower)) {
						testBase.addFailure(new Failure("lowest: " + lower + " next: " + next, next));
					}
					if(!lower.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						if(!Objects.equals(next.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " lowest prefix length: " + next.getPrefixLength(), next));
						}
						if(!Objects.equals(lower.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " lowest prefix length: " + lower.getPrefixLength(), lower));
						}
					}
				} else if(counter == 1) {
					if(!next.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						if(!Objects.equals(next.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " next prefix length: " + next.getPrefixLength(), next));
						}
					}
				}
				set.add(next);
				counter++;
			}
			if((number < Integer.MAX_VALUE && set.size() != number) || counter != number) {
				testBase.addFailure(new Failure("set count was " + set.size() + " instead of expected " + number, w));
			} else if (number > 0){
				if(!next.equals(val.getUpper())) {
					testBase.addFailure(new Failure("highest: " + val.getUpper(), next));
				} else {
					Address lower = excludeZeroHosts ? ((IPAddress)val).getLowerNonZeroHost() : val.getLower();
					if(counter == 1 && !val.getUpper().equals(lower)) {
						testBase.addFailure(new Failure("highest: " + val.getUpper() + " lowest: " + val.getLower(), next));
					}
					if(!val.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						if(!Objects.equals(next.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " upper prefix length: " + next.getPrefixLength(), next));
						}
						if(!Objects.equals(val.getUpper().getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " upper prefix length: " + val.getUpper().getPrefixLength(), next));
						}
					}
				}
			} else {
				if(excludeZeroHosts) {
					IPAddress lower = ((IPAddress)val).getLowerNonZeroHost();
					if(lower != null) {
						testBase.addFailure(new Failure("unexpected non-null lower: " + lower, val));
					}
				} else {
					testBase.addFailure(new Failure("unexpected zero count ", val));
				}
			}
		}
		testBase.incrementTestCount();
	}
	
	void testRangeCount(String low, String high, long number) {
		IPAddressString w = createAddress(low);
		IPAddressString w2 = createAddress(high);
		testRangeCount(this, w, w2, number);
	}
	
	void testRangeCount(String low, String high, BigInteger number) {
		IPAddressString w = createAddress(low);
		IPAddressString w2 = createAddress(high);
		testRangeCount(this, w, w2, number);
	}
	
	static void testRangeCount(TestBase testBase, IPAddressString w, IPAddressString high, BigInteger number) {
		IPAddressSeqRange val = w.getAddress().spanWithRange(high.getAddress());
		BigInteger count = val.getCount();
		if(!count.equals(number)) {
			testBase.addFailure(new Failure("big count was " + count, w));
		}
		testBase.incrementTestCount();
	}
	
	static void testRangeCount(TestBase testBase, IPAddressString w, IPAddressString high, long number) {
		IPAddressSeqRange val = w.getAddress().spanWithRange(high.getAddress());
		BigInteger count = val.getCount();
		if(!count.equals(BigInteger.valueOf(number))) {
			testBase.addFailure(new Failure("count was " + count + " instead of expected count " + number, w));
		} else {
			Iterator<? extends Address> addrIterator = val.iterator();
			long counter = 0;
			Set<Address> set = new HashSet<Address>();
			Address next = null;
			while(addrIterator.hasNext()) {
				next = addrIterator.next();
				if(counter == 0) {
					Address lower = val.getLower();
					if(!next.equals(lower)) {
						testBase.addFailure(new Failure("lowest: " + lower + " next: " + next, next));
					}
				}
				set.add(next);
				counter++;
			}
			if((number < Integer.MAX_VALUE && set.size() != number) || counter != number) {
				testBase.addFailure(new Failure("set count was " + set.size() + " instead of expected " + number, w));
			} else if (number > 0){
				if(!next.equals(val.getUpper())) {
					testBase.addFailure(new Failure("highest: " + val.getUpper(), next));
				} else {
					Address lower = val.getLower();
					if(counter == 1 && !val.getUpper().equals(lower)) {
						testBase.addFailure(new Failure("highest: " + val.getUpper() + " lowest: " + val.getLower(), next));
					}
				}
			} else {
				testBase.addFailure(new Failure("unexpected zero count ", val));
			}
		}
		testBase.incrementTestCount();
	}
	
	void testRangePrefixCount(String low, String high, int prefixLength, long number) {
		IPAddressString w = createAddress(low);
		IPAddressString w2 = createAddress(high);
		testRangePrefixCount(this, w, w2, prefixLength, number);
	}
	
	static void testRangePrefixCount(TestBase testBase, IPAddressString w, IPAddressString high, int prefixLength, long number) {
		IPAddressSeqRange val = w.getAddress().spanWithRange(high.getAddress());
		BigInteger count = val.getPrefixCount(prefixLength);
		if(!count.equals(BigInteger.valueOf(number))) {
			testBase.addFailure(new Failure("count was " + count + " instead of expected count " + number, w));
		} else {
			Iterator<? extends IPAddress> addrIterator = val.prefixBlockIterator(prefixLength);
			long counter = 0;
			Set<IPAddress> set = new HashSet<IPAddress>();
			IPAddress next = null, previous = null;
			while(addrIterator.hasNext()) {
				next = addrIterator.next();
				if(!next.isPrefixBlock()) {
					testBase.addFailure(new Failure("not prefix block next: " + next, next));
					break;
				}
				if(!next.isSinglePrefixBlock()) {
					testBase.addFailure(new Failure("not single prefix block next: " + next, next));
					break;
				}
				if(previous != null && next.intersect(previous) != null) {
					testBase.addFailure(new Failure("intersection of " + previous + " when iterating: " + next.intersect(previous), next));
					break;
				}
				set.add(next);
				previous = next;
				//System.out.println(next);
				counter++;
			}
			if((number < Integer.MAX_VALUE && set.size() != number) || counter != number) {
				testBase.addFailure(new Failure("set count was " + set.size() + " instead of expected " + number, w));
			} else if (number < 0) {
				testBase.addFailure(new Failure("unexpected zero count ", val));
			}

			BigInteger totalCount = val.getCount();
			BigInteger countedCount = BigInteger.ZERO;
			Iterator<? extends IPAddressSeqRange> rangeIterator = val.prefixIterator(prefixLength);
			counter = 0;
			Set<IPAddressSeqRange> rangeSet = new HashSet<IPAddressSeqRange>();
			IPAddressSeqRange nextRange = null, previousRange = null;
			while(rangeIterator.hasNext()) {
				nextRange = rangeIterator.next();
				IPAddress blocks[] = nextRange.spanWithPrefixBlocks();
				if(previous != null && addrIterator.hasNext()) {
					if(blocks.length != 1) {
						testBase.addFailure(new Failure("not prefix next: " + nextRange, nextRange));
						break;
					}
					if(!blocks[0].isSinglePrefixBlock()) {
						testBase.addFailure(new Failure("not single prefix next: " + nextRange, nextRange));
						break;
					}
				}
				countedCount = countedCount.add(nextRange.getCount());
				if(previousRange != null && nextRange.intersect(previousRange) != null) {
					testBase.addFailure(new Failure("intersection of " + previousRange + " when iterating: " + nextRange.intersect(previousRange), nextRange));
					break;
				}
				rangeSet.add(nextRange);
				previousRange = nextRange;
				//System.out.println(next);
				counter++;
			}
			if((number < Integer.MAX_VALUE && rangeSet.size() != number) || counter != number) {
				testBase.addFailure(new Failure("set count was " + rangeSet.size() + " instead of expected " + number, w));
			} else if (number < 0) {
				testBase.addFailure(new Failure("unexpected zero count ", val));
			} else if(!countedCount.equals(totalCount)){
				testBase.addFailure(new Failure("count mismatch, expected " + totalCount + " got " + countedCount, val));
			}

		}
		testBase.incrementTestCount();
	}
	
	void testRangeBlocks(String original, int segmentCount, long number) {
		IPAddressString w = createAddress(original);
		testRangeBlocks(this, w, segmentCount, number);
	}

	static void testRangeBlocks(TestBase testBase, IPAddressString w, int segmentCount, long number) {
		IPAddress val = w.getAddress();
		BigInteger count = val.getBlockCount(segmentCount);
		if(!count.equals(BigInteger.valueOf(number))) {
			testBase.addFailure(new Failure("count was " + count + " instead of expected count " + number, w));
		} else {
			Iterator<? extends IPAddress> addrIterator = val.blockIterator(segmentCount);
			long counter = 0, sectionCounter = 0;
			IPAddressSection valSection = val.getSection(0, segmentCount);
			Iterator<? extends IPAddressSection> sectionIterator = valSection.iterator();
			Set<Address> set = new HashSet<Address>();
			Address next = null;
			AddressSection nextSection = null;
			while(addrIterator.hasNext()) {
				next = addrIterator.next();
				nextSection = sectionIterator.next();
				if(counter == 0) {
					Address lower = val.getLower();
					AddressSection lowerSection = lower.getSection(0, segmentCount);
					AddressSection nextAddrSection = next.getSection(0, segmentCount);
					if(!nextAddrSection.equals(lowerSection) || !lowerSection.equals(nextAddrSection)) {
						testBase.addFailure(new Failure("lowest: " + lower + " next addr: " + nextAddrSection, nextAddrSection));
					}
					if(!nextSection.equals(lowerSection) || !lowerSection.equals(nextSection)) {
						testBase.addFailure(new Failure("lowest: " + lower + " next sectiob: " + nextSection, nextSection));
					}
					if(!nextSection.equals(nextAddrSection) || !nextAddrSection.equals(nextSection)) {
						testBase.addFailure(new Failure("nextAddrSection: " + nextAddrSection + " next section: " + nextSection, nextSection));
					}
					if(!lower.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						if(!Objects.equals(next.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " lowest prefix length: " + next.getPrefixLength(), next));
						}
						if(!Objects.equals(lower.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " lowest prefix length: " + lower.getPrefixLength(), lower));
						}
					}
				} else if(counter == 1) {
					if(!next.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						if(!Objects.equals(next.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " next prefix length: " + next.getPrefixLength(), next));
						}
					}
				}
				set.add(next);
				counter++;
				sectionCounter++;
			}
			if((number < Integer.MAX_VALUE && set.size() != number) || counter != number) {
				testBase.addFailure(new Failure("set count was " + set.size() + " instead of expected " + number, w));
			} else if(sectionIterator.hasNext()) {
				do {
					sectionCounter++;
				} while(sectionIterator.hasNext());
				testBase.addFailure(new Failure("counter mismatch, count was " + counter + " section count " + sectionCounter, w));
			} else if (number > 0) {
				AddressSection upperSection = val.getUpper().getSection(0, segmentCount);
				AddressSection nextAddrSection = next.getSection(0, segmentCount);
				if(!nextAddrSection.equals(upperSection) || !upperSection.equals(nextAddrSection)) {
					testBase.addFailure(new Failure("highest: " + upperSection + " next addr: " + nextAddrSection, nextAddrSection));
				}
				if(!nextSection.equals(upperSection) || !upperSection.equals(nextSection)) {
					testBase.addFailure(new Failure("highest: " + upperSection + " next section: " + nextSection, nextSection));
				} else {
					Address lower = val.getLower();
					AddressSection lowerSection = lower.getSection(0, segmentCount);
					if(counter == 1 && !upperSection.equals(lowerSection)) {
						testBase.addFailure(new Failure("highest: " + val.getUpper() + " lowest: " + val.getLower(), next));
					}
					if(!val.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						if(!Objects.equals(next.getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " upper prefix length: " + next.getPrefixLength(), next));
						}
						if(!Objects.equals(val.getUpper().getPrefixLength(), val.getPrefixLength())) {
							testBase.addFailure(new Failure("val prefix length: " + val.getPrefixLength() + " upper prefix length: " + val.getUpper().getPrefixLength(), next));
						}
					}
				}
			} else {
				testBase.addFailure(new Failure("unexpected zero count ", val));
			}
		}
		testBase.incrementTestCount();
	}
	
	void testIPv4Wildcarded(String original, int bits, String expected, String expectedSQL) {
		testWildcarded(original, bits, expected, expected, expected, expected, expectedSQL);
	}
	
	void testIPv6Wildcarded(String original, int bits, String expectedSubnet, String expectedNormalizedCompressedCanonical, String expectedSQL) {
		String all = expectedNormalizedCompressedCanonical;
		testWildcarded(original, bits, expectedSubnet, all, all, all, expectedSQL);
	}
	
	void testWildcarded(String original, int bits, String expectedSubnet, String expectedNormalized, String expectedCanonical, String expectedCompressed, String expectedSQL) {
		IPAddressString w = createAddress(original);
		IPAddress addr = w.getAddress();
		addr = addr.applyPrefixLength(bits);
		String string = addr.toCompressedWildcardString();
		if(!string.equals(expectedCompressed)) {
			addFailure(new Failure("failed expected: " + expectedCompressed + " actual: " + string, w));
		} else {
			IPAddressString w2 = createAddress(original + '/' + bits);
			IPAddress addr2 = w2.getAddress();
			string = addr2.toCompressedWildcardString();
			if(!string.equals(expectedCompressed)) {
				addFailure(new Failure("failed expected: " + expectedCompressed + " actual: " + string, w));
			} else {
				string = addr.toNormalizedWildcardString();
				if(!string.equals(expectedNormalized)) {
					addFailure(new Failure("failed expected: " + expectedNormalized + " actual: " + string, w));
				} else {
					string = addr2.toNormalizedWildcardString();
					if(!string.equals(expectedNormalized)) {
						addFailure(new Failure("failed expected: " + expectedNormalized + " actual: " + string, w));
					} else {
						string = addr.toCanonicalWildcardString();
						if(!string.equals(expectedCanonical)) {
							addFailure(new Failure("failed expected: " + expectedCanonical + " actual: " + string, w));
						} else {
							string = addr.toSubnetString();
							if(!string.equals(expectedSubnet)) {
								addFailure(new Failure("failed expected: " + expectedSubnet + " actual: " + string, w));
							} else {
								string = addr2.toSubnetString();
								if(!string.equals(expectedSubnet)) {
									addFailure(new Failure("failed expected: " + expectedSubnet + " actual: " + string, w));
								} else {
									string = addr2.toSQLWildcardString();
									if(!string.equals(expectedSQL)) {
										addFailure(new Failure("failed expected: " + expectedSQL + " actual: " + string, w));
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
	
	void testIPv4Strings(String addr, String normalizedString, String normalizedWildcardString, String sqlString, String fullString, String octalString, String hexString, String reverseDNSString, String singleHex, String singleOctal) {
		IPAddressString w = createAddress(addr);
		IPAddress ipAddr = w.getAddress();
		//createList(w);
		testIPv4Strings(w, ipAddr, normalizedString, normalizedWildcardString, sqlString, fullString, octalString, hexString, reverseDNSString, singleHex, singleOctal);
	}
	
	void createList(IPAddressString str) {}
	
	void testIPv6Strings(String addr, 
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
		IPAddressString w = createAddress(addr);
		IPAddress ipAddr = w.getAddress();
		
		//createList(w);
		
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
	
	void testTree(String start, String parents[]) {
		IPAddressString str = createAddress(start, WILDCARD_AND_RANGE_ADDRESS_OPTIONS);
		IPAddressString originaLabelStr = str;
		IPAddressString labelStr = str;
		boolean originalPrefixed = str.isPrefixed();
		if(!originalPrefixed) { 
			IPAddress address = str.getAddress();
			//convert 1.2.3.* to 1.2.3.*/24 which is needed by adjustPrefixBySegment
			address = address.assignPrefixForSingleBlock();
			str = address.toAddressString();
		}
		
		IPAddressString original = str;
		
		int i = 0;
		IPAddressString last;
		do {
			String label = getLabel(labelStr);
			String expected = parents[i];
			if(!label.equals(expected)) {
				addFailure(new Failure("failed expected: " + expected + " actual: " + label, str));
				break;
			}
			last = str;
			labelStr = str = str.adjustPrefixBySegment(false);
			if(labelStr != null) {
				IPAddress labelAddr = labelStr.getAddress();
				if(labelAddr != null) {
					IPAddress subnetAddr = labelAddr.toPrefixBlock(labelAddr.getNetworkPrefixLength());
					if(labelAddr.getNetwork().getPrefixConfiguration().prefixedSubnetsAreExplicit()) {
						if(subnetAddr.isIPv4() && !originalPrefixed) {
							labelStr = subnetAddr.toAddressString();
						}
					} else if(labelAddr.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && !labelAddr.equals(subnetAddr)) {
						//System.out.println("not already a subnet " + labelAddr + " expected: " + subnetAddr);
						addFailure(new Failure("not already a subnet " + labelAddr + " expected: " + subnetAddr, labelAddr));
					}
				}
			}
			i++;
		} while(str != null && last != str);
		
		//now do the same thing but use the IPAddress objects instead
		labelStr = originaLabelStr;
		str = original;
		i = 0;
		do {
			String label = getLabel(labelStr);
			String expected = parents[i];
			if(!label.equals(expected)) {
				addFailure(new Failure("failed expected: " + expected + " actual: " + label, str));
				break;
			}
			IPAddress labelAddr = str.getAddress().adjustPrefixBySegment(false);
			IPAddress subnetAddr = labelAddr.toPrefixBlock(labelAddr.getNetworkPrefixLength());
			if(labelAddr.getNetwork().getPrefixConfiguration().prefixedSubnetsAreExplicit()) {
				if(subnetAddr.isIPv4() && !originalPrefixed) {
					labelAddr = subnetAddr;
				}
			} else if(labelAddr != subnetAddr) {
				//addFailure(new Failure("not already a subnet " + labelAddr + " expected: " + subnetAddr, labelAddr));
			}
			labelStr = str = labelAddr.toAddressString();
			i++;
		} while(str.getNetworkPrefixLength() != 0); //when network prefix is 0, IPAddress.adjustPrefixBySegment() returns the same address
		incrementTestCount();
	}
	
	static String getLabel(IPAddressString addressString) {
		IPAddress address = addressString.getAddress();
		if(address == null) {
			return addressString.toString();
		}
		if(!address.isMultiple()) {
			return address.toPrefixLengthString();
		}
		return address.toSubnetString();
	}
	
	void testTrees() {
		
		testTree("1.2.3.4", new String[] {
				"1.2.3.4",
				"1.2.3.*",
				"1.2.*.*",
				"1.*.*.*",
				"*.*.*.*",
				"*"
		});
		
		testTree("1.2.3.*", new String[] {
				"1.2.3.*",
				"1.2.*.*",
				"1.*.*.*",
				"*.*.*.*",
				"*"
		});
		
		testTree("1.2.*.*", new String[] {
				"1.2.*.*",
				"1.*.*.*",
				"*.*.*.*",
				"*"
		});
		
		testTree("a:b:c:d:e:f:a:b", new String[] {
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a::/112",
				"a:b:c:d:e:f::/96",
				"a:b:c:d:e::/80",
				"a:b:c:d::/64",
				"a:b:c::/48",
				"a:b::/32",
				"a::/16",
				"::/0",
				"*"
		});
		
		boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		
		if(allPrefixesAreSubnets) {
			testTree("1.2.3.4/28", new String[] {
					"1.2.3.0-15",
					"1.2.3.*",
					"1.2.*.*",
					"1.*.*.*",
					"*.*.*.*",
					"*"
			});
			testTree("1.2.3.4/17", new String[] {
					"1.2.0-127.*",
					"1.2.*.*",
					"1.*.*.*",
					"*.*.*.*",
					"*"
			});
			testTree("a:b:c:d:e:f:a:b/97", new String[] {
					"a:b:c:d:e:f::/97",
					"a:b:c:d:e:f::/96",
					"a:b:c:d:e::/80",
					"a:b:c:d::/64",
					"a:b:c::/48",
					"a:b::/32",
					"a::/16",
					"::/0",
					"*"
			});
			testTree("a:b:c:d:e:f:ffff:b/97", new String[] {
					"a:b:c:d:e:f:8000::/97",
					"a:b:c:d:e:f::/96",
					"a:b:c:d:e::/80",
					"a:b:c:d::/64",
					"a:b:c::/48",
					"a:b::/32",
					"a::/16",
					"::/0",
					"*"
			});
			testTree("a:b:c:d:e:f:a:b/96", new String[] {
					"a:b:c:d:e:f::/96",
					"a:b:c:d:e::/80",
					"a:b:c:d::/64",
					"a:b:c::/48",
					"a:b::/32",
					"a::/16",
					"::/0",
					"*"
			});
		} else {
			testTree("1.2.3.4/28", new String[] {
					"1.2.3.4/28",
					"1.2.3.4/24",
					"1.2.0.4/16",
					"1.0.0.4/8",
					"0.0.0.4/0"
			});
			testTree("1.2.3.4/17", new String[] {
					"1.2.3.4/17",
					"1.2.3.4/16",
					"1.0.3.4/8",
					"0.0.3.4/0"
			});
			testTree("a:b:c:d:e:f:a:b/97", new String[] {
					"a:b:c:d:e:f:a:b/97",
					"a:b:c:d:e:f:a:b/96",
					"a:b:c:d:e::a:b/80",
					"a:b:c:d::a:b/64",
					"a:b:c::a:b/48",
					"a:b::a:b/32",
					"a::a:b/16",
					"::a:b/0"
			});
			testTree("a:b:c:d:e:f:ffff:b/97", new String[] {
					"a:b:c:d:e:f:ffff:b/97",
					"a:b:c:d:e:f:7fff:b/96",
					"a:b:c:d:e::7fff:b/80",
					"a:b:c:d::7fff:b/64",
					"a:b:c::7fff:b/48",
					"a:b::7fff:b/32",
					"a::7fff:b/16",
					"::7fff:b/0"
			});
			testTree("a:b:c:d:e:f:a:b/96", new String[] {
					"a:b:c:d:e:f:a:b/96",
					"a:b:c:d:e::a:b/80",
					"a:b:c:d::a:b/64",
					"a:b:c::a:b/48",
					"a:b::a:b/32",
					"a::a:b/16",
					"::a:b/0",
			});
		}
		
		testTree("a:b:c:d::a:b", new String[] {
				"a:b:c:d::a:b",
				"a:b:c:d:0:0:a::/112",
				"a:b:c:d::/96",
				"a:b:c:d::/80",
				"a:b:c:d::/64",
				"a:b:c::/48",
				"a:b::/32",
				"a::/16",
				"::/0",
				"*"
		});
		testTree("::c:d:e:f:a:b", new String[] {
				"::c:d:e:f:a:b",
				"0:0:c:d:e:f:a::/112",
				"0:0:c:d:e:f::/96",
				"0:0:c:d:e::/80",
				"0:0:c:d::/64",
				"0:0:c::/48",
				"::/32",
				"::/16",
				"::/0",
				"*"
		});
	}
	
	//each ipv4 failure is 6, each ipv6 is 10, current total is 520

	void testStrings() {
		boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		
		testIPv4Strings("1.2.3.4", "1.2.3.4", "1.2.3.4", "1.2.3.4", "001.002.003.004", "01.02.03.04", "0x1.0x2.0x3.0x4", "4.3.2.1.in-addr.arpa", "0x01020304", "000100401404");
		if(allPrefixesAreSubnets) {
			testIPv4Strings("1.2.3.4/16", "1.2.0.0/16", "1.2.*.*", "1.2.%.%", "001.002.000.000/16", "01.02.00.00/16", "0x1.0x2.0x0.0x0/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
		} else {
			testIPv4Strings("1.2.3.4/16", "1.2.3.4/16", "1.2.3.4", "1.2.3.4", "001.002.003.004/16", "01.02.03.04/16", "0x1.0x2.0x3.0x4/16", "4.3.2.1.in-addr.arpa", "0x01020304", "000100401404");
		}
		testIPv4Strings("1.2.*.*", "1.2.*.*", "1.2.*.*", "1.2.%.%", "001.002.000-255.000-255", "01.02.*.*", "0x1.0x2.*.*", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");//note that wildcards are never converted to CIDR.
		testIPv4Strings("1.2.*", "1.2.*.*", "1.2.*.*", "1.2.%.%", "001.002.000-255.000-255", "01.02.*.*", "0x1.0x2.*.*", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
		if(isNoAutoSubnets) {
			testIPv4Strings("1.2.*.*/16", "1.2.*.*/16", "1.2.*.*", "1.2.%.%", "001.002.000-255.000-255/16", "01.02.*.*/16", "0x1.0x2.*.*/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.2.*/16", "1.2.*.*/16", "1.2.*.*", "1.2.%.%", "001.002.000-255.000-255/16", "01.02.*.*/16", "0x1.0x2.*.*/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.*.*/16",  "1.*.*.*/16", "1.*.*.*", "1.%.%.%", "001.000-255.000-255.000-255/16",  "01.*.*.*/16",  "0x1.*.*.*/16", "*.*.*.1.in-addr.arpa", "0x01000000-0x01ffffff", "000100000000-000177777777");
		} else {
			testIPv4Strings("1.2.*.*/16", "1.2.0.0/16", "1.2.*.*", "1.2.%.%", "001.002.000.000/16", "01.02.00.00/16", "0x1.0x2.0x0.0x0/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.2.*/16", "1.2.0.0/16", "1.2.*.*", "1.2.%.%", "001.002.000.000/16", "01.02.00.00/16", "0x1.0x2.0x0.0x0/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.*.*/16",  "1.*.0.0/16", "1.*.*.*", "1.%.%.%", "001.000-255.000.000/16",  "01.*.00.00/16",  "0x1.*.0x0.0x0/16", "*.*.*.1.in-addr.arpa", "0x01000000-0x01ffffff", "000100000000-000177777777");
		}
		testIPv4Strings("0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "000.000.000.000", "00.00.00.00", "0x0.0x0.0x0.0x0", "0.0.0.0.in-addr.arpa", "0x00000000", "000000000000");
		testIPv4Strings("9.63.127.254", "9.63.127.254", "9.63.127.254", "9.63.127.254", "009.063.127.254", "011.077.0177.0376", "0x9.0x3f.0x7f.0xfe", "254.127.63.9.in-addr.arpa", "0x093f7ffe", "001117677776");
		if(allPrefixesAreSubnets) {
			testIPv4Strings("9.63.127.254/16", "9.63.0.0/16", "9.63.*.*", "9.63.%.%", "009.063.000.000/16", "011.077.00.00/16", "0x9.0x3f.0x0.0x0/16", "*.*.63.9.in-addr.arpa", "0x093f0000-0x093fffff", "001117600000-001117777777");
		} else {
			testIPv4Strings("9.63.127.254/16", "9.63.127.254/16", "9.63.127.254", "9.63.127.254", "009.063.127.254/16", "011.077.0177.0376/16", "0x9.0x3f.0x7f.0xfe/16", "254.127.63.9.in-addr.arpa", "0x093f7ffe", "001117677776");
		}
		testIPv4Strings("9.63.*.*", "9.63.*.*", "9.63.*.*", "9.63.%.%", "009.063.000-255.000-255", "011.077.*.*", "0x9.0x3f.*.*", "*.*.63.9.in-addr.arpa", "0x093f0000-0x093fffff", "001117600000-001117777777");//note that wildcards are never converted to CIDR.
		testIPv4Strings("9.63.*", "9.63.*.*", "9.63.*.*", "9.63.%.%", "009.063.000-255.000-255", "011.077.*.*", "0x9.0x3f.*.*", "*.*.63.9.in-addr.arpa", "0x093f0000-0x093fffff", "001117600000-001117777777");
		if(isNoAutoSubnets) {
			testIPv4Strings("9.63.*.*/16", "9.63.*.*/16", "9.63.*.*", "9.63.%.%", "009.063.000-255.000-255/16", "011.077.*.*/16", "0x9.0x3f.*.*/16", "*.*.63.9.in-addr.arpa", "0x093f0000-0x093fffff", "001117600000-001117777777");
			testIPv4Strings("9.63.*/16", "9.63.*.*/16", "9.63.*.*", "9.63.%.%", "009.063.000-255.000-255/16", "011.077.*.*/16", "0x9.0x3f.*.*/16", "*.*.63.9.in-addr.arpa", "0x093f0000-0x093fffff", "001117600000-001117777777");
			testIPv4Strings("9.*.*/16",  "9.*.*.*/16", "9.*.*.*", "9.%.%.%", "009.000-255.000-255.000-255/16", "011.*.*.*/16", "0x9.*.*.*/16", "*.*.*.9.in-addr.arpa", "0x09000000-0x09ffffff", "001100000000-001177777777"); 
		} else {
			testIPv4Strings("9.63.*.*/16", "9.63.0.0/16", "9.63.*.*", "9.63.%.%", "009.063.000.000/16", "011.077.00.00/16", "0x9.0x3f.0x0.0x0/16", "*.*.63.9.in-addr.arpa", "0x093f0000-0x093fffff", "001117600000-001117777777");
			testIPv4Strings("9.63.*/16", "9.63.0.0/16", "9.63.*.*", "9.63.%.%", "009.063.000.000/16", "011.077.00.00/16", "0x9.0x3f.0x0.0x0/16", "*.*.63.9.in-addr.arpa", "0x093f0000-0x093fffff", "001117600000-001117777777");
			testIPv4Strings("9.*.*/16",  "9.*.0.0/16", "9.*.*.*", "9.%.%.%", "009.000-255.000.000/16", "011.*.00.00/16", "0x9.*.0x0.0x0/16", "*.*.*.9.in-addr.arpa", "0x09000000-0x09ffffff", "001100000000-001177777777"); 
		}
		testIPv4Strings("1.2.3.250-255", "1.2.3.250-255", "1.2.3.250-255", "1.2.3.25_", "001.002.003.250-255", "01.02.03.0372-0377", "0x1.0x2.0x3.0xfa-0xff", "250-255.3.2.1.in-addr.arpa", "0x010203fa-0x010203ff", "000100401772-000100401777");
		testIPv4Strings("1.2.3.200-255", "1.2.3.200-255", "1.2.3.200-255", "1.2.3.2__", "001.002.003.200-255", "01.02.03.0310-0377", "0x1.0x2.0x3.0xc8-0xff", "200-255.3.2.1.in-addr.arpa", "0x010203c8-0x010203ff", "000100401710-000100401777");
		testIPv4Strings("1.2.3.100-199", "1.2.3.100-199", "1.2.3.100-199", "1.2.3.1__", "001.002.003.100-199", "01.02.03.0144-0307", "0x1.0x2.0x3.0x64-0xc7", "100-199.3.2.1.in-addr.arpa", "0x01020364-0x010203c7", "000100401544-000100401707");
		testIPv4Strings("100-199.2.3.100-199", "100-199.2.3.100-199", "100-199.2.3.100-199", "1__.2.3.1__", "100-199.002.003.100-199", "0144-0307.02.03.0144-0307", "0x64-0xc7.0x2.0x3.0x64-0xc7", "100-199.3.2.100-199.in-addr.arpa", null, null);
		testIPv4Strings("100-199.2.3.100-198", "100-199.2.3.100-198", "100-199.2.3.100-198", "1__.2.3.100-198", "100-199.002.003.100-198", "0144-0307.02.03.0144-0306", "0x64-0xc7.0x2.0x3.0x64-0xc6", "100-198.3.2.100-199.in-addr.arpa", null, null);
		testIPv4Strings("1.2.3.0-99", "1.2.3.0-99", "1.2.3.0-99", "1.2.3.0-99", "001.002.003.000-099", "01.02.03.00-0143", "0x1.0x2.0x3.0x0-0x63", "0-99.3.2.1.in-addr.arpa", "0x01020300-0x01020363", "000100401400-000100401543");
		testIPv4Strings("1.2.3.100-155", "1.2.3.100-155", "1.2.3.100-155", "1.2.3.100-155", "001.002.003.100-155", "01.02.03.0144-0233", "0x1.0x2.0x3.0x64-0x9b", "100-155.3.2.1.in-addr.arpa", "0x01020364-0x0102039b", "000100401544-000100401633");
		testIPv4Strings("1.2.3.100-255", "1.2.3.100-255", "1.2.3.100-255", "1.2.3.100-255", "001.002.003.100-255", "01.02.03.0144-0377", "0x1.0x2.0x3.0x64-0xff", "100-255.3.2.1.in-addr.arpa", "0x01020364-0x010203ff", "000100401544-000100401777");
		if(allPrefixesAreSubnets) {
			testIPv4Strings("1.129-254.5.5/12", "1.128-240.0.0/12", "1.128-255.*.*", "1.128-255.%.%", "001.128-240.000.000/12", "01.0200-0360.00.00/12", "0x1.0x80-0xf0.0x0.0x0/12", "*.*.128-255.1.in-addr.arpa", "0x01800000-0x01ffffff", "000140000000-000177777777");
			testIPv4Strings("1.2__.5.5/14", "1.200-252.0.0/14", "1.200-255.*.*", "1.2__.%.%", "001.200-252.000.000/14", "01.0310-0374.00.00/14", "0x1.0xc8-0xfc.0x0.0x0/14", "*.*.200-255.1.in-addr.arpa", "0x01c80000-0x01ffffff", "000162000000-000177777777");
			testIPv4Strings("1.*.5.5/12", "1.0-240.0.0/12", "1.*.*.*", "1.%.%.%", "001.000-240.000.000/12", "01.00-0360.00.00/12", "0x1.0x0-0xf0.0x0.0x0/12", "*.*.*.1.in-addr.arpa", "0x01000000-0x01ffffff", "000100000000-000177777777");
		} else {
			testIPv4Strings("1.129-254.5.5/12", "1.129-254.5.5/12", "1.129-254.5.5", "1.129-254.5.5", "001.129-254.005.005/12", "01.0201-0376.05.05/12", "0x1.0x81-0xfe.0x5.0x5/12", "5.5.129-254.1.in-addr.arpa", null, null);
			testIPv4Strings("1.2__.5.5/14", "1.200-255.5.5/14", "1.200-255.5.5", "1.2__.5.5", "001.200-255.005.005/14", "01.0310-0377.05.05/14", "0x1.0xc8-0xff.0x5.0x5/14", "5.5.200-255.1.in-addr.arpa", null, null);
			testIPv4Strings("1.*.5.5/12", "1.*.5.5/12", "1.*.5.5", "1.%.5.5", "001.000-255.005.005/12", "01.*.05.05/12", "0x1.*.0x5.0x5/12", "5.5.*.1.in-addr.arpa", null, null);
			//OK we are testing 01.*.02405/12 and our bounds check for inet_aton does not work because later when creating address it is not treated as inet_aton due to the *
			//so when we do the bounds checking for inet_aton we need to check for * and only test with single segment boundaries
			//also check for that setting where * extends beyong single segment
		}

		testIPv6Strings("::",
				"0:0:0:0:0:0:0:0",
				"0:0:0:0:0:0:0:0",
				"::",
				"0:0:0:0:0:0:0:0",
				"0000:0000:0000:0000:0000:0000:0000:0000",
				"::",
				"::",
				"::",
				"::",
				"::0.0.0.0",
				"::",
				"::",
				"::",
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"0-0-0-0-0-0-0-0.ipv6-literal.net",
				"00000000000000000000",
				"0x00000000000000000000000000000000",
				"00000000000000000000000000000000000000000000");
		
		testIPv6Strings("::2",
				"0:0:0:0:0:0:0:2",
				"0:0:0:0:0:0:0:2",
				"::2",
				"0:0:0:0:0:0:0:2",
				"0000:0000:0000:0000:0000:0000:0000:0002",
				"::2",
				"::2",
				"::2",
				"::2",
				"::0.0.0.2",
				"::0.0.0.2",
				"::0.0.0.2",
				"::0.0.0.2",
				"2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"0-0-0-0-0-0-0-2.ipv6-literal.net",
				"00000000000000000002",
				"0x00000000000000000000000000000002",
				"00000000000000000000000000000000000000000002");
		
		testIPv6Strings("::7fff:ffff:ffff:ffff",
				"0:0:0:0:7fff:ffff:ffff:ffff",
				"0:0:0:0:7fff:ffff:ffff:ffff",
				"::7fff:ffff:ffff:ffff",
				"0:0:0:0:7fff:ffff:ffff:ffff",
				"0000:0000:0000:0000:7fff:ffff:ffff:ffff",
				"::7fff:ffff:ffff:ffff",
				"::7fff:ffff:ffff:ffff",
				"::7fff:ffff:ffff:ffff",
				"::7fff:ffff:ffff:ffff",
				"::7fff:ffff:255.255.255.255",
				"::7fff:ffff:255.255.255.255",
				"::7fff:ffff:255.255.255.255",
				"::7fff:ffff:255.255.255.255",
				"f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"0-0-0-0-7fff-ffff-ffff-ffff.ipv6-literal.net",
				"0000000000d*-h_{Y}sg",
				"0x00000000000000007fffffffffffffff",
				"00000000000000000000000777777777777777777777");
		
		testIPv6Strings("0:0:0:1::",
				"0:0:0:1:0:0:0:0",
				"0:0:0:1:0:0:0:0",
				"0:0:0:1::",
				"0:0:0:1:0:0:0:0",
				"0000:0000:0000:0001:0000:0000:0000:0000",
				"0:0:0:1::",
				"0:0:0:1::",
				"0:0:0:1::",
				"0:0:0:1::",
				"::1:0:0:0.0.0.0",
				"0:0:0:1::",
				"0:0:0:1::",
				"0:0:0:1::",
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"0-0-0-1-0-0-0-0.ipv6-literal.net",
				"0000000000_sw2=@*|O1",
				"0x00000000000000010000000000000000",
				"00000000000000000000002000000000000000000000");
		
		testIPv6Strings("::8fff:ffff:ffff:ffff",
				"0:0:0:0:8fff:ffff:ffff:ffff",
				"0:0:0:0:8fff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff",
				"0:0:0:0:8fff:ffff:ffff:ffff",
				"0000:0000:0000:0000:8fff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff",
				"::8fff:ffff:255.255.255.255",
				"::8fff:ffff:255.255.255.255",
				"::8fff:ffff:255.255.255.255",
				"::8fff:ffff:255.255.255.255",
				"f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"0-0-0-0-8fff-ffff-ffff-ffff.ipv6-literal.net",
				"0000000000i(`c)xypow",
				"0x00000000000000008fffffffffffffff",
				"00000000000000000000001077777777777777777777");
		
		testIPv6Strings("::8fff:ffff:ffff:ffff:ffff",
				"0:0:0:8fff:ffff:ffff:ffff:ffff",
				"0:0:0:8fff:ffff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff:ffff",
				"0:0:0:8fff:ffff:ffff:ffff:ffff",
				"0000:0000:0000:8fff:ffff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:ffff:ffff",
				"::8fff:ffff:ffff:255.255.255.255",
				"::8fff:ffff:ffff:255.255.255.255",
				"::8fff:ffff:ffff:255.255.255.255",
				"::8fff:ffff:ffff:255.255.255.255",
				"f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.8.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"0-0-0-8fff-ffff-ffff-ffff-ffff.ipv6-literal.net",
				"00000004&U-n{rbbza$w",
				"0x0000000000008fffffffffffffffffff",
				"00000000000000000217777777777777777777777777");
		
		testIPv6Strings("a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a:b",
				"000a:000b:000c:000d:000e:000f:000a:000b",
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:a:b",
				"a:b:c:d:e:f:0.10.0.11",
				"a:b:c:d:e:f:0.10.0.11",
				"a:b:c:d:e:f:0.10.0.11",
				"a:b:c:d:e:f:0.10.0.11",
				"b.0.0.0.a.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
				"a-b-c-d-e-f-a-b.ipv6-literal.net",
				"00|N0s0$ND2DCD&%D3QB",
				"0x000a000b000c000d000e000f000a000b",
				"00000240001300006000032000160000740002400013");
		
		if(allPrefixesAreSubnets) {
			testIPv6Strings("a:b:c:d:e:f:a:b/64",
					"a:b:c:d:0:0:0:0/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:%:%:%:%",
					"000a:000b:000c:000d:0000:0000:0000:0000/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-0-0-0-0.ipv6-literal.net/64",
					"00|N0s0$ND2BxK96%Chk/64",
					"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
					"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
			
			testIPv6Strings("::c:d:e:f:a:b/64",
					"0:0:c:d:0:0:0:0/64",
					"0:0:c:d:*:*:*:*",
					"::c:d:*:*:*:*",
					"0:0:c:d:%:%:%:%",
					"0000:0000:000c:000d:0000:0000:0000:0000/64",
					"0:0:c:d::/64",
					"0:0:c:d::/64",
					"0:0:c:d::/64",
					"::c:d:*:*:*:*",
					"::c:d:0:0:0.0.0.0/64",
					"::c:d:0:0:0.0.0.0/64",
					"0:0:c:d::/64",
					"0:0:c:d::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
					"0-0-c-d-0-0-0-0.ipv6-literal.net/64",
					"0000001G~Ie?xF;x&)@P/64",
					"0x00000000000c000d0000000000000000-0x00000000000c000dffffffffffffffff",
					"00000000000000006000032000000000000000000000-00000000000000006000033777777777777777777777");
		} else {
			testIPv6Strings("a:b:c:d:e:f:a:b/64",
					"a:b:c:d:e:f:a:b/64",
					"a:b:c:d:e:f:a:b",
					"a:b:c:d:e:f:a:b",
					"a:b:c:d:e:f:a:b",
					"000a:000b:000c:000d:000e:000f:000a:000b/64",
					"a:b:c:d:e:f:a:b/64",
					"a:b:c:d:e:f:a:b/64",
					"a:b:c:d:e:f:a:b/64",
					"a:b:c:d:e:f:a:b",
					"a:b:c:d:e:f:0.10.0.11/64",
					"a:b:c:d:e:f:0.10.0.11/64",
					"a:b:c:d:e:f:0.10.0.11/64",
					"a:b:c:d:e:f:0.10.0.11/64",
					"b.0.0.0.a.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-e-f-a-b.ipv6-literal.net/64",
					"00|N0s0$ND2DCD&%D3QB/64",
					"0x000a000b000c000d000e000f000a000b",
					"00000240001300006000032000160000740002400013");
			testIPv6Strings("::c:d:e:f:a:b/64",
					"0:0:c:d:e:f:a:b/64",
					"0:0:c:d:e:f:a:b",
					"::c:d:e:f:a:b",
					"0:0:c:d:e:f:a:b",
					"0000:0000:000c:000d:000e:000f:000a:000b/64",
					"::c:d:e:f:a:b/64",
					"::c:d:e:f:a:b/64",
					"::c:d:e:f:a:b/64",
					"::c:d:e:f:a:b",
					"::c:d:e:f:0.10.0.11/64",
					"::c:d:e:f:0.10.0.11/64",
					"::c:d:e:f:0.10.0.11/64",
					"::c:d:e:f:0.10.0.11/64",
					"b.0.0.0.a.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
					"0-0-c-d-e-f-a-b.ipv6-literal.net/64",
					"0000001G~Ie^C9jXExx>/64",
					"0x00000000000c000d000e000f000a000b",
					"00000000000000006000032000160000740002400013");
		}

		testIPv6Strings("::c:d:e:f:a:b",
				"0:0:c:d:e:f:a:b",
				"0:0:c:d:e:f:a:b",
				"::c:d:e:f:a:b",
				"0:0:c:d:e:f:a:b",
				"0000:0000:000c:000d:000e:000f:000a:000b",
				"::c:d:e:f:a:b",
				"::c:d:e:f:a:b",
				"::c:d:e:f:a:b",
				"::c:d:e:f:a:b",
				"::c:d:e:f:0.10.0.11",
				"::c:d:e:f:0.10.0.11",
				"::c:d:e:f:0.10.0.11",
				"::c:d:e:f:0.10.0.11",
				"b.0.0.0.a.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
				"0-0-c-d-e-f-a-b.ipv6-literal.net",
				"0000001G~Ie^C9jXExx>",
				"0x00000000000c000d000e000f000a000b",
				"00000000000000006000032000160000740002400013");
		
		testIPv6Strings("a:b:c:d::",
				"a:b:c:d:0:0:0:0",
				"a:b:c:d:0:0:0:0",
				"a:b:c:d::",
				"a:b:c:d:0:0:0:0",
				"000a:000b:000c:000d:0000:0000:0000:0000",
				"a:b:c:d::",
				"a:b:c:d::",
				"a:b:c:d::",
				"a:b:c:d::",
				"a:b:c:d::0.0.0.0",
				"a:b:c:d::",
				"a:b:c:d::",
				"a:b:c:d::",
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
				"a-b-c-d-0-0-0-0.ipv6-literal.net",
				"00|N0s0$ND2BxK96%Chk",
				"0x000a000b000c000d0000000000000000",
				"00000240001300006000032000000000000000000000");
		
		if(isNoAutoSubnets) {
			testIPv6Strings("a:b:c:d::/64",
				"a:b:c:d:0:0:0:0/64",
				"a:b:c:d:0:0:0:0",
				"a:b:c:d::",
				"a:b:c:d:0:0:0:0",
				"000a:000b:000c:000d:0000:0000:0000:0000/64",
				"a:b:c:d::/64",
				"a:b:c:d::/64",
				"a:b:c:d::/64",
				"a:b:c:d::",
				"a:b:c:d::0.0.0.0/64",
				"a:b:c:d::0.0.0.0/64",
				"a:b:c:d::/64",
				"a:b:c:d::/64",
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
				"a-b-c-d-0-0-0-0.ipv6-literal.net/64",
				"00|N0s0$ND2BxK96%Chk/64",
				"0x000a000b000c000d0000000000000000",
				"00000240001300006000032000000000000000000000");
		} else {
			testIPv6Strings("a:b:c:d::/64",
				"a:b:c:d:0:0:0:0/64",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:%:%:%:%",
				"000a:000b:000c:000d:0000:0000:0000:0000/64",
				"a:b:c:d::/64",
				"a:b:c:d::/64",
				"a:b:c:d::/64",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d::0.0.0.0/64",
				"a:b:c:d::0.0.0.0/64",
				"a:b:c:d::/64",
				"a:b:c:d::/64",
				"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
				"a-b-c-d-0-0-0-0.ipv6-literal.net/64",
				"00|N0s0$ND2BxK96%Chk/64",
				"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
				"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
		}
		if(allPrefixesAreSubnets) {
			testIPv6Strings("a::d:*:*:*:*/65",
					"a:0:0:d:0-8000:0:0:0/65",
					"a:0:0:d:*:*:*:*",
					"a::d:*:*:*:*",
					"a:0:0:d:%:%:%:%",
					"000a:0000:0000:000d:0000-8000:0000:0000:0000/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"a::d:*:*:*:*",
					"a::d:0-8000:0:0.0.0.0/65",
					"a::d:0-8000:0:0.0.0.0/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-0" + Address.ALTERNATIVE_RANGE_SEPARATOR + "8000-0-0-0.ipv6-literal.net/65",
					"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt+;M72aZe}L&/65",
					"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
					"00000240000000000000032000000000000000000000-00000240000000000000033777777777777777777777");
			
			testIPv6Strings("a::d:*:0:0:0/65",
					"a:0:0:d:0-8000:0:0:0/65",
					"a:0:0:d:*:*:*:*",
					"a::d:*:*:*:*",
					"a:0:0:d:%:%:%:%",
					"000a:0000:0000:000d:0000-8000:0000:0000:0000/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"a::d:*:*:*:*",
					"a::d:0-8000:0:0.0.0.0/65",
					"a::d:0-8000:0:0.0.0.0/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-0" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "8000-0-0-0.ipv6-literal.net/65",
					"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt+;M72aZe}L&/65",
					"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
					"00000240000000000000032000000000000000000000-00000240000000000000033777777777777777777777");
			
			testIPv6Strings("a:b:c:d:*::/64",
					"a:b:c:d:0:0:0:0/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:%:%:%:%",
					"000a:000b:000c:000d:0000:0000:0000:0000/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-0-0-0-0.ipv6-literal.net/64",
					"00|N0s0$ND2BxK96%Chk/64",
					"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
					"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
		} else {
			if(isNoAutoSubnets) {
				testIPv6Strings("a::d:*:*:*:*/65", 
						"a:0:0:d:*:*:*:*/65",
						"a:0:0:d:*:*:*:*",
						"a::d:*:*:*:*",
						"a:0:0:d:%:%:%:%",
						"000a:0000:0000:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff/65",
						"a::d:*:*:*:*/65",
						"a::d:*:*:*:*/65",
						"a::d:*:*:*:*/65",
						"a::d:*:*:*:*",
						"a::d:*:*:*.*.*.*/65",
						"a::d:*:*:*.*.*.*/65",
						"a::d:*:*:*.*.*.*/65",
						"a::d:*:*:*.*.*.*/65",
						"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
						"a-0-0-d-*-*-*-*.ipv6-literal.net/65",
						"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt-R6^kVV>{?N/65",
						"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
						"00000240000000000000032000000000000000000000-00000240000000000000033777777777777777777777");
				
				testIPv6Strings("a::d:0:*:*:*/65",
						"a:0:0:d:0:*:*:*/65",
						"a:0:0:d:0:*:*:*",
						"a::d:0:*:*:*",
						"a:0:0:d:0:%:%:%",
						"000a:0000:0000:000d:0000:0000-ffff:0000-ffff:0000-ffff/65",
						"a::d:0:*:*:*/65",
						"a::d:0:*:*:*/65",
						"a:0:0:d::*:*:*/65",
						"a::d:0:*:*:*",
						"a::d:0:*:*.*.*.*/65",
						"a::d:0:*:*.*.*.*/65",
						"a::d:0:*:*.*.*.*/65",
						"a::d:0:*:*.*.*.*/65",
						"*.*.*.*.*.*.*.*.*.*.*.*.0.0.0.0.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
						"a-0-0-d-0-*-*-*.ipv6-literal.net/65",
						"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt+WbTO)+bn+N/65",
						"0x000a00000000000d0000000000000000-0x000a00000000000d0000ffffffffffff",
						"00000240000000000000032000000000000000000000-00000240000000000000032000007777777777777777");
			} else {
				testIPv6Strings("a::d:*:*:*:*/65", 
					"a:0:0:d:0-8000:0:0:0/65",
					"a:0:0:d:*:*:*:*",
					"a::d:*:*:*:*",
					"a:0:0:d:%:%:%:%",
					"000a:0000:0000:000d:0000-8000:0000:0000:0000/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"a::d:*:*:*:*",
					"a::d:0-8000:0:0.0.0.0/65",
					"a::d:0-8000:0:0.0.0.0/65",
					"a:0:0:d:0-8000::/65",
					"a:0:0:d:0-8000::/65",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-0" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "8000-0-0-0.ipv6-literal.net/65",
					"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt+;M72aZe}L&/65",
					"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
					"00000240000000000000032000000000000000000000-00000240000000000000033777777777777777777777");
			
				testIPv6Strings("a::d:0:*:*:*/65",
					"a:0:0:d:0:0:0:0/65",
					"a:0:0:d:0-7fff:*:*:*",
					"a::d:0-7fff:*:*:*",
					"a:0:0:d:0-7fff:%:%:%",
					"000a:0000:0000:000d:0000:0000:0000:0000/65",
					"a:0:0:d::/65",
					"a:0:0:d::/65",
					"a:0:0:d::/65",
					"a::d:0-7fff:*:*:*",
					"a::d:0:0:0.0.0.0/65",
					"a::d:0:0:0.0.0.0/65",
					"a:0:0:d::/65",
					"a:0:0:d::/65",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.0-7.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-0-0-0-0.ipv6-literal.net/65",
					"00|M>t|tt+WbKhfd5~qN/65",
					"0x000a00000000000d0000000000000000-0x000a00000000000d7fffffffffffffff",
					"00000240000000000000032000000000000000000000-00000240000000000000032777777777777777777777");
			}
			
			testIPv6Strings("a::d:*:*:*:0/65",
					"a:0:0:d:*:*:*:0/65",
					"a:0:0:d:*:*:*:0",
					"a::d:*:*:*:0",
					"a:0:0:d:%:%:%:0",
					"000a:0000:0000:000d:0000-ffff:0000-ffff:0000-ffff:0000/65",
					"a::d:*:*:*:0/65",
					"a::d:*:*:*:0/65",
					"a:0:0:d:*:*:*::/65",
					"a::d:*:*:*:0",
					"a::d:*:*:*.*.0.0/65",
					"a::d:*:*:*.*.0.0/65",
					"a::d:*:*:*.*.0.0/65",
					"a::d:*:*:*.*.0.0/65",
					"0.0.0.0.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-*-*-*-0.ipv6-literal.net/65",
					null,
					null,
					null);
			
			
			testIPv6Strings("a::d:0:*:0:*/65",
					"a:0:0:d:0:*:0:*/65",
					"a:0:0:d:0:*:0:*",
					"a::d:0:*:0:*",
					"a:0:0:d:0:%:0:%",
					"000a:0000:0000:000d:0000:0000-ffff:0000:0000-ffff/65",
					"a::d:0:*:0:*/65",
					"a::d:0:*:0:*/65",
					"a:0:0:d:0:*::*/65",
					"a::d:0:*:0:*",
					"a::d:0:*:0.0.*.*/65",
					"a::d:0:*:0.0.*.*/65",
					"a::d:0:*:0.0.*.*/65",
					"a::d:0:*:0.0.*.*/65",
					"*.*.*.*.0.0.0.0.*.*.*.*.0.0.0.0.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-0-*-0-*.ipv6-literal.net/65",
					null,
					null,
					null);
			
			testIPv6Strings("a::d:*:0:0:0/65",
					"a:0:0:d:*:0:0:0/65",
					"a:0:0:d:*:0:0:0",
					"a:0:0:d:*::",
					"a:0:0:d:%:0:0:0",
					"000a:0000:0000:000d:0000-ffff:0000:0000:0000/65",
					"a:0:0:d:*::/65",
					"a:0:0:d:*::/65",
					"a:0:0:d:*::/65",
					"a:0:0:d:*::",
					"a::d:*:0:0.0.0.0/65",
					"a::d:*:0:0.0.0.0/65",
					"a:0:0:d:*::/65",
					"a:0:0:d:*::/65",
					"0.0.0.0.0.0.0.0.0.0.0.0.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-*-0-0-0.ipv6-literal.net/65",
					null,
					null,
					null);
			
			testIPv6Strings("a:b:c:d:*::/64",
					"a:b:c:d:*:0:0:0/64",
					"a:b:c:d:*:0:0:0",
					"a:b:c:d:*::",
					"a:b:c:d:%:0:0:0",
					"000a:000b:000c:000d:0000-ffff:0000:0000:0000/64",
					"a:b:c:d:*::/64",
					"a:b:c:d:*::/64",
					"a:b:c:d:*::/64",
					"a:b:c:d:*::",
					"a:b:c:d:*::0.0.0.0/64",
					"a:b:c:d:*::0.0.0.0/64",
					"a:b:c:d:*::/64",
					"a:b:c:d:*::/64",
					"0.0.0.0.0.0.0.0.0.0.0.0.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-*-0-0-0.ipv6-literal.net/64",
					null,
					null,
					null);
		}
		if(isNoAutoSubnets) {
			
			testIPv6Strings("a:b:c:*::/64",
					"a:b:c:*:0:0:0:0/64",
					"a:b:c:*:0:0:0:0",
					"a:b:c:*::",
					"a:b:c:%:0:0:0:0",
					"000a:000b:000c:0000-ffff:0000:0000:0000:0000/64",
					"a:b:c:*::/64",
					"a:b:c:*::/64",
					"a:b:c:*::/64",
					"a:b:c:*::",
					"a:b:c:*::0.0.0.0/64",
					"a:b:c:*::0.0.0.0/64",
					"a:b:c:*::/64",
					"a:b:c:*::/64",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.*.*.*.*.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-*-0-0-0-0.ipv6-literal.net/64",
					null,
					null,
					null);
			
			testIPv6Strings("a::/64",
					"a:0:0:0:0:0:0:0/64",
					"a:0:0:0:0:0:0:0",
					"a::",
					"a:0:0:0:0:0:0:0",
					"000a:0000:0000:0000:0000:0000:0000:0000/64",
					"a::/64",
					"a::/64",
					"a::/64",
					"a::",
					"a::0.0.0.0/64",
					"a::0.0.0.0/64",
					"a::/64",
					"a::/64",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-0-0-0-0-0.ipv6-literal.net/64",
					"00|M>t|ttwH6V62lVY`A/64",
					"0x000a0000000000000000000000000000",
					"00000240000000000000000000000000000000000000");
			
			testIPv6Strings("a:0:0:d:e:f:0:0/112",
					"a:0:0:d:e:f:0:0/112",
					"a:0:0:d:e:f:0:0",
					"a::d:e:f:0:0",
					"a:0:0:d:e:f:0:0",
					"000a:0000:0000:000d:000e:000f:0000:0000/112",
					"a::d:e:f:0:0/112",
					"a::d:e:f:0:0/112",
					"a:0:0:d:e:f::/112",
					"a::d:e:f:0:0",
					"a::d:e:f:0.0.0.0/112",
					"a::d:e:f:0.0.0.0/112",
					"a::d:e:f:0.0.0.0/112",
					"a:0:0:d:e:f::/112",
					"0.0.0.0.0.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-e-f-0-0.ipv6-literal.net/112",
					"00|M>t|tt+WcwbECb*xq/112",
					"0x000a00000000000d000e000f00000000",
					"00000240000000000000032000160000740000000000");
			
			testIPv6Strings("a:0:c:d:e:f:0:0/112",
					"a:0:c:d:e:f:0:0/112",			
					"a:0:c:d:e:f:0:0",
					"a:0:c:d:e:f::",
					"a:0:c:d:e:f:0:0",
					"000a:0000:000c:000d:000e:000f:0000:0000/112",
					"a:0:c:d:e:f::/112",
					"a:0:c:d:e:f::/112",
					"a:0:c:d:e:f::/112",
					"a:0:c:d:e:f::",
					"a::c:d:e:f:0.0.0.0/112",
					"a::c:d:e:f:0.0.0.0/112",
					"a::c:d:e:f:0.0.0.0/112",
					"a:0:c:d:e:f::/112",
					"0.0.0.0.0.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-0-0.ipv6-literal.net/112",
					"00|M>t};s?v~hFl`j3_$/112",
					"0x000a0000000c000d000e000f00000000",
					"00000240000000006000032000160000740000000000");
		
			testIPv6Strings("a:0:c:d:e:f:0:0/97",
					"a:0:c:d:e:f:0:0/97",		
					"a:0:c:d:e:f:0:0",
					"a:0:c:d:e:f::",
					"a:0:c:d:e:f:0:0",
					"000a:0000:000c:000d:000e:000f:0000:0000/97",
					"a:0:c:d:e:f::/97",
					"a:0:c:d:e:f::/97",
					"a:0:c:d:e:f::/97",
					"a:0:c:d:e:f::",
					"a::c:d:e:f:0.0.0.0/97",
					"a::c:d:e:f:0.0.0.0/97",
					"a::c:d:e:f:0.0.0.0/97",
					"a:0:c:d:e:f::/97",
					"0.0.0.0.0.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-0-0.ipv6-literal.net/97",
					"00|M>t};s?v~hFl`j3_$/97",
					"0x000a0000000c000d000e000f00000000",
					"00000240000000006000032000160000740000000000");
			
			testIPv6Strings("a:0:c:d:e:f:0:0/96",
					"a:0:c:d:e:f:0:0/96",			
					"a:0:c:d:e:f:0:0",
					"a:0:c:d:e:f::",
					"a:0:c:d:e:f:0:0",
					"000a:0000:000c:000d:000e:000f:0000:0000/96",
					"a:0:c:d:e:f::/96",
					"a:0:c:d:e:f::/96",
					"a:0:c:d:e:f::/96",
					"a:0:c:d:e:f::",
					"a::c:d:e:f:0.0.0.0/96",
					"a::c:d:e:f:0.0.0.0/96",
					"a:0:c:d:e:f::/96",
					"a:0:c:d:e:f::/96",
					"0.0.0.0.0.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-0-0.ipv6-literal.net/96",
					"00|M>t};s?v~hFl`j3_$/96",
					"0x000a0000000c000d000e000f00000000",
					"00000240000000006000032000160000740000000000");
			
			testIPv6Strings("a:0:c:d:e:f:1:0/112",
					"a:0:c:d:e:f:1:0/112",
					"a:0:c:d:e:f:1:0",
					"a:0:c:d:e:f:1:0",
					"a:0:c:d:e:f:1:0",
					"000a:0000:000c:000d:000e:000f:0001:0000/112",
					"a::c:d:e:f:1:0/112",//compressed
					"a:0:c:d:e:f:1:0/112",//canonical (only zeros are single so not compressed)
					"a:0:c:d:e:f:1::/112",//subnet
					"a::c:d:e:f:1:0",//compressed wildcard
					"a::c:d:e:f:0.1.0.0/112",//mixed, no compress
					"a::c:d:e:f:0.1.0.0/112",//mixed, no compress host
					"a::c:d:e:f:0.1.0.0/112",
					"a::c:d:e:f:0.1.0.0/112",
					"0.0.0.0.1.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-1-0.ipv6-literal.net/112",
					"00|M>t};s?v~hFl`jD0%/112",
					"0x000a0000000c000d000e000f00010000",
					"00000240000000006000032000160000740000200000");//mixed
			
			testIPv6Strings("a:0:c:d:0:0:1:0/112",
					"a:0:c:d:0:0:1:0/112", //normalized
					"a:0:c:d:0:0:1:0",//normalized wildcard
					"a:0:c:d::1:0",//canonical wildcard
					"a:0:c:d:0:0:1:0",//sql
					"000a:0000:000c:000d:0000:0000:0001:0000/112", //full
					"a:0:c:d::1:0/112",//compressed
					"a:0:c:d::1:0/112",//canonical 
					"a:0:c:d:0:0:1::/112",//subnet
					"a:0:c:d::1:0",//compressed wildcard
					"a:0:c:d::0.1.0.0/112",//mixed, no compress
					"a:0:c:d::0.1.0.0/112",//mixed, no compress host
					"a:0:c:d::0.1.0.0/112",
					"a:0:c:d::0.1.0.0/112",
					"0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-0-0-1-0.ipv6-literal.net/112",
					"00|M>t};s?v}5L>MDR^a/112",
					"0x000a0000000c000d0000000000010000",
					"00000240000000006000032000000000000000200000");//mixed
			
			testIPv6Strings("a:0:c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a:0",
					"a:0:c:d:e:f:a:0",
					"a:0:c:d:e:f:a:0",
					"000a:0000:000c:000d:000e:000f:000a:0000/112",
					"a::c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a::/112",
					"a::c:d:e:f:a:0",
					"a::c:d:e:f:0.10.0.0/112",
					"a::c:d:e:f:0.10.0.0/112",
					"a::c:d:e:f:0.10.0.0/112",
					"a::c:d:e:f:0.10.0.0/112",
					"0.0.0.0.a.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-a-0.ipv6-literal.net/112",
					"00|M>t};s?v~hFl`k9s=/112",
					"0x000a0000000c000d000e000f000a0000",
					"00000240000000006000032000160000740002400000");
			
			testIPv6Strings("a:0:c:d:0:0:0:100/120",
					"a:0:c:d:0:0:0:100/120", //normalized
					"a:0:c:d:0:0:0:100",//normalized wildcard
					"a:0:c:d::100",//canonical wildcard
					"a:0:c:d:0:0:0:100",//sql
					"000a:0000:000c:000d:0000:0000:0000:0100/120", //full
					"a:0:c:d::100/120",//compressed
					"a:0:c:d::100/120",//canonical 
					"a:0:c:d::100/120",//subnet
					"a:0:c:d::100",//compressed wildcard
					"a:0:c:d::0.0.1.0/120",//mixed, no compress
					"a:0:c:d::0.0.1.0/120",//mixed, no compress host
					"a:0:c:d::0.0.1.0/120",
					"a:0:c:d::0.0.1.0/120",
					"0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-0-0-0-100.ipv6-literal.net/120",
					"00|M>t};s?v}5L>MDI>a/120",
					"0x000a0000000c000d0000000000000100",
					"00000240000000006000032000000000000000000400");//mixed
			
			testIPv6Strings("a:b:c:d:*/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:%:%:%:%",
					"000a:000b:000c:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*.*.*.*/64",
					"a:b:c:d:*:*:*.*.*.*/64",
					"a:b:c:d:*:*:*.*.*.*/64",
					"a:b:c:d:*:*:*.*.*.*/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-*-*-*-*.ipv6-literal.net/64",
					"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k/64",
					"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
					"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
			
			testIPv6Strings("a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:%:%:%:%",
					"000a:000b:000c:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*.*.*.*/64",
					"a:b:c:d:*:*:*.*.*.*/64",
					"a:b:c:d:*:*:*.*.*.*/64",
					"a:b:c:d:*:*:*.*.*.*/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-*-*-*-*.ipv6-literal.net/64",
					"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k/64",
					"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
					"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
			
			testIPv6Strings("a::d:*:*:*:*/64",
					"a:0:0:d:*:*:*:*/64",
					"a:0:0:d:*:*:*:*",
					"a::d:*:*:*:*",
					"a:0:0:d:%:%:%:%",
					"000a:0000:0000:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff/64",
					"a::d:*:*:*:*/64",
					"a::d:*:*:*:*/64",
					"a::d:*:*:*:*/64",
					"a::d:*:*:*:*",
					"a::d:*:*:*.*.*.*/64",
					"a::d:*:*:*.*.*.*/64",
					"a::d:*:*:*.*.*.*/64",
					"a::d:*:*:*.*.*.*/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-*-*-*-*.ipv6-literal.net/64",
					"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt-R6^kVV>{?N/64",
					"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
					"00000240000000000000032000000000000000000000-00000240000000000000033777777777777777777777");
			
			testIPv6Strings("1::/32",
					"1:0:0:0:0:0:0:0/32",
					"1:0:0:0:0:0:0:0",
					"1::",
					"1:0:0:0:0:0:0:0",
					"0001:0000:0000:0000:0000:0000:0000:0000/32",
					"1::/32",
					"1::/32",
					"1::/32",
					"1::",
					"1::0.0.0.0/32",
					"1::0.0.0.0/32",
					"1::/32",
					"1::/32",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.ip6.arpa",
					"1-0-0-0-0-0-0-0.ipv6-literal.net/32",
					"008JOm8Mm5*yBppL!sg1/32",
					"0x00010000000000000000000000000000",
					"00000020000000000000000000000000000000000000");
			
			testIPv6Strings("ffff::/104",
					"ffff:0:0:0:0:0:0:0/104",
					"ffff:0:0:0:0:0:0:0",
					"ffff::",
					"ffff:0:0:0:0:0:0:0",
					"ffff:0000:0000:0000:0000:0000:0000:0000/104",
					"ffff::/104",
					"ffff::/104",
					"ffff::/104",
					"ffff::",
					"ffff::0.0.0.0/104",
					"ffff::0.0.0.0/104",
					"ffff::0.0.0.0/104",
					"ffff::/104",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-0-0.ipv6-literal.net/104",
					"=q{+M|w0(OeO5^EGP660/104",
					"0xffff0000000000000000000000000000",
					"03777760000000000000000000000000000000000000");

			testIPv6Strings("ffff::/108",
					"ffff:0:0:0:0:0:0:0/108",
					"ffff:0:0:0:0:0:0:0",
					"ffff::",
					"ffff:0:0:0:0:0:0:0",
					"ffff:0000:0000:0000:0000:0000:0000:0000/108",
					"ffff::/108",
					"ffff::/108",
					"ffff::/108",
					"ffff::",
					"ffff::0.0.0.0/108",
					"ffff::0.0.0.0/108",
					"ffff::0.0.0.0/108",
					"ffff::/108",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-0-0.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^EGP660/108",
					"0xffff0000000000000000000000000000",
					"03777760000000000000000000000000000000000000");
			
			testIPv6Strings("ffff::1000:0/108",
					"ffff:0:0:0:0:0:1000:0/108",
					"ffff:0:0:0:0:0:1000:0",
					"ffff::1000:0",
					"ffff:0:0:0:0:0:1000:0",
					"ffff:0000:0000:0000:0000:0000:1000:0000/108",
					"ffff::1000:0/108",
					"ffff::1000:0/108",
					"ffff:0:0:0:0:0:1000::/108",
					"ffff::1000:0",
					"ffff::16.0.0.0/108",
					"ffff::16.0.0.0/108",
					"ffff::16.0.0.0/108",
					"ffff::16.0.0.0/108",
					"0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-1000-0.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^ELbE%G/108",
					"0xffff0000000000000000000010000000",
					"03777760000000000000000000000000002000000000");
			
			testIPv6Strings("ffff::a000:0/108",
					"ffff:0:0:0:0:0:a000:0/108",
					"ffff:0:0:0:0:0:a000:0",
					"ffff::a000:0",
					"ffff:0:0:0:0:0:a000:0",
					"ffff:0000:0000:0000:0000:0000:a000:0000/108",
					"ffff::a000:0/108",
					"ffff::a000:0/108",
					"ffff:0:0:0:0:0:a000::/108",
					"ffff::a000:0",
					"ffff::160.0.0.0/108",
					"ffff::160.0.0.0/108",
					"ffff::160.0.0.0/108",
					"ffff::160.0.0.0/108",
					"0.0.0.0.0.0.0.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-a000-0.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^E(z82>/108",
					"0xffff00000000000000000000a0000000",
					"03777760000000000000000000000000024000000000");
			
			testIPv6Strings("ffff::/107",
					"ffff:0:0:0:0:0:0:0/107",
					"ffff:0:0:0:0:0:0:0",
					"ffff::",
					"ffff:0:0:0:0:0:0:0",
					"ffff:0000:0000:0000:0000:0000:0000:0000/107",
					"ffff::/107",
					"ffff::/107",
					"ffff::/107",
					"ffff::",
					"ffff::0.0.0.0/107",
					"ffff::0.0.0.0/107",
					"ffff::0.0.0.0/107",
					"ffff::/107",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-0-0.ipv6-literal.net/107",
					"=q{+M|w0(OeO5^EGP660/107",
					"0xffff0000000000000000000000000000",
					"03777760000000000000000000000000000000000000");
			
			testIPv6Strings("abcd::/107",
					"abcd:0:0:0:0:0:0:0/107",
					"abcd:0:0:0:0:0:0:0",
					"abcd::",
					"abcd:0:0:0:0:0:0:0",
					"abcd:0000:0000:0000:0000:0000:0000:0000/107",
					"abcd::/107",
					"abcd::/107",
					"abcd::/107",
					"abcd::",
					"abcd::0.0.0.0/107",
					"abcd::0.0.0.0/107",
					"abcd::0.0.0.0/107",
					"abcd::/107",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.a.ip6.arpa",
					"abcd-0-0-0-0-0-0-0.ipv6-literal.net/107",
					"o6)n`s#^$cP5&p^H}p=a/107",
					"0xabcd0000000000000000000000000000",
					"02536320000000000000000000000000000000000000");
			
			testIPv6Strings("1:2:3:4::/80",
					"1:2:3:4:0:0:0:0/80", //normalized
					"1:2:3:4:0:0:0:0", //normalizedWildcards
					"1:2:3:4::", //canonicalWildcards
					"1:2:3:4:0:0:0:0", //sql
					"0001:0002:0003:0004:0000:0000:0000:0000/80",
					"1:2:3:4::/80",//compressed
					"1:2:3:4::/80",
					"1:2:3:4::/80",
					"1:2:3:4::",
					"1:2:3:4::0.0.0.0/80",//mixed no compress
					"1:2:3:4::0.0.0.0/80",//mixedNoCompressHost
					"1:2:3:4::/80",
					"1:2:3:4::/80",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
					"1-2-3-4-0-0-0-0.ipv6-literal.net/80",
					"008JQWOV7Skb)C|ve)jA/80",
					"0x00010002000300040000000000000000",
					"00000020000200001400010000000000000000000000");
		} else {

			testIPv6Strings("a:0:c:d:e:f:0:0/97",
					"a:0:c:d:e:f:0:0/97",		
					"a:0:c:d:e:f:0-7fff:*",
					"a:0:c:d:e:f:0-7fff:*",
					"a:0:c:d:e:f:0-7fff:%",
					"000a:0000:000c:000d:000e:000f:0000:0000/97",
					"a:0:c:d:e:f::/97",
					"a:0:c:d:e:f::/97",
					"a:0:c:d:e:f::/97",
					"a::c:d:e:f:0-7fff:*",
					"a::c:d:e:f:0.0.0.0/97",
					"a::c:d:e:f:0.0.0.0/97",
					"a::c:d:e:f:0.0.0.0/97",
					"a:0:c:d:e:f::/97",
					"*.*.*.*.*.*.*.0-7.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-0-0.ipv6-literal.net/97",
					"00|M>t};s?v~hFl`j3_$/97",
					"0x000a0000000c000d000e000f00000000-0x000a0000000c000d000e000f7fffffff",
					"00000240000000006000032000160000740000000000-00000240000000006000032000160000757777777777");
			
			testIPv6Strings("a:0:c:d:e:f:0:0/96",
					"a:0:c:d:e:f:0:0/96",			
					"a:0:c:d:e:f:*:*",
					"a:0:c:d:e:f:*:*",
					"a:0:c:d:e:f:%:%",
					"000a:0000:000c:000d:000e:000f:0000:0000/96",
					"a:0:c:d:e:f::/96",
					"a:0:c:d:e:f::/96",
					"a:0:c:d:e:f::/96",
					"a::c:d:e:f:*:*",
					"a::c:d:e:f:0.0.0.0/96",
					"a::c:d:e:f:0.0.0.0/96",
					"a:0:c:d:e:f::/96",
					"a:0:c:d:e:f::/96",
					"*.*.*.*.*.*.*.*.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-0-0.ipv6-literal.net/96",
					"00|M>t};s?v~hFl`j3_$/96",
					"0x000a0000000c000d000e000f00000000-0x000a0000000c000d000e000fffffffff",
					"00000240000000006000032000160000740000000000-00000240000000006000032000160000777777777777");
			
			testIPv6Strings("a:0:c:d:e:f:1:0/112",
					"a:0:c:d:e:f:1:0/112",
					"a:0:c:d:e:f:1:*",
					"a:0:c:d:e:f:1:*",
					"a:0:c:d:e:f:1:%",
					"000a:0000:000c:000d:000e:000f:0001:0000/112",
					"a::c:d:e:f:1:0/112",//compressed
					"a:0:c:d:e:f:1:0/112",//canonical (only zeros are single so not compressed)
					"a:0:c:d:e:f:1::/112",//subnet
					"a::c:d:e:f:1:*",//compressed wildcard
					"a::c:d:e:f:0.1.0.0/112",//mixed, no compress
					"a::c:d:e:f:0.1.0.0/112",//mixed, no compress host
					"a::c:d:e:f:0.1.0.0/112",
					"a::c:d:e:f:0.1.0.0/112",
					"*.*.*.*.1.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-1-0.ipv6-literal.net/112",
					"00|M>t};s?v~hFl`jD0%/112",
					"0x000a0000000c000d000e000f00010000-0x000a0000000c000d000e000f0001ffff",
					"00000240000000006000032000160000740000200000-00000240000000006000032000160000740000377777");//mixed
			
			testIPv6Strings("a:0:c:d:0:0:1:0/112",
					"a:0:c:d:0:0:1:0/112", //normalized
					"a:0:c:d:0:0:1:*",//normalized wildcard
					"a:0:c:d::1:*",//canonical wildcard
					"a:0:c:d:0:0:1:%",//sql
					"000a:0000:000c:000d:0000:0000:0001:0000/112", //full
					"a:0:c:d::1:0/112",//compressed
					"a:0:c:d::1:0/112",//canonical 
					"a:0:c:d:0:0:1::/112",//subnet
					"a:0:c:d::1:*",//compressed wildcard
					"a:0:c:d::0.1.0.0/112",//mixed, no compress
					"a:0:c:d::0.1.0.0/112",//mixed, no compress host
					"a:0:c:d::0.1.0.0/112",
					"a:0:c:d::0.1.0.0/112",
					"*.*.*.*.1.0.0.0.0.0.0.0.0.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-0-0-1-0.ipv6-literal.net/112",
					"00|M>t};s?v}5L>MDR^a/112",
					"0x000a0000000c000d0000000000010000-0x000a0000000c000d000000000001ffff",
					"00000240000000006000032000000000000000200000-00000240000000006000032000000000000000377777");//mixed
			
			testIPv6Strings("a:b:c:*::/64",
					"a:b:c:*:0:0:0:0/64",
					"a:b:c:*:*:*:*:*",
					"a:b:c:*:*:*:*:*",
					"a:b:c:%:%:%:%:%",
					"000a:000b:000c:0000-ffff:0000:0000:0000:0000/64",
					"a:b:c:*::/64",
					"a:b:c:*::/64",
					"a:b:c:*::/64",
					"a:b:c:*:*:*:*:*",
					"a:b:c:*::0.0.0.0/64",
					"a:b:c:*::0.0.0.0/64",
					"a:b:c:*::/64",
					"a:b:c:*::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-*-0-0-0-0.ipv6-literal.net/64",
					"00|N0s0$N0-%*(tF5l-X" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0;%Z;E{Rk+ZU@X/64",
					"0x000a000b000c00000000000000000000-0x000a000b000cffffffffffffffffffff",
					"00000240001300006000000000000000000000000000-00000240001300006377777777777777777777777777");
			
			testIPv6Strings("a::/64",
					"a:0:0:0:0:0:0:0/64",
					"a:0:0:0:*:*:*:*",
					"a::*:*:*:*",
					"a:0:0:0:%:%:%:%",
					"000a:0000:0000:0000:0000:0000:0000:0000/64",
					"a::/64",
					"a::/64",
					"a::/64",
					"a::*:*:*:*",
					"a::0.0.0.0/64",
					"a::0.0.0.0/64",
					"a::/64",
					"a::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-0-0-0-0-0.ipv6-literal.net/64",
					"00|M>t|ttwH6V62lVY`A/64",
					"0x000a0000000000000000000000000000-0x000a000000000000ffffffffffffffff",
					"00000240000000000000000000000000000000000000-00000240000000000000001777777777777777777777");
			
			testIPv6Strings("a:0:0:d:e:f:0:0/112",
					"a:0:0:d:e:f:0:0/112",
					"a:0:0:d:e:f:0:*",
					"a::d:e:f:0:*",
					"a:0:0:d:e:f:0:%",
					"000a:0000:0000:000d:000e:000f:0000:0000/112",
					"a::d:e:f:0:0/112",
					"a::d:e:f:0:0/112",
					"a:0:0:d:e:f::/112",
					"a::d:e:f:0:*",
					"a::d:e:f:0.0.0.0/112",
					"a::d:e:f:0.0.0.0/112",
					"a::d:e:f:0.0.0.0/112",
					"a:0:0:d:e:f::/112",
					"*.*.*.*.0.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-e-f-0-0.ipv6-literal.net/112",
					"00|M>t|tt+WcwbECb*xq/112",
					"0x000a00000000000d000e000f00000000-0x000a00000000000d000e000f0000ffff",
					"00000240000000000000032000160000740000000000-00000240000000000000032000160000740000177777");
			
			testIPv6Strings("a:0:c:d:e:f:0:0/112",
					"a:0:c:d:e:f:0:0/112",			
					"a:0:c:d:e:f:0:*",
					"a:0:c:d:e:f:0:*",
					"a:0:c:d:e:f:0:%",
					"000a:0000:000c:000d:000e:000f:0000:0000/112",
					"a:0:c:d:e:f::/112",
					"a:0:c:d:e:f::/112",
					"a:0:c:d:e:f::/112",
					"a::c:d:e:f:0:*",
					"a::c:d:e:f:0.0.0.0/112",
					"a::c:d:e:f:0.0.0.0/112",
					"a::c:d:e:f:0.0.0.0/112",
					"a:0:c:d:e:f::/112",
					"*.*.*.*.0.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-0-0.ipv6-literal.net/112",
					"00|M>t};s?v~hFl`j3_$/112",
					"0x000a0000000c000d000e000f00000000-0x000a0000000c000d000e000f0000ffff",
					"00000240000000006000032000160000740000000000-00000240000000006000032000160000740000177777");
			
			testIPv6Strings("a:0:c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a:*",
					"a:0:c:d:e:f:a:*",
					"a:0:c:d:e:f:a:%",
					"000a:0000:000c:000d:000e:000f:000a:0000/112",
					"a::c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a:0/112",
					"a:0:c:d:e:f:a::/112",
					"a::c:d:e:f:a:*",
					"a::c:d:e:f:0.10.0.0/112",
					"a::c:d:e:f:0.10.0.0/112",
					"a::c:d:e:f:0.10.0.0/112",
					"a::c:d:e:f:0.10.0.0/112",
					"*.*.*.*.a.0.0.0.f.0.0.0.e.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-e-f-a-0.ipv6-literal.net/112",
					"00|M>t};s?v~hFl`k9s=/112",
					"0x000a0000000c000d000e000f000a0000-0x000a0000000c000d000e000f000affff",
					"00000240000000006000032000160000740002400000-00000240000000006000032000160000740002577777");
			
			testIPv6Strings("a:0:c:d:0:0:0:100/120",
					"a:0:c:d:0:0:0:100/120", //normalized
					"a:0:c:d:0:0:0:100-1ff",//normalized wildcard
					"a:0:c:d::100-1ff",//canonical wildcard
					"a:0:c:d:0:0:0:1__",//sql
					"000a:0000:000c:000d:0000:0000:0000:0100/120", //full
					"a:0:c:d::100/120",//compressed
					"a:0:c:d::100/120",//canonical 
					"a:0:c:d::100/120",//subnet
					"a:0:c:d::100-1ff",//compressed wildcard
					"a:0:c:d::0.0.1.0/120",//mixed, no compress
					"a:0:c:d::0.0.1.0/120",//mixed, no compress host
					"a:0:c:d::0.0.1.0/120",
					"a:0:c:d::0.0.1.0/120",
					"*.*.1.0.0.0.0.0.0.0.0.0.0.0.0.0.d.0.0.0.c.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-c-d-0-0-0-100.ipv6-literal.net/120",
					"00|M>t};s?v}5L>MDI>a/120",
					"0x000a0000000c000d0000000000000100-0x000a0000000c000d00000000000001ff",
					"00000240000000006000032000000000000000000400-00000240000000006000032000000000000000000777");//mixed
			
			testIPv6Strings("a:b:c:d:*/64",
					"a:b:c:d:0:0:0:0/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:%:%:%:%",
					"000a:000b:000c:000d:0000:0000:0000:0000/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-0-0-0-0.ipv6-literal.net/64",
					"00|N0s0$ND2BxK96%Chk/64",
					"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
					"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
			
			testIPv6Strings("a:b:c:d:*:*:*:*/64",
					"a:b:c:d:0:0:0:0/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d:%:%:%:%",
					"000a:000b:000c:000d:0000:0000:0000:0000/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"a:b:c:d:*:*:*:*",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::0.0.0.0/64",
					"a:b:c:d::/64",
					"a:b:c:d::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
					"a-b-c-d-0-0-0-0.ipv6-literal.net/64",
					"00|N0s0$ND2BxK96%Chk/64",
					"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
					"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
			
			testIPv6Strings("a::d:*:*:*:*/64",
					"a:0:0:d:0:0:0:0/64",
					"a:0:0:d:*:*:*:*",
					"a::d:*:*:*:*",
					"a:0:0:d:%:%:%:%",
					"000a:0000:0000:000d:0000:0000:0000:0000/64",
					"a:0:0:d::/64",
					"a:0:0:d::/64",
					"a:0:0:d::/64",
					"a::d:*:*:*:*",
					"a::d:0:0:0.0.0.0/64",
					"a::d:0:0:0.0.0.0/64",
					"a:0:0:d::/64",
					"a:0:0:d::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-d-0-0-0-0.ipv6-literal.net/64",
					"00|M>t|tt+WbKhfd5~qN/64",
					"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
					"00000240000000000000032000000000000000000000-00000240000000000000033777777777777777777777");
			
			testIPv6Strings("1::/32",
					"1:0:0:0:0:0:0:0/32",
					"1:0:*:*:*:*:*:*",
					"1:0:*:*:*:*:*:*",
					"1:0:%:%:%:%:%:%",
					"0001:0000:0000:0000:0000:0000:0000:0000/32",
					"1::/32",
					"1::/32",
					"1::/32",
					"1::*:*:*:*:*:*",
					"1::0.0.0.0/32",
					"1::0.0.0.0/32",
					"1::/32",
					"1::/32",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.0.0.0.0.1.0.0.0.ip6.arpa",
					"1-0-0-0-0-0-0-0.ipv6-literal.net/32",
					"008JOm8Mm5*yBppL!sg1/32",
					"0x00010000000000000000000000000000-0x00010000ffffffffffffffffffffffff",
					"00000020000000000000000000000000000000000000-00000020000077777777777777777777777777777777");
			
			testIPv6Strings("ffff::/104",
					"ffff:0:0:0:0:0:0:0/104",
					"ffff:0:0:0:0:0:0-ff:*",
					"ffff::0-ff:*",
					"ffff:0:0:0:0:0:0-ff:%",
					"ffff:0000:0000:0000:0000:0000:0000:0000/104",
					"ffff::/104",
					"ffff::/104",
					"ffff::/104",
					"ffff::0-ff:*",
					"ffff::0.0.0.0/104",
					"ffff::0.0.0.0/104",
					"ffff::0.0.0.0/104",
					"ffff::/104",
					"*.*.*.*.*.*.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-0-0.ipv6-literal.net/104",
					"=q{+M|w0(OeO5^EGP660/104",
					"0xffff0000000000000000000000000000-0xffff0000000000000000000000ffffff",
					"03777760000000000000000000000000000000000000-03777760000000000000000000000000000077777777");

			testIPv6Strings("ffff::/108",
					"ffff:0:0:0:0:0:0:0/108",
					"ffff:0:0:0:0:0:0-f:*",
					"ffff::0-f:*",
					"ffff:0:0:0:0:0:_:%",
					"ffff:0000:0000:0000:0000:0000:0000:0000/108",
					"ffff::/108",
					"ffff::/108",
					"ffff::/108",
					"ffff::0-f:*",
					"ffff::0.0.0.0/108",
					"ffff::0.0.0.0/108",
					"ffff::0.0.0.0/108",
					"ffff::/108",
					"*.*.*.*.*.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-0-0.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^EGP660/108",
					"0xffff0000000000000000000000000000-0xffff00000000000000000000000fffff",
					"03777760000000000000000000000000000000000000-03777760000000000000000000000000000003777777");
			
			testIPv6Strings("ffff::1000:0/108",
					"ffff:0:0:0:0:0:1000:0/108",
					"ffff:0:0:0:0:0:1000-100f:*",
					"ffff::1000-100f:*",
					"ffff:0:0:0:0:0:100_:%",
					"ffff:0000:0000:0000:0000:0000:1000:0000/108",
					"ffff::1000:0/108",
					"ffff::1000:0/108",
					"ffff:0:0:0:0:0:1000::/108",
					"ffff::1000-100f:*",
					"ffff::16.0.0.0/108",
					"ffff::16.0.0.0/108",
					"ffff::16.0.0.0/108",
					"ffff::16.0.0.0/108",
					"*.*.*.*.*.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-1000-0.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^ELbE%G/108",
					"0xffff0000000000000000000010000000-0xffff00000000000000000000100fffff",
					"03777760000000000000000000000000002000000000-03777760000000000000000000000000002003777777");
			
			testIPv6Strings("ffff::a000:0/108",
					"ffff:0:0:0:0:0:a000:0/108",
					"ffff:0:0:0:0:0:a000-a00f:*",
					"ffff::a000-a00f:*",
					"ffff:0:0:0:0:0:a00_:%",
					"ffff:0000:0000:0000:0000:0000:a000:0000/108",
					"ffff::a000:0/108",
					"ffff::a000:0/108",
					"ffff:0:0:0:0:0:a000::/108",
					"ffff::a000-a00f:*",
					"ffff::160.0.0.0/108",
					"ffff::160.0.0.0/108",
					"ffff::160.0.0.0/108",
					"ffff::160.0.0.0/108",
					"*.*.*.*.*.0.0.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-a000-0.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^E(z82>/108",
					"0xffff00000000000000000000a0000000-0xffff00000000000000000000a00fffff",
					"03777760000000000000000000000000024000000000-03777760000000000000000000000000024003777777");
			
			testIPv6Strings("ffff::/107",
					"ffff:0:0:0:0:0:0:0/107",
					"ffff:0:0:0:0:0:0-1f:*",
					"ffff::0-1f:*",
					"ffff:0:0:0:0:0:0-1f:%",
					"ffff:0000:0000:0000:0000:0000:0000:0000/107",
					"ffff::/107",
					"ffff::/107",
					"ffff::/107",
					"ffff::0-1f:*",
					"ffff::0.0.0.0/107",
					"ffff::0.0.0.0/107",
					"ffff::0.0.0.0/107",
					"ffff::/107",
					"*.*.*.*.*.0-1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-0-0.ipv6-literal.net/107",
					"=q{+M|w0(OeO5^EGP660/107",
					"0xffff0000000000000000000000000000-0xffff00000000000000000000001fffff",
					"03777760000000000000000000000000000000000000-03777760000000000000000000000000000007777777");
			
			testIPv6Strings("abcd::/107",
					"abcd:0:0:0:0:0:0:0/107",
					"abcd:0:0:0:0:0:0-1f:*",
					"abcd::0-1f:*",
					"abcd:0:0:0:0:0:0-1f:%",
					"abcd:0000:0000:0000:0000:0000:0000:0000/107",
					"abcd::/107",
					"abcd::/107",
					"abcd::/107",
					"abcd::0-1f:*",
					"abcd::0.0.0.0/107",
					"abcd::0.0.0.0/107",
					"abcd::0.0.0.0/107",
					"abcd::/107",
					"*.*.*.*.*.0-1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.a.ip6.arpa",
					"abcd-0-0-0-0-0-0-0.ipv6-literal.net/107",
					"o6)n`s#^$cP5&p^H}p=a/107",
					"0xabcd0000000000000000000000000000-0xabcd00000000000000000000001fffff",
					"02536320000000000000000000000000000000000000-02536320000000000000000000000000000007777777");
			
			testIPv6Strings("1:2:3:4::/80",
					"1:2:3:4:0:0:0:0/80", //normalized
					"1:2:3:4:0:*:*:*", //normalizedWildcards
					"1:2:3:4:0:*:*:*", //canonicalWildcards
					"1:2:3:4:0:%:%:%", //sql
					"0001:0002:0003:0004:0000:0000:0000:0000/80",
					"1:2:3:4::/80",//compressed
					"1:2:3:4::/80",
					"1:2:3:4::/80",
					"1:2:3:4::*:*:*",
					"1:2:3:4::0.0.0.0/80",//mixed no compress
					"1:2:3:4::0.0.0.0/80",//mixedNoCompressHost
					"1:2:3:4::/80",
					"1:2:3:4::/80",
					"*.*.*.*.*.*.*.*.*.*.*.*.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
					"1-2-3-4-0-0-0-0.ipv6-literal.net/80",
					"008JQWOV7Skb)C|ve)jA/80",
					"0x00010002000300040000000000000000-0x00010002000300040000ffffffffffff",
					"00000020000200001400010000000000000000000000-00000020000200001400010000007777777777777777");
		}
		
		testIPv6Strings("a:b:c:*:*:*:*:*",//as noted above, addresses are not converted to prefix if starting as wildcards.  
				"a:b:c:*:*:*:*:*",
				"a:b:c:*:*:*:*:*",
				"a:b:c:*:*:*:*:*",
				"a:b:c:%:%:%:%:%",
				"000a:000b:000c:0000-ffff:0000-ffff:0000-ffff:0000-ffff:0000-ffff",
				"a:b:c:*:*:*:*:*",
				"a:b:c:*:*:*:*:*",
				"a:b:c:*:*:*:*:*",
				"a:b:c:*:*:*:*:*",
				"a:b:c:*:*:*:*.*.*.*",
				"a:b:c:*:*:*:*.*.*.*",
				"a:b:c:*:*:*:*.*.*.*",
				"a:b:c:*:*:*:*.*.*.*",
				"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
				"a-b-c-*-*-*-*-*.ipv6-literal.net",
				"00|N0s0$N0-%*(tF5l-X" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0;%a&*sUa#KSGX",
				"0x000a000b000c00000000000000000000-0x000a000b000cffffffffffffffffffff",
				"00000240001300006000000000000000000000000000-00000240001300006377777777777777777777777777");
		
		testIPv6Strings("a:b:c:d:*", 
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:%:%:%:%",
				"000a:000b:000c:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*.*.*.*",
				"a:b:c:d:*:*:*.*.*.*",
				"a:b:c:d:*:*:*.*.*.*",
				"a:b:c:d:*:*:*.*.*.*",
				"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
				"a-b-c-d-*-*-*-*.ipv6-literal.net",
				"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k",
				"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
				"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
		
		testIPv6Strings("a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:%:%:%:%",
				"000a:000b:000c:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*:*",
				"a:b:c:d:*:*:*.*.*.*",
				"a:b:c:d:*:*:*.*.*.*",
				"a:b:c:d:*:*:*.*.*.*",
				"a:b:c:d:*:*:*.*.*.*",
				"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.ip6.arpa",
				"a-b-c-d-*-*-*-*.ipv6-literal.net",
				"00|N0s0$ND2BxK96%Chk" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|N0s0$ND{&WM}~o9(k",
				"0x000a000b000c000d0000000000000000-0x000a000b000c000dffffffffffffffff",
				"00000240001300006000032000000000000000000000-00000240001300006000033777777777777777777777");
		
		testIPv6Strings("a::c:d:*",
				"a:0:0:0:0:c:d:*",
				"a:0:0:0:0:c:d:*",
				"a::c:d:*",
				"a:0:0:0:0:c:d:%",
				"000a:0000:0000:0000:0000:000c:000d:0000-ffff",
				"a::c:d:*",
				"a::c:d:*",
				"a::c:d:*",
				"a::c:d:*",
				"a::c:0.13.*.*",
				"a::c:0.13.*.*",
				"a::c:0.13.*.*",
				"a::c:0.13.*.*",
				"*.*.*.*.d.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
				"a-0-0-0-0-c-d-*.ipv6-literal.net",
				"00|M>t|ttwH6V6EEzblZ" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|ttwH6V6EEzkrZ",
				"0x000a0000000000000000000c000d0000-0x000a0000000000000000000c000dffff",
				"00000240000000000000000000000000600003200000-00000240000000000000000000000000600003377777");
		
		testIPv6Strings("a::d:*:*:*:*",
				"a:0:0:d:*:*:*:*",
				"a:0:0:d:*:*:*:*",
				"a::d:*:*:*:*",
				"a:0:0:d:%:%:%:%",
				"000a:0000:0000:000d:0000-ffff:0000-ffff:0000-ffff:0000-ffff",
				"a::d:*:*:*:*",
				"a::d:*:*:*:*",
				"a::d:*:*:*:*",
				"a::d:*:*:*:*",
				"a::d:*:*:*.*.*.*",
				"a::d:*:*:*.*.*.*",
				"a::d:*:*:*.*.*.*",
				"a::d:*:*:*.*.*.*",
				"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.d.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
				"a-0-0-d-*-*-*-*.ipv6-literal.net",
				"00|M>t|tt+WbKhfd5~qN" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|tt-R6^kVV>{?N",
				"0x000a00000000000d0000000000000000-0x000a00000000000dffffffffffffffff",
				"00000240000000000000032000000000000000000000-00000240000000000000033777777777777777777777");
		
		if(allPrefixesAreSubnets) {
			testIPv6Strings("a::c:d:*/64",
					"a:0:0:0:0:0:0:0/64",
					"a:0:0:0:*:*:*:*",
					"a::*:*:*:*",
					"a:0:0:0:%:%:%:%",
					"000a:0000:0000:0000:0000:0000:0000:0000/64",
					"a::/64",
					"a::/64",
					"a::/64",
					"a::*:*:*:*",
					"a::0.0.0.0/64",
					"a::0.0.0.0/64",
					"a::/64",
					"a::/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-0-0-0-0-0.ipv6-literal.net/64",
					"00|M>t|ttwH6V62lVY`A/64",
					"0x000a0000000000000000000000000000-0x000a000000000000ffffffffffffffff",
					"00000240000000000000000000000000000000000000-00000240000000000000001777777777777777777777");
			
			testIPv4Strings("1.2.0.4/16", "1.2.0.0/16", "1.2.*.*", "1.2.%.%", "001.002.000.000/16", "01.02.00.00/16", "0x1.0x2.0x0.0x0/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.2.3.0/16", "1.2.0.0/16", "1.2.*.*", "1.2.%.%", "001.002.000.000/16", "01.02.00.00/16", "0x1.0x2.0x0.0x0/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.0.0.0/14", "1.0.0.0/14", "1.0-3.*.*", "1.0-3.%.%", "001.000.000.000/14", "01.00.00.00/14", "0x1.0x0.0x0.0x0/14", "*.*.0-3.1.in-addr.arpa", "0x01000000-0x0103ffff", "000100000000-000100777777");
			testIPv4Strings("1.2.*.4/16", "1.2.0.0/16", "1.2.*.*", "1.2.%.%", "001.002.000.000/16", "01.02.00.00/16", "0x1.0x2.0x0.0x0/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.2.3.*/16", "1.2.0.0/16", "1.2.*.*", "1.2.%.%", "001.002.000.000/16", "01.02.00.00/16", "0x1.0x2.0x0.0x0/16", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777");
			testIPv4Strings("1.0.*.*/14", "1.0.0.0/14", "1.0-3.*.*", "1.0-3.%.%", "001.000.000.000/14", "01.00.00.00/14", "0x1.0x0.0x0.0x0/14", "*.*.0-3.1.in-addr.arpa", "0x01000000-0x0103ffff", "000100000000-000100777777");
		
			testIPv6Strings("ffff::/8",
					"ff00:0:0:0:0:0:0:0/8",
					"ff00-ffff:*:*:*:*:*:*:*",
					"ff00-ffff:*:*:*:*:*:*:*",
					"ff__:%:%:%:%:%:%:%",
					"ff00:0000:0000:0000:0000:0000:0000:0000/8",
					"ff00::/8",
					"ff00::/8",
					"ff00::/8",
					"ff00-ffff:*:*:*:*:*:*:*",
					"ff00::0.0.0.0/8",
					"ff00::0.0.0.0/8",
					"ff00::/8",
					"ff00::/8",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.f.f.ip6.arpa",
					"ff00-0-0-0-0-0-0-0.ipv6-literal.net/8",
					"=SN{mv>Qn+T=L9X}Vo30/8",
					"0xff000000000000000000000000000000-0xffffffffffffffffffffffffffffffff",
					"03770000000000000000000000000000000000000000-03777777777777777777777777777777777777777777");
		
			testIPv6Strings("ffff::eeee:eeee/108",
					"ffff:0:0:0:0:0:eee0:0/108",
					"ffff:0:0:0:0:0:eee0-eeef:*",
					"ffff::eee0-eeef:*",
					"ffff:0:0:0:0:0:eee_:%",
					"ffff:0000:0000:0000:0000:0000:eee0:0000/108",
					"ffff::eee0:0/108",
					"ffff::eee0:0/108",
					"ffff:0:0:0:0:0:eee0::/108",
					"ffff::eee0-eeef:*",
					"ffff::238.224.0.0/108",
					"ffff::238.224.0.0/108",
					"ffff::238.224.0.0/108",
					"ffff::238.224.0.0/108",
					"*.*.*.*.*.e.e.e.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-eee0-0.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^F85=Cb/108",
					"0xffff00000000000000000000eee00000-0xffff00000000000000000000eeefffff",
					"03777760000000000000000000000000035670000000-03777760000000000000000000000000035673777777");
			
		} else {
			testIPv6Strings("a::c:d:*/64",
					"a:0:0:0:0:c:d:*/64",
					"a:0:0:0:0:c:d:*",
					"a::c:d:*",
					"a:0:0:0:0:c:d:%",
					"000a:0000:0000:0000:0000:000c:000d:0000-ffff/64",
					"a::c:d:*/64",
					"a::c:d:*/64",
					"a::c:d:*/64",
					"a::c:d:*",
					"a::c:0.13.*.*/64",
					"a::c:0.13.*.*/64",
					"a::c:0.13.*.*/64",
					"a::c:0.13.*.*/64",
					"*.*.*.*.d.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-0-0-c-d-*.ipv6-literal.net/64",
					"00|M>t|ttwH6V6EEzblZ" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|ttwH6V6EEzkrZ/64", 
					"0x000a0000000000000000000c000d0000-0x000a0000000000000000000c000dffff",
					"00000240000000000000000000000000600003200000-00000240000000000000000000000000600003377777");
			
			testIPv6Strings("a::c:d:*/80",//similar to above, but allows us to test the base 85 string with non-64 bit prefix
					"a:0:0:0:0:c:d:*/80",
					"a:0:0:0:0:c:d:*",
					"a::c:d:*",
					"a:0:0:0:0:c:d:%",
					"000a:0000:0000:0000:0000:000c:000d:0000-ffff/80",
					"a::c:d:*/80",
					"a::c:d:*/80",
					"a::c:d:*/80",
					"a::c:d:*",
					"a::c:0.13.*.*/80",
					"a::c:0.13.*.*/80",
					"a::c:0.13.*.*/80",
					"a::c:0.13.*.*/80",
					"*.*.*.*.d.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-0-0-c-d-*.ipv6-literal.net/80",
					"00|M>t|ttwH6V6EEzblZ" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|ttwH6V6EEzkrZ/80", 
					"0x000a0000000000000000000c000d0000-0x000a0000000000000000000c000dffff",
					"00000240000000000000000000000000600003200000-00000240000000000000000000000000600003377777");
			
			testIPv6Strings("a::c:d:*/48",//similar to above, but allows us to test the base 85 string with non-64 bit prefix
					"a:0:0:0:0:c:d:*/48",
					"a:0:0:0:0:c:d:*",
					"a::c:d:*",
					"a:0:0:0:0:c:d:%",
					"000a:0000:0000:0000:0000:000c:000d:0000-ffff/48",
					"a::c:d:*/48",
					"a::c:d:*/48",
					"a::c:d:*/48",
					"a::c:d:*",
					"a::c:0.13.*.*/48",
					"a::c:0.13.*.*/48",
					"a::c:0.13.*.*/48",
					"a::c:0.13.*.*/48",
					"*.*.*.*.d.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.ip6.arpa",
					"a-0-0-0-0-c-d-*.ipv6-literal.net/48",
					"00|M>t|ttwH6V6EEzblZ" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "00|M>t|ttwH6V6EEzkrZ/48", 
					"0x000a0000000000000000000c000d0000-0x000a0000000000000000000c000dffff",
					"00000240000000000000000000000000600003200000-00000240000000000000000000000000600003377777");
			
			testIPv4Strings("1.2.0.4/16", "1.2.0.4/16", "1.2.0.4", "1.2.0.4", "001.002.000.004/16", "01.02.00.04/16", "0x1.0x2.0x0.0x4/16", "4.0.2.1.in-addr.arpa", "0x01020004", "000100400004");
			testIPv4Strings("1.2.3.0/16", "1.2.3.0/16", "1.2.3.0", "1.2.3.0", "001.002.003.000/16", "01.02.03.00/16", "0x1.0x2.0x3.0x0/16", "0.3.2.1.in-addr.arpa", "0x01020300", "000100401400");
			testIPv4Strings("1.2.0.0/14", "1.2.0.0/14", "1.2.0.0", "1.2.0.0", "001.002.000.000/14", "01.02.00.00/14", "0x1.0x2.0x0.0x0/14", "0.0.2.1.in-addr.arpa", "0x01020000", "000100400000");
		
			testIPv4Strings("1.2.*.4/16", "1.2.*.4/16", "1.2.*.4", "1.2.%.4", "001.002.000-255.004/16", "01.02.*.04/16", "0x1.0x2.*.0x4/16", "4.*.2.1.in-addr.arpa", null, null);
			testIPv4Strings("1.2.3.*/16", "1.2.3.*/16", "1.2.3.*", "1.2.3.%", "001.002.003.000-255/16", "01.02.03.*/16", "0x1.0x2.0x3.*/16", "*.3.2.1.in-addr.arpa", "0x01020300-0x010203ff", "000100401400-000100401777"); 
			testIPv4Strings("1.2.*.*/14", "1.2.*.*/14", "1.2.*.*", "1.2.%.%", "001.002.000-255.000-255/14", "01.02.*.*/14", "0x1.0x2.*.*/14", "*.*.2.1.in-addr.arpa", "0x01020000-0x0102ffff", "000100400000-000100577777"); //000100400000-000100400000/14"
		
			testIPv6Strings("ffff::/8",
					"ffff:0:0:0:0:0:0:0/8",
					"ffff:0:0:0:0:0:0:0",
					"ffff::",
					"ffff:0:0:0:0:0:0:0",
					"ffff:0000:0000:0000:0000:0000:0000:0000/8",
					"ffff::/8",
					"ffff::/8",
					"ffff::/8",
					"ffff::",
					"ffff::0.0.0.0/8",
					"ffff::0.0.0.0/8",
					"ffff::/8",
					"ffff::/8",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-0-0.ipv6-literal.net/8",
					"=q{+M|w0(OeO5^EGP660/8",
					"0xffff0000000000000000000000000000",
					"03777760000000000000000000000000000000000000");
			
			testIPv6Strings("ffff::eeee:eeee/108",
					"ffff:0:0:0:0:0:eeee:eeee/108",
					"ffff:0:0:0:0:0:eeee:eeee",
					"ffff::eeee:eeee",
					"ffff:0:0:0:0:0:eeee:eeee",
					"ffff:0000:0000:0000:0000:0000:eeee:eeee/108",
					"ffff::eeee:eeee/108",
					"ffff::eeee:eeee/108",
					"ffff::eeee:eeee/108",
					"ffff::eeee:eeee",
					"ffff::238.238.238.238/108",
					"ffff::238.238.238.238/108",
					"ffff::238.238.238.238/108",
					"ffff::238.238.238.238/108",
					"e.e.e.e.e.e.e.e.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.ip6.arpa",
					"ffff-0-0-0-0-0-eeee-eeee.ipv6-literal.net/108",
					"=q{+M|w0(OeO5^F87dpH/108",
					"0xffff00000000000000000000eeeeeeee",
					"03777760000000000000000000000000035673567356");
		}
		testIPv6Strings("1:2:3:4::%x%x%", //Note: % is the zone character (not sql wildcard), so this is handled as 1:2:3:4:: with zone :%:%
				"1:2:3:4:0:0:0:0%x%x%", //normalized
				"1:2:3:4:0:0:0:0%x%x%", //normalizedWildcards
				"1:2:3:4::%x%x%", //canonicalWildcards
				"1:2:3:4:0:0:0:0%x%x%", //sql
				"0001:0002:0003:0004:0000:0000:0000:0000%x%x%",
				"1:2:3:4::%x%x%",//compressed
				"1:2:3:4::%x%x%",//canonical
				"1:2:3:4::%x%x%",//subnet
				"1:2:3:4::%x%x%",//compressed wildcard
				"1:2:3:4::0.0.0.0%x%x%",//mixed no compress
				"1:2:3:4::%x%x%",//mixedNoCompressHost
				"1:2:3:4::%x%x%",
				"1:2:3:4::%x%x%",
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
				"1-2-3-4-0-0-0-0sxsxs.ipv6-literal.net",
				"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_ZONE_SEPARATOR + "x%x%",
				"0x00010002000300040000000000000000%x%x%",
				"00000020000200001400010000000000000000000000%x%x%");//mixed
		if(allPrefixesAreSubnets) {
			testIPv6Strings("1:2:3:4:5:6:7:8%a/64", //Note: % is the zone character (not sql wildcard)
					"1:2:3:4:0:0:0:0%a/64", //normalized
					"1:2:3:4:*:*:*:*%a", //normalizedWildcards
					"1:2:3:4:*:*:*:*%a", //canonicalWildcards
					"1:2:3:4:%:%:%:%%a", //sql
					"0001:0002:0003:0004:0000:0000:0000:0000%a/64",
					"1:2:3:4::%a/64",//compressed
					"1:2:3:4::%a/64",//canonical
					"1:2:3:4::%a/64",//subnet
					"1:2:3:4:*:*:*:*%a",//compressed wildcard
					"1:2:3:4::0.0.0.0%a/64",//mixed no compress
					"1:2:3:4::0.0.0.0%a/64",//mixedNoCompressHost
					"1:2:3:4::%a/64",
					"1:2:3:4::%a/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
					"1-2-3-4-0-0-0-0sa.ipv6-literal.net/64",
					"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_ZONE_SEPARATOR + "a/64",
					"0x00010002000300040000000000000000-0x0001000200030004ffffffffffffffff%a",
					"00000020000200001400010000000000000000000000-00000020000200001400011777777777777777777777%a");
		} else {
			testIPv6Strings("1:2:3:4:5:6:7:8%a/64", //Note: % is the zone character (not sql wildcard), so this is handled as 1:2:3:4:: with zone :%:%
					"1:2:3:4:5:6:7:8%a/64", //normalized
					"1:2:3:4:5:6:7:8%a", //normalizedWildcards
					"1:2:3:4:5:6:7:8%a", //canonicalWildcards
					"1:2:3:4:5:6:7:8%a", //sql
					"0001:0002:0003:0004:0005:0006:0007:0008%a/64",
					"1:2:3:4:5:6:7:8%a/64",//compressed
					"1:2:3:4:5:6:7:8%a/64",//canonical
					"1:2:3:4:5:6:7:8%a/64",//subnet
					"1:2:3:4:5:6:7:8%a",//compressed wildcard
					"1:2:3:4:5:6:0.7.0.8%a/64",//mixed no compress
					"1:2:3:4:5:6:0.7.0.8%a/64",//mixedNoCompressHost
					"1:2:3:4:5:6:0.7.0.8%a/64",
					"1:2:3:4:5:6:0.7.0.8%a/64",
					"8.0.0.0.7.0.0.0.6.0.0.0.5.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
					"1-2-3-4-5-6-7-8sa.ipv6-literal.net/64",
					"008JQWOV7SkcR4tS1R_a" + IPv6Address.ALTERNATIVE_ZONE_SEPARATOR + "a/64",
					"0x00010002000300040005000600070008%a",
					"00000020000200001400010000050000300001600010%a");
		}
		if(isNoAutoSubnets) {
			testIPv6Strings("1:2:3:4::%a/64", //Note: % is the zone character (not sql wildcard), so this is handled as 1:2:3:4:: with zone :%:%
					"1:2:3:4:0:0:0:0%a/64", //normalized
					"1:2:3:4:0:0:0:0%a", //normalizedWildcards
					"1:2:3:4::%a", //canonicalWildcards
					"1:2:3:4:0:0:0:0%a", //sql
					"0001:0002:0003:0004:0000:0000:0000:0000%a/64",
					"1:2:3:4::%a/64",//compressed
					"1:2:3:4::%a/64",//canonical
					"1:2:3:4::%a/64",//subnet
					"1:2:3:4::%a",//compressed wildcard
					"1:2:3:4::0.0.0.0%a/64",//mixed no compress
					"1:2:3:4::0.0.0.0%a/64",//mixedNoCompressHost
					"1:2:3:4::%a/64",
					"1:2:3:4::%a/64",
					"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
					"1-2-3-4-0-0-0-0sa.ipv6-literal.net/64",
					"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_ZONE_SEPARATOR + "a/64",
					"0x00010002000300040000000000000000%a",
					"00000020000200001400010000000000000000000000%a");
		} else {
			testIPv6Strings("1:2:3:4::%a/64", //Note: % is the zone character (not sql wildcard), so this is handled as 1:2:3:4:: with zone :%:%
					"1:2:3:4:0:0:0:0%a/64", //normalized
					"1:2:3:4:*:*:*:*%a", //normalizedWildcards
					"1:2:3:4:*:*:*:*%a", //canonicalWildcards
					"1:2:3:4:%:%:%:%%a", //sql
					"0001:0002:0003:0004:0000:0000:0000:0000%a/64",
					"1:2:3:4::%a/64",//compressed
					"1:2:3:4::%a/64",//canonical
					"1:2:3:4::%a/64",//subnet
					"1:2:3:4:*:*:*:*%a",//compressed wildcard
					"1:2:3:4::0.0.0.0%a/64",//mixed no compress
					"1:2:3:4::0.0.0.0%a/64",//mixedNoCompressHost
					"1:2:3:4::%a/64",
					"1:2:3:4::%a/64",
					"*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
					"1-2-3-4-0-0-0-0sa.ipv6-literal.net/64",
					"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_ZONE_SEPARATOR + "a/64",
					"0x00010002000300040000000000000000-0x0001000200030004ffffffffffffffff%a",
					"00000020000200001400010000000000000000000000-00000020000200001400011777777777777777777777%a");
		}
		
		testIPv6Strings("1:2:3:4::%.a.a", //Note: % is the zone character (not sql wildcard), so this is handled as 1:2:3:4:: with zone :%:%
				"1:2:3:4:0:0:0:0%.a.a", //normalized
				"1:2:3:4:0:0:0:0%.a.a", //normalizedWildcards
				"1:2:3:4::%.a.a", //canonicalWildcards
				"1:2:3:4:0:0:0:0%.a.a", //sql
				"0001:0002:0003:0004:0000:0000:0000:0000%.a.a",
				"1:2:3:4::%.a.a",//compressed
				"1:2:3:4::%.a.a",//canonical
				"1:2:3:4::%.a.a",//subnet
				"1:2:3:4::%.a.a",//compressed wildcard
				"1:2:3:4::0.0.0.0%.a.a",//mixed no compress
				"1:2:3:4::%.a.a",//mixedNoCompressHost
				"1:2:3:4::%.a.a",
				"1:2:3:4::%.a.a",
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
				"1-2-3-4-0-0-0-0s.a.a.ipv6-literal.net",
				"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_ZONE_SEPARATOR + ".a.a",
				"0x00010002000300040000000000000000%.a.a",
				"00000020000200001400010000000000000000000000%.a.a");//mixed
		testIPv6Strings("1:2:3:4::*:*:*",
				"1:2:3:4:0:*:*:*", //normalized
				"1:2:3:4:0:*:*:*", //normalizedWildcards
				"1:2:3:4:0:*:*:*", //canonicalWildcards
				"1:2:3:4:0:%:%:%", //sql
				"0001:0002:0003:0004:0000:0000-ffff:0000-ffff:0000-ffff",
				"1:2:3:4::*:*:*",//compressed
				"1:2:3:4:0:*:*:*",//canonical
				"1:2:3:4::*:*:*",//subnet
				"1:2:3:4::*:*:*",//compressed wildcard
				"1:2:3:4::*:*.*.*.*",//mixed no compress
				"1:2:3:4::*:*.*.*.*",//mixedNoCompressHost
				"1:2:3:4::*:*.*.*.*",
				"1:2:3:4::*:*.*.*.*",
				"*.*.*.*.*.*.*.*.*.*.*.*.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
				"1-2-3-4-0-*-*-*.ipv6-literal.net",
				"008JQWOV7Skb)C|ve)jA" + IPv6Address.ALTERNATIVE_RANGE_SEPARATOR + "008JQWOV7Skb?_P3;X#A",
				"0x00010002000300040000000000000000-0x00010002000300040000ffffffffffff",
				"00000020000200001400010000000000000000000000-00000020000200001400010000007777777777777777");

		testIPv6Strings("1:2:3:4::",
				"1:2:3:4:0:0:0:0", //normalized
				"1:2:3:4:0:0:0:0", //normalizedWildcards
				"1:2:3:4::", //canonicalWildcards
				"1:2:3:4:0:0:0:0", //sql
				"0001:0002:0003:0004:0000:0000:0000:0000",
				"1:2:3:4::",//compressed
				"1:2:3:4::",
				"1:2:3:4::",
				"1:2:3:4::",
				"1:2:3:4::0.0.0.0",//mixed no compress
				"1:2:3:4::",//mixedNoCompressHost
				"1:2:3:4::",
				"1:2:3:4::",
				"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
				"1-2-3-4-0-0-0-0.ipv6-literal.net",
				"008JQWOV7Skb)C|ve)jA",
				"0x00010002000300040000000000000000",
				"00000020000200001400010000000000000000000000");//mixed
		
		testIPv6Strings("1:2:3:4:0:6::",
				"1:2:3:4:0:6:0:0", //normalized
				"1:2:3:4:0:6:0:0", //normalizedWildcards
				"1:2:3:4:0:6::", //canonicalWildcards
				"1:2:3:4:0:6:0:0", //sql
				"0001:0002:0003:0004:0000:0006:0000:0000",
				"1:2:3:4:0:6::",//compressed
				"1:2:3:4:0:6::",
				"1:2:3:4:0:6::",//subnet
				"1:2:3:4:0:6::",//compressedWildcard
				"1:2:3:4::6:0.0.0.0",//mixed no compress
				"1:2:3:4:0:6::",//mixedNoCompressHost
				"1:2:3:4:0:6::",
				"1:2:3:4:0:6::",
				"0.0.0.0.0.0.0.0.6.0.0.0.0.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
				"1-2-3-4-0-6-0-0.ipv6-literal.net",
				"008JQWOV7Skb)D3fCrWG",
				"0x00010002000300040000000600000000",
				"00000020000200001400010000000000300000000000");
		testIPv6Strings("1:2:3:0:0:6::",
				"1:2:3:0:0:6:0:0", //normalized
				"1:2:3:0:0:6:0:0", //normalizedWildcards
				"1:2:3::6:0:0", //canonicalWildcards
				"1:2:3:0:0:6:0:0", //sql
				"0001:0002:0003:0000:0000:0006:0000:0000",
				"1:2:3::6:0:0",//compressed
				"1:2:3::6:0:0",
				"1:2:3::6:0:0",//subnet
				"1:2:3::6:0:0",//compressedWildcard
				"1:2:3::6:0.0.0.0",//mixed no compress
				"1:2:3::6:0.0.0.0",//mixedNoCompressHost
				"1:2:3::6:0.0.0.0",
				"1:2:3:0:0:6::",
				"0.0.0.0.0.0.0.0.6.0.0.0.0.0.0.0.0.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa",
				"1-2-3-0-0-6-0-0.ipv6-literal.net",
				"008JQWOV7O(=61h*;$LC",
				"0x00010002000300000000000600000000",
				"00000020000200001400000000000000300000000000");
	}
	
	void testPrefix(String original, Integer prefixLength, int minPrefix, Integer equivalentPrefix) {
		IPAddress ipaddr = createAddress(original).getAddress();
		testPrefix(ipaddr, prefixLength, minPrefix, equivalentPrefix);
		incrementTestCount();
	}
	
	@Override
	boolean allowsRange() {
		return true;
	}

	
	
	
	@Override
	void runTest() {
		boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		
		if(isNoAutoSubnets) {
			testEquivalentPrefix("128-255.*.*.*/1", 1);
			testEquivalentPrefix("1.2-3.*.*/15", 15);
			testEquivalentPrefix("1.2.*.*/16", 16);
			
			testEquivalentPrefix("1:2:*/32", 32);
			testEquivalentPrefix("8000-8fff:*/1", 4);
			testEquivalentPrefix("8000-ffff:*/1", 1);
			testEquivalentPrefix("1:2-3:*/31", 31);
			testEquivalentPrefix("1:2:*/34", 32);
			testEquivalentPrefix("1:2:0-3fff:*/34", 34);
		}
		
		testEquivalentPrefix("*.*.*.*", 0);
		testEquivalentPrefix("0-127.*.*.*", 1);
		testEquivalentPrefix("128-255.*.*.*", 1);
		testEquivalentPrefix("*.*.*.*/1", 0);
		testEquivalentPrefix("0.*.*.*/1", isNoAutoSubnets ? 8 : 1);
		testEquivalentPrefix("128-255.*.*.*/1", 1);
		testEquivalentPrefix("1.2.*.*", 16);
		testEquivalentPrefix("1.2.*.*/24", 16);
		testEquivalentPrefix("1.2.*.0/24", isNoAutoSubnets ? null : 16, isNoAutoSubnets ? 32 : 16);
		testEquivalentPrefix("1.2.0-255.0/24", isNoAutoSubnets ? null : 16, isNoAutoSubnets ? 32 : 16);
		testEquivalentPrefix("1.2.1.0/24", isNoAutoSubnets ? 32 : 24);
		testEquivalentPrefix("1.2.1.*/24", 24);
		testEquivalentPrefix("1.2.1.*", 24);
		testEquivalentPrefix("1.2.*.4", null, 32);
		testEquivalentPrefix("1.2.252-255.*", 22);
		testEquivalentPrefix("1.2.252-255.0-255", 22);
		testEquivalentPrefix("1.2.0-3.0-255", 22);
		testEquivalentPrefix("1.2.128-131.0-255", 22);
		testEquivalentPrefix("1.2.253-255.0-255", null, 24);
		testEquivalentPrefix("1.2.252-255.0-254", null, 32);
		testEquivalentPrefix("1.2.251-255.0-254", null, 32);
		testEquivalentPrefix("1.2.251-255.0-255", null, 24);
		
		testEquivalentPrefix("1.2.1-3.*", null, 24);
		testEquivalentPrefix("1.2.0-3.*", 22);
		
		testEquivalentPrefix("*:*", 0);
		testEquivalentPrefix("::/0", isNoAutoSubnets ? 128 : 0);
		testEquivalentPrefix("0-1::/0", allPrefixesAreSubnets ? 0 : null, allPrefixesAreSubnets ? 0 : 128);
		testEquivalentPrefix("::/1", isNoAutoSubnets ? 128 : 1);
		testEquivalentPrefix("0-1::/1", allPrefixesAreSubnets ? 1 : null, allPrefixesAreSubnets ? 1 : 128);
		testEquivalentPrefix("8000-ffff::/1", allPrefixesAreSubnets ? 1 : null, allPrefixesAreSubnets ? 1 : 128);
		testEquivalentPrefix("8000-ffff:*", 1);
		testEquivalentPrefix("7fff-ffff:*", null, 16);
		testEquivalentPrefix("7fff-ffff:*/1", allPrefixesAreSubnets ? 0 : null, allPrefixesAreSubnets ? 0 : 16);
		testEquivalentPrefix("11:8000-ffff:*/1", allPrefixesAreSubnets ? 1 : 17);
		testEquivalentPrefix("11:8000-ffff:*", 17);
		testEquivalentPrefix("1:2:*", 32);
		testEquivalentPrefix("1:2:*:*::/64", isNoAutoSubnets ? null : 32, isNoAutoSubnets ? 128 : 32);
		testEquivalentPrefix("1:2:*:*/64", 32);
		testEquivalentPrefix("1:2:3:4:5:*:*/64", allPrefixesAreSubnets ? 64 : 80);
		testEquivalentPrefix("1:2:*::/64", null, isNoAutoSubnets ? 128 : 64);
		testEquivalentPrefix("1:2:*::", null, 128);
		testEquivalentPrefix("1:2:8000-ffff:*", 33);
		testEquivalentPrefix("1:2:0000-7fff:*", 33);
		testEquivalentPrefix("1:2:c000-ffff:*", 34);
		testEquivalentPrefix("1:2:0000-3fff:*", 34);
		testEquivalentPrefix("1:2:8000-bfff:*", 34);
		testEquivalentPrefix("1:2:4000-7fff:*", 34);
		testEquivalentPrefix("1:2:fffc-ffff:*", 46);
		testEquivalentPrefix("1:2:fffc-ffff:0-ffff:*", 46);
		testEquivalentPrefix("1:2:fffd-ffff:0-ffff:*", null, 48);
		testEquivalentPrefix("1:2:fffc-ffff:0-fffe:*", null, 64);
		testEquivalentPrefix("1:2:fffb-ffff:0-fffe:*", null, 64);
		testEquivalentPrefix("1:2:fffb-ffff:0-ffff:*", null, 48);
		
		testReverseHostAddress("*.*.0-240.0/20");
		testReverseHostAddress("*.*.0.0/16");
		testReverseHostAddress("*:0-f000::/20");
		
		testTrees();

		testStrings();
		
		testReverse("1:2:*:4:5:6:a:b", false, false);
		testReverse("1:1:1:1-fffe:2:3:3:3", false, false);
		testReverse("1:1:1:0-fffe:1-fffe:*:1:1", false, false);
		testReverse("ffff:80:*:ff:01:ffff", false, false);
		testReverse("ffff:8000:fffe::7fff:0001:ffff", true, false);
		testReverse("ffff:8000:*:8000:1:*:01:ffff", true, false);
		testReverse("ffff:8118:ffff:*:1-fffe:ffff", false, true);
		testReverse("ffff:8181:c3c3::4224:2400:0-fffe", false, true);
		testReverse("ffff:1:ff:ff:*:*", false, false);
		
		if(allPrefixesAreSubnets) {
			testMatches(true, "1.2.3.4/16", "1.2.*.*");
			testMatches(true, "1.2.3.4/16", "1.2.*");
			testMatches(false, "1.2.3.4/15", "1.2.*.*");
			testMatches(false, "1.2.3.4/17", "1.2.*.*");
		} else {
			testMatches(true, "1.2.3.4/16", "1.2.3.4");
			testMatches(true, "1.2.3.4/15", "1.2.3.4");
			testMatches(true, "1.2.3.4/17", "1.2.3.4");
			
			testMatches(true, "1.2.0.4/16", "1.2.0.4");
			testMatches(true, "1.2.3.0/16", "1.2.3.0");
			
			testMatches(true, "1.2.3.4/14", "1.2.3.4");
			testMatches(true, "1.2.0.4/14", "1.2.0.4");
			testMatches(true, "1.2.0.0/14", "1.2.0.0");
			testMatches(true, "1.0.3.0/14", "1.0.3.0");
			
		}
		
		testMatches(!isNoAutoSubnets, "1.2.0.0/16", "1.2.*.*");
		testMatches(!isNoAutoSubnets, "1.2.0.0/16", "1.2.*");
		
		testMatches(!isNoAutoSubnets, "1.4.0.0/14", "1.4-7.*");
		testMatches(!isNoAutoSubnets, "1.4.0.0/14", "1.4-7.*.*");
		
		testMatches(allPrefixesAreSubnets, "1.2.3.4/16", "1.2.*/255.255.0.0");
		testMatches(allPrefixesAreSubnets, "1.2.3.4/15", "1.2.3.*/255.254.0.0");
		testMatches(allPrefixesAreSubnets, "1.2.3.4/17", "1.2.3.*/255.255.128.0");
		
		testMatches(!isNoAutoSubnets, "1.2.0.0/16", "1.2.*/255.255.0.0");
		testMatches(true, "1.2.3.*/15", "1.2.3.*/255.254.0.0");
		testMatches(true, "1.2.3.*/17", "1.2.3.*/255.255.128.0");
		
		
		
		testMatches(false, "1.1.3.4/15", "1.2.3.*/255.254.0.0");
		testMatches(false, "1.1.3.4/17", "1.2.3.*/255.255.128.0");
		
		testMatches(!isNoAutoSubnets, "1:2::/32", "1:2:*:*:*:*:*:*");
		testMatches(!isNoAutoSubnets, "1:2::/32", "1:2:*:*:*:*:*.*.*.*");
		testMatches(!isNoAutoSubnets, "1:2::/32", "1:2:*");
		testMatches(false, "1:2::/32", "1:2:*:*:*:*:3:*");
		testMatches(false, "1:2::/32", "1:2:*:*:*:*:*.*.3.*");
		testMatches(false, "1:2::/31", "1:2:*");
		testMatches(false, "1:2::/33", "1:2::*");
		
		testMatches(!isNoAutoSubnets, "1:2::/32", "1:2:*:*:*:*:*:*/ffff:ffff::");
		testMatches(!isNoAutoSubnets, "1:2::/31", "1:2:*:*:*:*:*:*/ffff:fffe::");
		testMatches(!isNoAutoSubnets, "1:2::/33", "1:2:0:*:*:*:*:*/ffff:ffff:8000::");
		
		testMatches(allPrefixesAreSubnets, "1:2::/24", "1:__:*");
		testMatches(allPrefixesAreSubnets, "1:2::/28", "1:_::/32");
		testMatches(allPrefixesAreSubnets, "1:2::/20", "1:___::/32");
		testMatches(allPrefixesAreSubnets, "1:2::/16", "1:____::/32");
		testMatches(allPrefixesAreSubnets, "1:ffef::/24", "1:ff__::/32");
		testMatches(allPrefixesAreSubnets, "1:ffef::/24", "1:ff__:*:*");
		
		testMatches(!isNoAutoSubnets, "1::/24", "1:__:*");
		testMatches(!isNoAutoSubnets, "1::/28", "1:_::/32");
		testMatches(!isNoAutoSubnets, "1::/20", "1:___::/32");
		testMatches(!isNoAutoSubnets, "1::/16", "1:____::/32");
		testMatches(!isNoAutoSubnets, "1:ff00::/24", "1:ff__::/32");
		testMatches(!isNoAutoSubnets, "1:ff00::/24", "1:ff__:*:*");
		
		
		testMatches(true, "250-255.200-255.0-255.20-29", "25_.2__.___.2_");
		testMatches(true, "150-159.100-199.0-99.10-19", "15_.1__.__.1_");
		testMatches(false, "251-255.200-255.0-255.20-29", "25_.2__.___.2_");
		testMatches(false, "150-158.100-199.0-99.10-19", "15_.1__.__.1_");
		testMatches(true, "250-25f:200-2ff:0-fff:20-2f::", "25_:2__:___:2_::");
		testMatches(true, "150-15f:100-1ff:0-ff:10-1f::", "15_:1__:__:1_::");
		testMatches(false, "250-25f:201-2ff:0-fff:20-2f::", "25_:2__:___:2_::");
		testMatches(false, "150-15f:100-1ef:0-ff:10-1f::", "15_:1__:__:1_::");
		testMatches(true, "::250-25f:200-2ff:0-fff:20-2f", "::25_:2__:___:2_");
		testMatches(true, "::150-15f:100-1ff:0-ff:10-1f", "::15_:1__:__:1_");
		testMatches(true, "250-25f:200-2ff::0-fff:20-2f", "25_:2__::___:2_");
		testMatches(true, "150-15f:100-1ff::0-ff:10-1f", "15_:1__::__:1_");
		
		testMatches(true, "1:2:3:4:5:6:1.2.0.4-5", "1:2:3:4:5:6:102:4-5"); //mixed ending with range
		testMatches(true, "1:2:3:4:5:6:1.2.0.*", "1:2:3:4:5:6:102:0-ff"); //mixed ending with range
		testMatches(true, "1:2:3:4:5:6:1.2.0._", "1:2:3:4:5:6:102:0-9"); //mixed ending with range
		testMatches(true, "1:2:3:4:5:6:1.2.0.1_", "1:2:3:4:5:6:102:a-13"); //mixed ending with range
		
		testMatches(true, "1.2.3", "1.2.0.3", true);
		testMatches(true, "1.2.2-3.4", "0x1.0x2.2-0x3.0x4", true);
		testMatches(true, "1.2.2-3.4", "0x1.0x2.0x2-0x3.0x4", true);
		testMatches(true, "1.2.2-3.4", "0x1.0x2.0x2-3.0x4", true);
		testMatches(true, "1.2.2-3.4", "01.02.2-03.04", true);
		testMatches(true, "1.2.2-3.4", "01.02.2-3.04", true);
		testMatches(true, "1.2.2-3.4", "01.02.02-03.04", true);
		testMatches(true, "1.2.2-3.4", "01.02.0x2-03.04", true);
		testMatches(true, "1.2.2-3.4", "01.02.0x2-0x3.04", true);
		testMatches(true, "1.2.0200-0277.4", "01.02.02__.04", true);
		testMatches(true, "1.2.0x20-0x2f.4", "01.02.0x2_.04", true);
		testMatches(true, "1.2.0x10-0x1f.4", "01.02.0x1_.04", true);
		testMatches(true, "1.2.*.4", "01.02.0x__.04", true);
		testMatches(true, "1.2.0-077.4", "01.02.0__.04", true);
		
		testMatches(true, "1.2.2-3.4", "01.02.0x2-0x3.04", true);
		
		testMatches(true, "0.0.0-1.4", "00.0x0.0x00-0x000001.04", true);
		testMatches(true, "11.10-11.10-11.10-11", "11.012-0xb.0xa-013.012-0xB", true);
		testMatches(true, "11.10-11.*.10-11", "11.012-0xb.0x0-0xff.012-0xB", true);
		testMatches(true, "1.*", "1.*.*.0x0-0xff", true);
		testMatches(true, "1.*", "1.0-255.0-65535", true);
		testMatches(true, "1.*", "1.0-0xff.0-0xffff", true);
		testMatches(true, "1.*", "1.0x0-0xff.00-0xffff", true);
		
		testMatches(true, "11.11.0-11.*", "11.11.0-0xbff", true);
		testMatches(true, "11.0.0.11-11", "11.0x00000000000000000b-0000000000000000000013", true);
		testMatches(true, "11.1-11.*/16", "11.0x10000-786431/16", true);
		testMatches(true, "11.1-11.*/16", "11.0x10000-0xbffff/16", true);
		
		testMatches(true, "1:2:3:4:5:6:1.2.3.4/128", "1:2:3:4:5:6:102:304");
		
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.3.4/96", "1:2:3:4:5:6:*:*");
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:255.2.3.4/97", "1:2:3:4:5:6:8000-ffff:*");
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.3.4/112", "1:2:3:4:5:6:102:*");
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.255.4/115", "1:2:3:4:5:6:102:e000-ffff");
		
		testMatches(allPrefixesAreSubnets, "1.2.3.4/0", "*.*");
		testMatches(allPrefixesAreSubnets, "1.2.3.4/0", "*.*.*.*");
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:7:8/0", "*:*");
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:7:8/0", "*:*:*:*:*:*:*:*");
		
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.3.4/96", "1:2:3:4:5:6:102:304");
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:255.2.3.4/97", "1:2:3:4:5:6:ff02:304");
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.3.4/112", "1:2:3:4:5:6:102:304");
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.255.4/115", "1:2:3:4:5:6:102:ff04");
		
		testMatches(!allPrefixesAreSubnets, "1.2.3.4/0", "1.2.3.4");
		testMatches(!allPrefixesAreSubnets, "1.2.3.4/0", "1.2.3.4");
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:7:8/0", "1:2:3:4:5:6:7:8");
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:7:8/0", "1:2:3:4:5:6:7:8");
		
		
		testMatches(!isNoAutoSubnets, "1:2:3:4:5:6:0.0.0.0/96", "1:2:3:4:5:6:*:*");
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:255.0.0.0/97", "1:2:3:4:5:6:8000-ffff:*");
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:255.0.0.0/97", "1:2:3:4:5:6:ff00:0");
		testMatches(!isNoAutoSubnets, "1:2:3:4:5:6:128.0.0.0/97", "1:2:3:4:5:6:8000-ffff:*");
		testMatches(!isNoAutoSubnets, "1:2:3:4:5:6:1.2.0.0/112", "1:2:3:4:5:6:102:*");
		testMatches(allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.255.0/115", "1:2:3:4:5:6:102:e000-ffff");
		testMatches(!allPrefixesAreSubnets, "1:2:3:4:5:6:1.2.255.0/115", "1:2:3:4:5:6:102:FF00");
		testMatches(!isNoAutoSubnets, "1:2:3:4:5:6:1.2.224.0/115", "1:2:3:4:5:6:102:e000-ffff");
		
		testMatches(!isNoAutoSubnets, "0.0.0.0/0", "*.*");
		testMatches(!isNoAutoSubnets, "0.0.0.0/0", "*.*.*.*");
		testMatches(!isNoAutoSubnets, "::/0", "*:*");
		testMatches(!isNoAutoSubnets, "::/0", "*:*:*:*:*:*:*:*");
		
		
		testMatches(true, "1-02.03-4.05-06.07", "1-2.3-4.5-6.7");
		testMatches(true, "1-002.003-4.005-006.007", "1-2.3-4.5-6.7");
		
		testMatches(true, "1-2.0-0.00-00.00-0", "1-2.0.0.0");
		testMatches(true, "1-2:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "1-2:0:0:0:0:0:0:0");
		testMatches(true, "00-0.0-0.00-00.00-0", "0.0.0.0");
		testMatches(true, "0-00:0-0:00-00:00-0:0-000:0000-0000:0000-00:0000-0", "::");
		
		testMatches(true, "-1.22.33.4", "0-1.22.33.4");
		testMatches(true, "-1.22.33.4", "0-1.22.33.4");
		testMatches(true, "22.1-.33.4", "22.1-255.33.4");
		testMatches(true, "22.33.4.1-", "22.33.4.1-255");
		testMatches(true, "aa:-1:cc::d:ee:f", "aa:0-1:cc::d:ee:f");
		testMatches(true, "aa:dd-:cc::d:ee:f", "aa:dd-ffff:cc::d:ee:f");
		testMatches(true, "::1:0:0:0.0.0.0", "0:0:0:1::0.0.0.0");
		
		testMatches(true, "1::-1:16", "1::0-1:16");
		if(isNoAutoSubnets) {
			testMatches(true, "1::-1:16/16", "1::0-1:16");
			testMatches(true, "1::-1:16", "1::0-1:16/16");
			testMatches(true, "1:-1::16/16", "1:0-1::16");
			testMatches(true, "1:-1::16", "1:0-1::16/16");
		} else if(allPrefixesAreSubnets) {
			testMatches(true, "1:-1::16/32", "1:0-1:*");
			testMatches(true, "1:-1:*", "1:0-1::16/32");
		} else {
			testMatches(true, "1:-1::16/32", "1:0-1::16");
			testMatches(true, "1:-1::16", "1:0-1::16/32");
		}
		if(allPrefixesAreSubnets) {
			testCIDRSubnets("9.*.237.26/0", "0.0.0.0/0");
			testCIDRSubnets("9.*.237.26/1", "0.0.0.0/1");
			testCIDRSubnets("9.*.237.26/4", "0.0.0.0/4");
			testCIDRSubnets("9.*.237.26/5", "8.0.0.0/5");
			testCIDRSubnets("9.*.237.26/7", "8.0.0.0/7");
			testCIDRSubnets("9.*.237.26/8", "9.0.0.0/8");
			testCIDRSubnets("9.*.237.26/9", "9.0-128.0.0/9");
			testCIDRSubnets("9.*.237.26/16", "9.*.0.0/16");
			testCIDRSubnets("9.*.237.26/30", "9.*.237.24/30");
			testCIDRSubnets("9.*.237.26/31", "9.*.237.26/31");
			testCIDRSubnets("9.*.237.26/32", "9.*.237.26/32");
		} else {
			testCIDRSubnets("9.*.237.26/0", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/1", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/4", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/5", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/7", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/8", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/9", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/16", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/30", "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/31", !isNoAutoSubnets ? "9.*.237.26-27" : "9.*.237.26", false);
			testCIDRSubnets("9.*.237.26/32", "9.*.237.26", false);
		}
		
		testSubnet("1.2-4.3.4", "255.255.254.255", 24, allPrefixesAreSubnets ? "1.2-4.2.0/24" : "1.2-4.2.4/24", "1.2-4.2.4", allPrefixesAreSubnets ? "1.2-4.3.0/24" : "1.2-4.3.4/24");
		testSubnet("1.2-4.3.4", "255.248.254.255", 24, allPrefixesAreSubnets ? "1.0.2.0/24" : "1.0.2.4/24", "1.0.2.4", allPrefixesAreSubnets ? "1.2-4.3.0/24" : "1.2-4.3.4/24");
		
		testSubnet("__::", "ffff::", 128, "0-ff:0:0:0:0:0:0:0/128", "0-ff:0:0:0:0:0:0:0", "0-ff:0:0:0:0:0:0:0/128");
		testSubnet("0-ff::", "fff0::", 128, null, null, "0-ff:0:0:0:0:0:0:0/128");
		
		testSubnet("0-ff::", "fff0::", 12, 
				allPrefixesAreSubnets ? "0-f0:0:0:0:0:0:0:0/12" : "0-ff:0:0:0:0:0:0:0/12", 
				null, 
				allPrefixesAreSubnets ? "0-f0:0:0:0:0:0:0:0/12" : "0-ff:0:0:0:0:0:0:0/12");
		testSubnet("0-f0::", "fff0::", 12, 
				"0-f0:0:0:0:0:0:0:0/12", "0-f0:0:0:0:0:0:0:0", "0-f0:0:0:0:0:0:0:0/12");
		testSubnet("0-f::*", "fff0::ffff", 12, allPrefixesAreSubnets ? "0:0:0:0:0:0:0:0/12" : "0-f:0:0:0:0:0:0:*/12", "0:0:0:0:0:0:0:*", allPrefixesAreSubnets ? "0:0:0:0:0:0:0:0/12" : "0-f:0:0:0:0:0:0:*/12");
		
		
		testSubnet("::1:__", "::1:ffff", 128, "0:0:0:0:0:0:1:0-ff/128", "0:0:0:0:0:0:1:0-ff", "0:0:0:0:0:0:1:0-ff/128");
		testSubnet("::1:__", "::1:ffff", 126, isNoAutoSubnets ? "0:0:0:0:0:0:1:0-ff/126" : "0:0:0:0:0:0:1:0-fc/126", "0:0:0:0:0:0:1:0-ff", isNoAutoSubnets ? "0:0:0:0:0:0:1:0-ff/126" : "0:0:0:0:0:0:1:0-fc/126");
		testSubnet("::1:0-ff", "::1:fff0", 128, null, null, "0:0:0:0:0:0:1:0-ff/128");
		testSubnet("::1:0-ff", "::1:fff0", 124, isNoAutoSubnets ? "0:0:0:0:0:0:1:0-ff/124" : "0:0:0:0:0:0:1:0-f0/124", null, isNoAutoSubnets ? "0:0:0:0:0:0:1:0-ff/124" : "0:0:0:0:0:0:1:0-f0/124");
		testSubnet("*::1:0-f", "ffff::1:fff0", 124, isNoAutoSubnets ? "*:0:0:0:0:0:1:0-f/124" : "*:0:0:0:0:0:1:0/124", "*:0:0:0:0:0:1:0", isNoAutoSubnets ? "*:0:0:0:0:0:1:0-f/124" : "*:0:0:0:0:0:1:0/124");
		
		testBitwiseOr("1.2.0.0/16", 8, "0.0.3.248", isNoAutoSubnets ? "1.2.3.248" : "1.2.3.248-255");
		testBitwiseOr("1.2.0.0/16", 7, "0.0.2.0", isNoAutoSubnets ? "1.2.2.0" : "1.2.2-3.*");
		testBitwiseOr("1.2.*.*", 7, "0.0.3.0", null);
		testBitwiseOr("1.2.0-3.*", 0, "0.0.3.0", "1.2.3.*");
		testBitwiseOr("1.2.0.0/16", 7, "0.0.3.0", isNoAutoSubnets ? "1.2.3.0" : "1.2.3.*");
		testBitwiseOr("0.0.0.0/0", 0, "128.192.224.240", isNoAutoSubnets ? "128.192.224.240" : "128-255.192-255.224-255.240-255");
		testBitwiseOr("*.*", 0, "128.192.224.240", "128-255.192-255.224-255.240-255");
		testBitwiseOr("0.0.0.0/0", 0, "128.192.224.64", isNoAutoSubnets ? "128.192.224.64" : null);
		testBitwiseOr("*.*", 0, "128.192.224.64", null);
		testPrefixBitwiseOr("1.3.0.0/15", 24, "0.0.255.1", allPrefixesAreSubnets ? "1.2-3.255.0/24" : "1.3.255.0/24", "1.3.255.1/15");
		testPrefixBitwiseOr("1.3.0.1/15", 24, "0.0.255.1", allPrefixesAreSubnets ? "1.2-3.255.0/24" : "1.3.255.1/24", "1.3.255.1/15");
		testPrefixBitwiseOr("1.3.0.1/15", 24, "0.0.255.0", allPrefixesAreSubnets ? "1.2-3.255.0/24" : "1.3.255.1/24", "1.3.255.1/15");
		testPrefixBitwiseOr("1.2.0.0/22", 24, "0.0.3.248", "1.2.3.0/24", isNoAutoSubnets ? "1.2.3.248/22" : (allPrefixesAreSubnets ? "1.2.0.0/22" : "1.2.3.248-255/22"));
		testPrefixBitwiseOr("1.2.0.0/24", 24, "0.0.3.248", "1.2.3.0/24", isNoAutoSubnets ? "1.2.3.248/24" : (allPrefixesAreSubnets ? "1.2.3.0/24" : "1.2.3.248-255/24"));
		testPrefixBitwiseOr("1.2.0.0/22", 23, "0.0.3.0", "1.2.2.0/23", allPrefixesAreSubnets ? "1.2.0.0/22" : (isNoAutoSubnets ? "1.2.3.0/22" : "1.2.3.0-255/22"));
		testPrefixBitwiseOr("1.2.0.0/24", 23, "0.0.3.0", "1.2.2.0/23", allPrefixesAreSubnets ? "1.2.3.0/24" : (isNoAutoSubnets ? "1.2.3.0/24" : "1.2.3.0-255/24"));
		testPrefixBitwiseOr("1:2::/46", 47, "0:0:3::", "1:2:2::/47", isNoAutoSubnets || allPrefixesAreSubnets ? "1:2:3::/46" : "1:2:3:*:*:*:*:*/46");
		
		testPrefixBitwiseOr("0.0.0.0/16", 18, "0.0.2.8", isNoAutoSubnets ? "0.0.0.0/18" : "0.0.0-192.0/18", isNoAutoSubnets || allPrefixesAreSubnets ? "0.0.2.8/16" : null);
		
		
		testBitwiseOr("1:2::/32", 16, "0:0:3:fff8::", isNoAutoSubnets ? "1:2:3:fff8::" : "1:2:3:fff8-ffff:*");
		testBitwiseOr("1:2::/32", 15, "0:0:2::", isNoAutoSubnets ? "1:2:2::" : "1:2:2-3:*");
		testBitwiseOr("1:2:*", 0, "0:0:8000::", "1:2:8000-ffff:*");
		testBitwiseOr("1:2:*", 0, "0:0:c000::", "1:2:c000-ffff:*");
		testBitwiseOr("1:2::/32", 15, "0:0:3::", isNoAutoSubnets ? "1:2:3::" : "1:2:3:*");
		testBitwiseOr("::/0", 0, "8000:c000:e000:fff0::", isNoAutoSubnets ? "8000:c000:e000:fff0::" : "8000-ffff:c000-ffff:e000-ffff:fff0-ffff:*");
		testBitwiseOr("*:*", 0, "8000:c000:e000:fff0::", "8000-ffff:c000-ffff:e000-ffff:fff0-ffff:*");
		testBitwiseOr("::/0", 0, "8000:c000:e000:4000::", isNoAutoSubnets ? "8000:c000:e000:4000::" : null);
		testBitwiseOr("1:1::/16", 32, "0:2:3::ffff", isNoAutoSubnets ?  "1:2:3::ffff" : "1:2:3:*:*:*:*:ffff");//note the prefix length is dropped to become "1.2.3.*", but equality still holds
		testBitwiseOr("1:0:0:1::/16", 32, "0:2:3::ffff", allPrefixesAreSubnets ? "1:2:3:*:*:*:*:ffff" : "1:2:3:1::ffff");//note the prefix length is dropped to become "1.2.3.*", but equality still holds
		testPrefixBitwiseOr("::/32", 34, "0:0:2:8::", isNoAutoSubnets ? "::/34" : "0:0:0-c000::/34", isNoAutoSubnets || allPrefixesAreSubnets ? "0:0:2:8::/32" : null);
		
		testDelimitedCount("1,2-3,4:3:4,5:6:7:8:ffff:ffff", 8); 
		testDelimitedCount("1,2::3,6:7:8:4,5-6:6,8", 16);
		testDelimitedCount("1:2:3:*:4::5", 1);
		testDelimitedCount("1:2,3,*:3:ffff:ffff:6:4:5,ff,7,8,99", 15);
		testDelimitedCount("0,1-2,3,5:3::6:4:5,ffff,7,8,99", 30);
		
		boolean isAutoSubnets = !isNoAutoSubnets;
		boolean isAllSubnets = allPrefixesAreSubnets;
		
		testContains("0.0.0.0/0", "1-2.*.3.*", isAutoSubnets, false);
		if(allPrefixesAreSubnets) {
			testContains("0-127.0.0.0/1", "127-127.*.3.*", false);
		}
		testContains("0-127.0.0.0/8", "127-127.*.3.*", isAutoSubnets, false);
		testContains("0.0.0.0/4", "13-15.*.3.*", isAutoSubnets, false);
		testContains("0-15.*.*.*/4", "13-15.*.3.*", true, false);
		testContains("0.0.0.0/4", "9.*.237.*/16", isAutoSubnets, false);
		testContains("0.0.0.0/4", "8-9.*.237.*/16", isAutoSubnets, false);
		if(allPrefixesAreSubnets) {
			testContains("1-2.0.0.0/4", "9.*.237.*/16", false);
			testContains("1-2.0.0.0/4", "8-9.*.237.*/16", false);
		} else {
			testNotContains("1-2.0.0.0/4", "9.*.237.*/16");
			testNotContains("1-2.0.0.0/4", "8-9.*.237.*/16");
		}
		testNotContains("1-2.0.0.0/4", "9-17.*.237.*/16");
		testContains("8.0.0.0/5", "15.2.3.4", isAutoSubnets, false);
		testContains("8.0.0.0/7", "8-9.*.3.*", isAutoSubnets, false);
		testContains("9.0.0.0/8", "9.*.3.*", isAutoSubnets, false);
		testContains("9.128.0.0/9", "9.128-255.*.0", isAutoSubnets, false);
		testContains("9.128.0.0/15", "9.128-129.3.*", isAutoSubnets, false);
		testContains("9.129.0.0/16", "9.129.3.*", isAutoSubnets, false);
		testNotContains("9.129.0.0/16", "9.128-129.3.*");
		testNotContains("9.129.0.0/16", "9.128.3.*");
		testContains("9.129.237.24/30", "9.129.237.24-27", isAutoSubnets, true);
		testContains("9.129.237.24/30", "9.129.237.24-27/31", isAutoSubnets, true);
		testContains("9.129.237.24-27/30", "9.129.237.24-27/31", true, true);

		testContains("*.*.*.*/0", "9.129.237.26/0", true, isAllSubnets);
		testContains("0.0.0.0/0", "*.*.*.*/0", isAutoSubnets, true);
		testContains("0.0.0.0/4", "0-15.0.0.*/4", isAutoSubnets, isAllSubnets);
		testNotContains("192.0.0.0/4", "0-15.0.0.*/4");
		
		if(allPrefixesAreSubnets) {
			testContains("0-127.129.237.26/1", "0-127.0.*.0/1", true);
			testContains("9.129.237.26/0", "*.*.*.*/0", true);
			testContains("9.129.237.26/4", "0-15.0.0.*/4", true);
			testContains("1-16.0.0.*/4", "9.129.237.26/4", false);
			testContains("9.129.237.26/5", "8-15.0.0.0/5", true);
			testContains("9.129.237.26/7", "8-9.0.0.1-3/7", true);
			testContains("7-9.0.0.1-3/7", "9.129.237.26/7", false);
			testContains("9.129.237.26/8", "9.*.0.0/8", true);
			testContains("9.129.237.26/9", "9.128-255.0.0/9", true);
			testContains("9.129.237.26/15", "9.128-129.0.*/15", true);
			testContains("9.129.237.26/16", "9.129.*.*/16", true);
			testContains("9.129.237.26/30", "9.129.237.24-27/30", true);	
		} else {
			testNotContains("0-127.129.237.26/1", "0-127.0.*.0/1");
			testNotContains("9.129.237.26/0", "*.*.*.1/0");
			testNotContains("9.129.237.26/4", "0-15.0.1.*/4");
			testNotContains("1-16.0.0.*/4", "9.129.237.26/4");
			testNotContains("9.129.237.26/5", "8-15.0.0.0/5");
			testNotContains("9.129.237.26/7", "8-9.0.0.1-3/7");
			testNotContains("7-9.0.0.1-3/7", "9.129.237.26/7");
			testNotContains("9.129.237.26/8", "9.*.0.0/8");
			testNotContains("9.129.237.26/9", "9.128-255.0.0/9");
			testNotContains("9.129.237.26/15", "9.128-129.0.*/15");
			testNotContains("9.129.237.26/16", "9.129.*.1/16");
			testNotContains("9.129.237.26/30", "9.129.237.27/30");
		}
		
		testContains("0.0.0.*/4", "9.129.237.26/4", isAutoSubnets, isAllSubnets);
		testContains("8.0.0.*/5", "8-15.0.0.0/5", isAutoSubnets, isAllSubnets);
		testContains("8.0.0.*/7", "8-9.0.0.1-3/7", isAutoSubnets, isAllSubnets);
		testContains("7-9.*.*.*/7", "9.129.237.26/7", true, false);
		testContains("9.0.0.0/8", "9.*.0.0/8", isAutoSubnets, isAllSubnets);
		testContains("9.128.0.0/9", "9.128-255.0.0/9", isAutoSubnets, isAllSubnets);
		testContains("9.128.0.0/15", "9.128-129.0.*/15", isAutoSubnets, isAllSubnets);
		testContains("9.128.0.0/15", "9.128.0.*/15", isAutoSubnets, true);
		testContains("9.129.0.0/16", "9.129.*.*/16", isAutoSubnets, true);
		testContains("9.128.*.*/15", "9.128.0.*/15", true, isAutoSubnets);
		testContains("9.128.*.*/16", "9.128.0.*/16", true, isAutoSubnets);
		testContains("9.129.*.*/16", "9.129.*.*/16", true, true);
		testContains("9.129.*.*/16", "9.129.*.0/16", true, isAllSubnets);
		testContains("9.129.237.24/30", "9.129.237.24-27/30", isAutoSubnets, true);
		testContains("9.128-129.*.26/32", "9.128-129.*.26/32", true, true);
		
		
		if(allPrefixesAreSubnets) {
			testContains("1-16.0.0.*/4", "9.129.237.26/4", false);
			testContains("9.129.237.26/5", "8-15.0.0.0/5", true);
			testContains("9.129.237.26/7", "8-9.0.0.1-3/7", true);
			testContains("7-9.0.0.1-3/7", "9.129.237.26/7", false);
			testContains("9.129.237.26/8", "9.*.0.0/8", true);
			testContains("9.129.237.26/9", "9.128-255.0.0/9", true);
			testContains("9.129.237.26/15", "9.128-129.0.*/15", true);
			testContains("9.129.237.26/16", "9.129.*.*/16", true);
			testContains("9.129.237.26/30", "9.129.237.24-27/30", true);
			
		} else {
			testNotContains("1-16.0.0.*/4", "9.129.237.26/4");
			testNotContains("9.129.237.26/5", "8-15.0.0.0/5");
			testNotContains("9.129.237.26/7", "8-9.0.0.1-3/7");
			testNotContains("7-9.0.0.1-3/7", "9.129.237.26/7");
			testNotContains("9.129.237.26/8", "9.*.0.0/8");
			testNotContains("9.129.237.26/9", "9.128-255.0.0/9");
			testNotContains("9.129.237.26/15", "9.128-129.0.*/15");
			testNotContains("9.129.237.26/16", "9.129.*.1/16");
			testNotContains("9.129.237.26/16", "9.129.1.*/16");
			testNotContains("9.129.237.25/30", "9.129.237.26/30");
		}
		
		testContains("1-16.0.0.*/4", "9.0.0.*/4", true, false);
		testContains("1-16.0.0.0-254/4", "9.0.0.*/4", isAllSubnets, false);
		testContains("0-16.0.0.0/4", "9.0.0.*/4", isAutoSubnets, false);
		testContains("8-15.129.237.26/5", "9.129.237.26/5", true, isAllSubnets);
		testContains("8-9.129.237.26/7", "9.129.237.26/7", true, isAllSubnets);
		testContains("7-9.0.0.1-3/7", "9.0.0.2/7", true, false);
		testContains("9.*.237.26/8", "9.*.237.26/8", true, true);
		testContains("9.128-255.237.26/9", "9.129.237.26/9", true, isAllSubnets);
		testContains("9.128-129.237.26/15", "9.129.237.26/15", true, isAllSubnets);
		testContains("9.129.*.*/16", "9.129.237.26/16", true,  isAllSubnets);
		testContains("9.129.237.24-27/30", "9.129.237.26/30", true, isAllSubnets);
		testContains("9.128-129.*.26/32", "9.128-129.*.26/32", true, true);
		
		testNotContains("9.129.237.26/4", "16-17.0.0.*/4");
		testNotContains("9.129.237.26/7", "2.0.0.1-3/7");
		
		
		testContains("::ffff:1.*.3.4", "1.2.3.4", true, false);//ipv4 mapped
		if(allPrefixesAreSubnets) {
			testContains("::ffff:1.2-4.3.4/112", "1.2-3.3.*", false);
			testContains("ffff:0:0:0:0:0:*:0/32", "ffff:0:ffff:1-d:e:f:*:b", false);
			testContains("fffc-ffff::ffff/30", "fffd-fffe:0:0:0:0:0:0:0/30", false);
			testContains("ffff:0-d::ffff/32", "ffff:a-c:0:0:0:0:0:0/32", false);
			testContains("ffff::ffff/0", "a-b:0:b:0:c:d-e:*:0/0", true);
			testContains("ffff::ffff/1", "8000-8fff:0:0:0:0:*:a-b:0/1", true);
			testContains("ffff:*::ffff/126", "ffff:*:0:0:0:0:0:fffc-ffff/126", true);
			testContains("ffff:1-2::ffff/126", "ffff:1-2:0:0:0:0:0:fffc-ffff/126", true);
		} else {
			testNotContains("::ffff:1.2-4.3.4/112", "1.2-3.3.*");
			testNotContains("ffff:0:0:0:0:0:*:0/32", "ffff:0:ffff:1-d:e:f:*:b");
			testNotContains("fffc-ffff::ffff/30", "fffd-fffe:0:0:0:0:0:0:0/30");
			testNotContains("ffff:0-d::ffff/32", "ffff:a-c:0:0:0:0:0:0/32");
			testNotContains("ffff::ffff/0", "a-b:0:b:0:c:d-e:*:0/0");
			testNotContains("ffff::ffff/1", "8000-8fff:0:0:0:0:*:a-b:0/1");
			testNotContains("ffff:*::fffb/126", "ffff:*:0:0:0:0:0:fffc-ffff/126");
			testNotContains("ffff:1-2::fffb/126", "ffff:1-2:0:0:0:0:0:fffc-ffff/126");
		}
		testContains("::ffff:1.2-4.0.0/112", "1.2-3.3.*", isAutoSubnets, false);
		
		testContains("0:0:0:0:0:0:0:0/0", "a:*:c:d:e:1-ffff:a:b", isAutoSubnets, false);
		testContains("8000:0:0:0:0:0:0:0/1", "8000-8fff:b:c:d:e:f:*:b", isAutoSubnets, false);
		testNotContains("8000:0:0:0:0:0:0:0/1", "7fff-8fff:b:c:d:e:f:*:b");
		testContains("ffff:0:0:0:0:0:0:0/30", "ffff:0-3:c:d:e:f:a:b", isAutoSubnets, false);
		testNotContains("ffff:0:0:0:0:0:0:0/30", "ffff:0-4:c:d:e:f:a:b");
		
		testContains("ffff:0:0:0:0:0:0:0/32", "ffff:0:ffff:1-d:e:f:*:b", isAutoSubnets, false);
		testContains("fffc-ffff::/30", "fffd-fffe:0:0:0:0:0:0:0/30", true, false);
		testContains("ffff:0-d::/32", "ffff:a-c:0:0:0:0:0:0/32", true, false);
		
		testNotContains("ffff:0:0:0:0:1-2:0:0/32", "ffff:0-1:ffff:d:e:f:a:b");
		testContains("ffff:0:0:0:0:4-ffff:0:fffc-ffff", "ffff:0:0:0:0:4-ffff:0:fffd-ffff", true, false);
		testContains("ffff:0:0:0:0:4-ffff:0:fffc/126", "ffff:0:0:0:0:4-ffff:0:fffd-ffff", isAutoSubnets, false);
		testContains("ffff:0:0:0:0:4-ffff:0:fffc/126", "ffff:0:0:0:0:4-ffff:0:fffc-ffff", isAutoSubnets, true);
		testContains("ffff:0:*:0:0:4-ffff:0:ffff/128", "ffff:0:*:0:0:4-ffff:0:ffff", true, true);
		
		testContains("ffff:*:0:0:0:0:0:fffa-ffff/126", "ffff:*::ffff/126", true, false);
		
		testContains("::/0", "a-b:0:b:0:c:d-e:*:0/0", isAutoSubnets, isAllSubnets);
		testContains("8000::/1", "8000-8fff:0:0:0:0:*:a-b:0/1", isAutoSubnets, isAllSubnets);
		testContains("ffff:*::fffc/126", "ffff:*:0:0:0:0:0:fffc-ffff/126", isAutoSubnets, true);
		testContains("ffff:1-2::fffc/126", "ffff:1-2:0:0:0:0:0:fffc-ffff/126", isAutoSubnets, true);
		
		testContains("10.162.155.1-255", "10.162.155.1-51", false);
		testContains("10.162.155.1-51", "10.162.155.1-51", true);
		testContains("10.162.1-51.155", "10.162.1-51.155", true);
		testContains("10.162.1-255.155", "10.162.1-51.155", false);
		testContains("1-255.10.162.155", "1-51.10.162.155", false);
		
		testContains("10.162.155.0-255", "10.162.155.0-51", false);
		testContains("10.162.155.0-51", "10.162.155.0-51", true);
		testContains("10.162.0-51.155", "10.162.0-51.155", true);
		testContains("10.162.0-255.155", "10.162.0-51.155", false);
		testContains("0-255.10.162.155", "0-51.10.162.155", false);
		
		testNotContains("192.13.1.0/25", "192.13.1.1-255");
		testNotContains("192.13.1.1-255", "192.13.1.0/25");
		
		if(isAutoSubnets) {
			testContains("192.13.1.0/25", "192.13.1.1-127", false);
			testContains("192.13.1.0/25", "192.13.1.0-127", true);
		} else {
			testNotContains("192.13.1.0/25", "192.13.1.1-127");
		}
		testContains("192.13.1.0-127", "192.13.1.0/25", isAutoSubnets);
		
		testContains("ffff:1-3::/32", "ffff:2::", false);
		testContains("ffff:2-3::/32", "ffff:2::", false);
		testContains("ffff:1-3::/32", "ffff:3::", false);
		
		testNotContains("ffff:1-3::/32", "ffff:4::");
		
		testContains("ffff:1000-3000::/20", "ffff:2000::", false);
		testContains("ffff:2000-3000::/20", "ffff:2000::", false);
		testContains("ffff:1000-3000::/20", "ffff:3000::", false);
		
		testNotContains("ffff:1000-3000::/20", "ffff:4000::");
		testNotContains("ffff:2000-3000::/20", "ffff:4000::");
		
		if(isAutoSubnets) {
			testContains("ffff:1000::/20", "ffff:1111-1222::", false);
			testNotContains("ffff:1000::/20", "ffff:1-::");
		} else {
			testContains("ffff:1-::", "ffff:1000::/20", false);
		}
		testContains("ffff:1-:*", "ffff:1000::/20", false);
		testNotContains("ffff:1000::/20", "ffff:1111-2222::");
		testNotContains("ffff:1000::/20", "ffff:1-10::");
		testNotContains("ffff:1000::/20", "ffff:1-1::");
		
		testPrefix("25:51:27:*:*:*:*:*", null, 48, 48);
		testPrefix("25:51:27:*:*:*:*:*/48", 48, 48, 48);
		testPrefix("25:50-51:27::/48", 48, isAutoSubnets ? 48 : 128, null);
		testPrefix("25:50-51:27:*:*:*:*:*", null, 48, null);
		testPrefix("25:51:27:12:82:55:2:2", null, 128, 128);
		testPrefix("*:*:*:*:*:*:*:*", null, 0, 0);
		testPrefix("*:*:*:*:*:*:0-fe:*", null, 112, null);
		testPrefix("*:*:*:*:*:*:0-ff:*", null, 104, null);
		testPrefix("*:*:*:*:*:*:0-ffff:*", null, 0, 0);
		testPrefix("*:*:*:*:*:*:0-7fff:*", null, 97, null);
		testPrefix("*:*:*:*:*:*:8000-ffff:*", null, 97, null);
		testPrefix("*.*.*.*", null, 0, 0);
		testPrefix("3.*.*.*", null, 8, 8);
		testPrefix("3.*.*.1-3", null, 32, null);
		testPrefix("3.0-127.*.*", null, 9, 9);
		testPrefix("3.128-255.*.*", null, 9, 9);
		
		
		ipv4test(true, "1.2.*.4/1");
		ipv4test(false, "1.2.*.4/-1");
		ipv4test(false, "1.2.*.4/");
		ipv4test(false, "1.2.*.4/x");
		ipv4test(false, "1.2.*.4/33");//we are not allowing extra-large prefixes
		ipv6test(true, "1:*::1/1");
		ipv6test(false, "1:*::1/-1");
		ipv6test(false, "1:*::1/");
		ipv6test(false, "1:*::1/x");
		ipv6test(false, "1:*::1/129");//we are not allowing extra-large prefixes
		
		//masks that have wildcards in them
		ipv4test(false, "1.2.3.4/*");
		ipv4test(false, "1.2.*.4/*");
		ipv4test(false, "1.2.3.4/1-2.2.3.4");
		ipv4test(false, "1.2.*.4/1-2.2.3.4");
		ipv4test(false, "1.2.3.4/**");
		ipv4test(false, "1.2.*.4/**");
		ipv4test(false, "1.2.3.4/*.*");
		ipv4test(false, "1.2.*.4/*.*");
		ipv4test(false, "1.2.3.4/*:*");
		ipv4test(false, "1.2.*.4/*:*");
		ipv4test(false, "1.2.3.4/*:*:*:*:*:*:*:*");
		ipv4test(false, "1.2.*.4/*:*:*:*:*:*:*:*");
		ipv4test(false, "1.2.3.4/1.2.*.4");
		ipv4test(false, "1.2.*.4/1.2.*.4");
		ipv4test(true, "1.2.*.4/1.2.3.4");
		ipv6test(false, "1:2::1/*");
		ipv6test(false, "1:*::1/*");
		ipv6test(false, "1:2::1/1:1-2:3:4:5:6:7:8");
		ipv6test(false, "1:*::1/1:1-2:3:4:5:6:7:8");
		ipv6test(false, "1:2::1/**");
		ipv6test(false, "1:*::1/**");
		ipv6test(false, "1:2::1/*:*");
		ipv6test(false, "1:*::1/*:*");
		ipv6test(false, "1:2::1/*.*");
		ipv6test(false, "1:*::1/*.*");
		ipv6test(false, "1:2::1/*.*.*.*");
		ipv6test(false, "1:*::1/*.*.*.*");
		ipv6test(false, "1:2::1/1:*::2");
		ipv6test(false, "1:*::1/1:*::2");
		ipv6test(true, "1:*::1/1::2");
		
		testResolved("8.*.27.26", "8.*.27.26");
		
		testResolved("2001:*:0:0:8:800:200C:417A", "2001:*:0:0:8:800:200C:417A");
		
		testNormalized("ABCD:EF12:*:*:***:A:*:BBBB", "abcd:ef12:*:*:*:a:*:bbbb");
		testNormalized("ABCD:EF12:*:*:**:A:***:BBBB%g", "abcd:ef12:*:*:*:a:*:bbbb%g");
		
		testNormalized("1.*", "1.*.*.*");
		testNormalized("*.1.*", "*.1.*.*");
		testNormalized("*:1::*", "*:1::*");
		testNormalized("*:1:*", "*:1:*:*:*:*:*:*");
		testNormalized("001-002:0001-0002:01-2:1-02:01-02:*", "1-2:1-2:1-2:1-2:1-2:*:*:*");
		
		if(allPrefixesAreSubnets) {
			testIPv4Wildcarded("1.2.3.4", 8, "1.*.*.*", "1.%.%.%");
			testIPv4Wildcarded("1.2.3.4", 9, "1.0-127.*.*", "1.0-127.%.%");
			testIPv4Wildcarded("1.2.3.4", 15, "1.2-3.*.*", "1.2-3.%.%");
			testIPv4Wildcarded("1.3.3.4", 15, "1.2-3.*.*", "1.2-3.%.%");
			testIPv4Wildcarded("1.2.3.4", 16, "1.2.*.*", "1.2.%.%");
			testIPv6Wildcarded("1::1", 16, "1::/16", "1:*:*:*:*:*:*:*", "1:%:%:%:%:%:%:%");
			testIPv4Wildcarded("1.3.0.0", 15, "1.2-3.*.*", "1.2-3.%.%");
		} else {
			testIPv4Wildcarded("1.2.3.4", 8, "1.2.3.4", "1.2.3.4");
			testIPv4Wildcarded("1.2.3.4", 9, "1.2.3.4", "1.2.3.4");
			testIPv4Wildcarded("1.2.3.4", 15, "1.2.3.4", "1.2.3.4");
			testIPv4Wildcarded("1.3.3.4", 15, "1.3.3.4", "1.3.3.4");
			testIPv4Wildcarded("1.2.3.4", 16, "1.2.3.4", "1.2.3.4");
			testWildcarded("1::1", 16, "1::1/16", "1:0:0:0:0:0:0:1", "1::1", "1::1", "1:0:0:0:0:0:0:1");
			testIPv4Wildcarded("1.3.0.0", 15, "1.3.0.0", "1.3.0.0");
		}
		
		if(isAutoSubnets) {
			testIPv4Wildcarded("1.0.0.0", 8, "1.*.*.*", "1.%.%.%");
			testIPv4Wildcarded("1.0.0.0", 9, "1.0-127.*.*", "1.0-127.%.%");
			testIPv4Wildcarded("1.2.0.0", 15, "1.2-3.*.*", "1.2-3.%.%");
			testIPv4Wildcarded("1.2.0.0", 16, "1.2.*.*", "1.2.%.%");
			
			testWildcarded("1:0::", 32, "1::/32", "1:0:*:*:*:*:*:*", "1:0:*:*:*:*:*:*", "1::*:*:*:*:*:*", "1:0:%:%:%:%:%:%");
			testIPv6Wildcarded("1::", 16, "1::/16", "1:*:*:*:*:*:*:*", "1:%:%:%:%:%:%:%");
			testIPv6Wildcarded("1::", 20, "1::/20", "1:0-fff:*:*:*:*:*:*", "1:0-fff:%:%:%:%:%:%");
			testIPv6Wildcarded("1:f000::", 20, "1:f000::/20", "1:f000-ffff:*:*:*:*:*:*", "1:f___:%:%:%:%:%:%");
			testIPv6Wildcarded("1::", 17, "1::/17", "1:0-7fff:*:*:*:*:*:*", "1:0-7fff:%:%:%:%:%:%");
			testIPv6Wildcarded("1:10::", 28, "1:10::/28", "1:10-1f:*:*:*:*:*:*", "1:1_:%:%:%:%:%:%");
			testIPv6Wildcarded("1::", 28, "1::/28", "1:0-f:*:*:*:*:*:*", "1:_:%:%:%:%:%:%");
			testIPv6Wildcarded("1::", 31, "1::/31", "1:0-1:*:*:*:*:*:*", "1:0-1:%:%:%:%:%:%");
			testWildcarded("1::", 36, "1::/36", "1:0:0-fff:*:*:*:*:*", "1:0:0-fff:*:*:*:*:*", "1::0-fff:*:*:*:*:*", "1:0:0-fff:%:%:%:%:%");
			testWildcarded("1::", 52, "1::/52", "1:0:0:0-fff:*:*:*:*", "1::0-fff:*:*:*:*", "1::0-fff:*:*:*:*", "1:0:0:0-fff:%:%:%:%");
			testWildcarded("1::", 60, "1::/60", "1:0:0:0-f:*:*:*:*", "1::0-f:*:*:*:*", "1::0-f:*:*:*:*", "1:0:0:_:%:%:%:%");
		} else {
			testIPv4Wildcarded("1.0.0.0", 8, "1.0.0.0", "1.0.0.0");
			testIPv4Wildcarded("1.0.0.0", 9, "1.0.0.0", "1.0.0.0");
			testIPv4Wildcarded("1.2.0.0", 15, "1.2.0.0", "1.2.0.0");
			testIPv4Wildcarded("1.2.0.0", 16, "1.2.0.0", "1.2.0.0");
			testWildcarded("1:0::", 32, "1::/32", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
			testWildcarded("1::", 16, "1::/16", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
			testWildcarded("1::", 20, "1::/20", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
			testWildcarded("1:f000::", 20, "1:f000::/20", "1:f000:0:0:0:0:0:0", "1:f000::", "1:f000::", "1:f000:0:0:0:0:0:0");
			testWildcarded("1::", 17, "1::/17", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
			testWildcarded("1:10::", 28, "1:10::/28", "1:10:0:0:0:0:0:0", "1:10::", "1:10::", "1:10:0:0:0:0:0:0");
			testWildcarded("1::", 31, "1::/31", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
			testWildcarded("1::", 36, "1::/36", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
			testWildcarded("1::", 52, "1::/52", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
			testWildcarded("1::", 60, "1::/60", "1:0:0:0:0:0:0:0", "1::", "1::", "1:0:0:0:0:0:0:0");
		}
		testIPv4Wildcarded("1.*.*.*", 8, "1.*.*.*", "1.%.%.%");
		testIPv4Wildcarded("1.0-127.*.*", 9, "1.0-127.*.*", "1.0-127.%.%");
		testWildcarded("1:0:*", 32, isAutoSubnets ? "1::/32" : "1::*:*:*:*:*:*/32", "1:0:*:*:*:*:*:*", "1:0:*:*:*:*:*:*", "1::*:*:*:*:*:*", "1:0:%:%:%:%:%:%");
		testIPv6Wildcarded("1:*", 16, isAutoSubnets ? "1::/16" : "1:*:*:*:*:*:*:*/16", "1:*:*:*:*:*:*:*", "1:%:%:%:%:%:%:%");
		testIPv6Wildcarded("1:0-fff:*", 20, isAutoSubnets ? "1::/20" : "1:0-fff:*:*:*:*:*:*/20", "1:0-fff:*:*:*:*:*:*", "1:0-fff:%:%:%:%:%:%");
		testIPv6Wildcarded("1:f000-ffff:*", 20, isAutoSubnets ? "1:f000::/20" : "1:f000-ffff:*:*:*:*:*:*/20", "1:f000-ffff:*:*:*:*:*:*", "1:f___:%:%:%:%:%:%");
		testIPv6Wildcarded("1:8000-ffff:*", 17, isAutoSubnets ? "1:8000::/17" : "1:8000-ffff:*:*:*:*:*:*/17", "1:8000-ffff:*:*:*:*:*:*", "1:8000-ffff:%:%:%:%:%:%");
		testIPv6Wildcarded("1:10-1f:*", 28, isAutoSubnets ? "1:10::/28" : "1:10-1f:*:*:*:*:*:*/28", "1:10-1f:*:*:*:*:*:*", "1:1_:%:%:%:%:%:%");
		
		testIPv6Wildcarded("1:0-f:*", 28, isAutoSubnets ? "1::/28" : "1:0-f:*:*:*:*:*:*/28", "1:0-f:*:*:*:*:*:*", "1:_:%:%:%:%:%:%");
		testIPv6Wildcarded("1:0-1:*", 31, isAutoSubnets ? "1::/31" : "1:0-1:*:*:*:*:*:*/31", "1:0-1:*:*:*:*:*:*", "1:0-1:%:%:%:%:%:%");
		testWildcarded("1:0:0-fff:*", 36, isAutoSubnets ? "1::/36" : "1::0-fff:*:*:*:*:*/36", "1:0:0-fff:*:*:*:*:*", "1:0:0-fff:*:*:*:*:*", "1::0-fff:*:*:*:*:*", "1:0:0-fff:%:%:%:%:%");
		testWildcarded("1:0:0:0-fff:*", 52, isAutoSubnets ? "1::/52" : "1::0-fff:*:*:*:*/52", "1:0:0:0-fff:*:*:*:*", "1::0-fff:*:*:*:*", "1::0-fff:*:*:*:*", "1:0:0:0-fff:%:%:%:%");
		testWildcarded("1:0:0:0-f:*", 60, isAutoSubnets ? "1::/60" : "1::0-f:*:*:*:*/60", "1:0:0:0-f:*:*:*:*", "1::0-f:*:*:*:*", "1::0-f:*:*:*:*", "1:0:0:_:%:%:%:%");
		
		testPrefixCount("1.2.3.*/31", 128);
		testPrefixCount("1.2.3.*/25", 2);
		testPrefixCount("1.2.*.4/31", 256);
		testPrefixCount("1.2.*.4/23", 128);
		testPrefixCount("*.2.*.4/23", 128 * 256);
		testPrefixCount("*.2.3.*/7", 128);
		testPrefixCount("2-3.2.3.*/8", 2);
		testPrefixCount("2-3.3-4.3.*/16", 4);
		testPrefixCount("2-3.3-4.3.*/12", 2);
		testPrefixCount("2-3.3-4.3.*", 256 * 2 * 2);
		testPrefixCount("2-3.3-4.3.*/32", 256 * 2 * 2);
		testPrefixCount("192.168.0.0-8/29", 2);
		testPrefixCount("192.168.0.0-15/29", 2);
		testPrefixCount("1.2.3.*/0", 1);
		testPrefixCount("1.2.3.4/0", 1);
		
		testCount("1.2.3.4", 1, 1);
		testCount("1.2.3.4/32", 1, 1);
		testCount("1.2.3.5/31", allPrefixesAreSubnets ? 2 : 1, 1);
		testCount("1.2.3.4/31", isNoAutoSubnets ? 1 : 2, isNoAutoSubnets ? 0 : 1);
		testCount("1.2.3.4/30", isNoAutoSubnets ? 1 : 4, isNoAutoSubnets ? 0 : 3);
		testCount("1.2.3.6/30", allPrefixesAreSubnets ? 4 : 1, allPrefixesAreSubnets ? 3 : 1);
		testCount("1.1-2.3.4", 2, 2, RangeParameters.WILDCARD_AND_RANGE);
		testCount("1.*.3.4", 256, 256);
		testCount("1.2.252.0/22", isNoAutoSubnets ? 1 : 4 * 256, isNoAutoSubnets ? 0 : (4 * 256) - 1);
		testCount("1-2.2.252.0/22", isNoAutoSubnets ? 2 : 2 * 4 * 256, isNoAutoSubnets ? 0 : 2 * ((4 * 256) - 1));
		
		testRangeBlocks("1.1-3.*.*", 2, 3);
		testRangeBlocks("5-9.1-3.*.*", 2, 15);
		testRangeBlocks("1.1-3.*.1", 2, 3);
		testRangeBlocks("5-9.1-3.1.*", 2, 15);
		if(isAutoSubnets) {
			testRangeBlocks("5-9.0.0.0/9", 2, 5 * 128);
			testRangeBlocks("4-8.0.0.0/7", 2, 6 * 256);
			testRangeBlocks("1.128.0.0/12", 2, 16);
		} else {
			testRangeBlocks("5-9.0.0.0/9", 2, 5);
			testRangeBlocks("4-8.0.0.0/7", 2, 5);
			testRangeBlocks("1.128.0.0/12", 2, 1);
		}
		testRangeBlocks("1.128.0.0/20", 2, 1);
		if(allPrefixesAreSubnets) {
			testRangeBlocks("5-9.1-3.1.0/9", 2, 5 * 128);
			testRangeBlocks("5-9.1-3.1.0/7", 2, 6 * 256);
			testRangeBlocks("5-9.0.0.0/7", 2, 6 * 256);
			testRangeBlocks("1.128.0.0/4", 2, 16 * 256);
		} else {
			testRangeBlocks("5-9.1-3.1.0/9", 2, 15);
			testRangeBlocks("5-9.1-3.1.0/7", 2, 15);
			testRangeBlocks("5-9.0.0.0/7", 2, 5);
			testRangeBlocks("1.128.0.0/4", 2, 1);
		}
		testRangeBlocks("1-3.1-3.1-3.1-3", 1, 3);
		testRangeBlocks("1-3.1-3.1-3.1-3", 2, 9);
		testRangeBlocks("1-3.1-3.1-3.1-3", 3, 27);
		testRangeBlocks("1-3.1-3.1-3.1-3", 4, 81);
		
		testRangeBlocks("1-3:1-3:1-3:1-3::", 1, 3);
		testRangeBlocks("1-3:1-3:1-3:1-3::", 2, 9);
		testRangeBlocks("1-3:1-3:1-3:1-3::", 3, 27);
		testRangeBlocks("1-3:1-3:1-3:1-3::", 4, 81);
		testRangeBlocks("1-3:1-3:1-3:1-3:*", 1, 3);
		testRangeBlocks("1-3:1-3:1-3:1-3:*", 2, 9);
		testRangeBlocks("1-3:1-3:1-3:1-3:*", 3, 27);
		testRangeBlocks("1-3:1-3:1-3:1-3:*", 4, 81);
		
		testRangeBlocks("::1-3:1-3:1-3:1-3", 5, 3);
		testRangeBlocks("::1-3:1-3:1-3:1-3", 6, 9);
		testRangeBlocks("::1-3:1-3:1-3:1-3", 7, 27);
		testRangeBlocks("::1-3:1-3:1-3:1-3", 8, 81);
		
		testRangeBlocks("1-3:1-3:1-3:1-3:1-3:1-3:1-3:1-3", 8, 81 * 81);
		
		if(isAutoSubnets) {
			testRangeBlocks("5-9:0:0:0::/17", 2, 5 * 0x8000);
			testRangeBlocks("4-8:0:0:0::/15", 2, 6 * 0x10000);
			testRangeBlocks("1:100:0:0::/24", 2, 256);
		} else {
			testRangeBlocks("5-9:0:0:0::/17", 2, 5);
			testRangeBlocks("4-8:0:0:0::/15", 2, 5);
			testRangeBlocks("1:100:0:0::/24", 2, 1);
		}
		testRangeBlocks("1:128:0:0::/36", 2, 1);
		if(allPrefixesAreSubnets) {
			testRangeBlocks("5-9:1-3:1:0::/17", 2, 5 * 0x8000);
			testRangeBlocks("5-9:1-3:1:0::/15", 2, 6 * 0x10000);
			testRangeBlocks("5-9:0:0:0::/15", 2, 6 * 0x10000);
			testRangeBlocks("1:128:0:0::/24", 2, 256);
		} else {
			testRangeBlocks("5-9:1-3:1:0::/17", 2, 15);
			testRangeBlocks("5-9:1-3:1:0::/15", 2, 15);
			testRangeBlocks("5-9:0:0:0::/15", 2, 5);
			testRangeBlocks("1:128:0:0::/12", 2, 1);
			testRangeBlocks("1:128:0:0::/24", 2, 1);
		}

		testRangeCount("1.2.3.4", "1.2.3.4", 1);
		testRangeCount("1.2.3.4", "1.2.3.5", 2);
		testRangeCount("1.2.3.4", "1.2.3.6", 3);
		testRangeCount("1.2.3.255", "1.2.4.1", 3);
		testRangeCount("1.2.3.254", "1.2.4.0", 3);
		if(fullTest) {
			testRangeCount("1.2.3.254", "1.3.4.0", 3 + 256 * 256);//on the slow side, generating 180k+ addresses
		}
		testRangeCount("0.0.0.0", "255.255.255.255", BigInteger.valueOf(256L * 256L * 256L * 256L));
		testRangeCount("0.0.0.0", "255.253.255.255", BigInteger.valueOf(255 * 16777216L + 253 * 65536L + 255 * 256L + 255L + 1));
		testRangeCount("2.0.1.0", "255.253.255.252", BigInteger.valueOf(255 * 16777216L + 253 * 65536L + 255 * 256L + 252L).subtract(BigInteger.valueOf(2 * 16777216L + 256L)).add(BigInteger.ONE));
		
		testRangeCount("::1:2:3:4", "::1:2:3:4", 1);
		testRangeCount("::1:2:3:4", "::1:2:3:5", 2);
		testRangeCount("::1:2:3:4", "::1:2:3:6", 3);
		testRangeCount("::1:2:3:ffff", "::1:2:4:1", 3);
		testRangeCount("::1:2:3:fffe", "::1:2:4:0", 3);
		
		testRangeCount("::1:2:3:4:1", "::1:2:3:4:1", 1);
		testRangeCount("::1:2:3:4:1", "::1:2:3:5:1", 0x10000L + 1);
		testRangeCount("::1:2:3:4:1", "::1:2:3:6:1", 2 * 0x10000L + 1);
		testRangeCount("::1:2:3:4:0", "::1:2:3:5:1", 0x10000L + 2);
		testRangeCount("::1:2:3:4:0", "::1:2:3:6:1", 2 * 0x10000L + 2);
		testRangeCount("::1:2:3:4:1", "::1:2:3:5:3", 0x10000L + 3);
		testRangeCount("::1:2:3:4:1", "::1:2:3:6:3", 2 * 0x10000L + 3);
		
		if(fullTest) {
			testRangeCount("::1:2:3:fffe", "::1:2:5:0", 3L + 0x10000L);
			testRangeCount("::1:2:3:fffe", "::1:2:6:0", 3L + 0x20000L);
		}
		
		testRangePrefixCount("1.2.3.4", "1.2.3.4", 24, 1);
		testRangePrefixCount("1.2.3.4", "1.2.3.6", 24, 1);
		testRangePrefixCount("1.2.3.4", "1.2.3.6", 23, 1);
		testRangePrefixCount("1.2.3.4", "1.2.3.6", 25, 1);
		
		testRangePrefixCount("2.3.4.5", "2.3.6.5", 24, 3);
		testRangePrefixCount("2.3.4.5", "2.3.6.5", 22, 1);
		testRangePrefixCount("2.3.4.5", "2.3.6.5", 23, 2);
		
		testRangePrefixCount("2.3.255.5", "2.4.1.5", 25, 5);
		testRangePrefixCount("2.3.255.5", "2.4.0.5", 24, 2);
		testRangePrefixCount("2.3.255.5", "2.4.1.5", 24, 3);
		
		
		
		if(fullTest) {
			testRangePrefixCount("::1:2:3:fffe", "::1:2:5:0", 128, 3L + 0x10000L);
			testRangePrefixCount("::1:2:3:fffe", "::1:2:6:0", 128, 3L + 0x20000L);
		}
		
		testRangePrefixCount("2:3:ffff:5::", "2:4:1:5::", 49, 5);
		testRangePrefixCount("2:3:ffff:5::", "2:4:0:5::", 48, 2);
		testRangePrefixCount("2:3:ffff:5::", "2:4:1:5::", 48, 3);
		
		if(fullTest) {
			//these can take a while, since they generate 48640, 65536, and 32758 addresses respectively
			testCount("1.*.11-200.4", 190 * 256, 190 * 256, RangeParameters.WILDCARD_AND_RANGE);
			testCount("1.3.*.4/16", allPrefixesAreSubnets ? 256 * 256 : 256, allPrefixesAreSubnets ? (256 * 256) - 1 : 256);
			testCount("1.2.*.1-3/25", allPrefixesAreSubnets ? 256 * 128 : 256 * 3, allPrefixesAreSubnets ? (256 * 128) - 256 : 256 * 3, RangeParameters.WILDCARD_AND_RANGE);
			testCount("1.2.*.0-2/25", allPrefixesAreSubnets ? 256 * 128 : 256 * 3, allPrefixesAreSubnets ? (256 * 128) - 256 : (256 * 3) - 256, RangeParameters.WILDCARD_AND_RANGE);
			
			testCount("11-13.*.0.0/23", !isNoAutoSubnets ? 3 * 256 * 2 * 256 : 3 * 256, 
					!isNoAutoSubnets ? ((3 * 256) * (2 * 256)) - (3 * 256) : 0, RangeParameters.WILDCARD_AND_RANGE);
		}
		
		
		
		ipv4test(true, "1.1.*.100-101", RangeParameters.WILDCARD_AND_RANGE);
		ipv4test(false, "1.2.*.101-100", RangeParameters.WILDCARD_AND_RANGE);//downwards range
		ipv4test(true, "1.2.*.101-101", RangeParameters.WILDCARD_AND_RANGE);
		ipv6test(true, "1:2:4:a-ff:0-2::1", RangeParameters.WILDCARD_AND_RANGE);
		ipv6test(false, "1:2:4:ff-a:0-2::1", RangeParameters.WILDCARD_AND_RANGE);//downwards range
		ipv4test(false, "1.2.*.101-100/24", RangeParameters.WILDCARD_AND_RANGE);//downwards range but ignored due to CIDR
		
		//these tests create strings that validate ipv4 and ipv6 differently, allowing ranges for one and not the other
		ipv4test(true, "1.*.3.4", RangeParameters.WILDCARD_AND_RANGE, RangeParameters.NO_RANGE);
		ipv4test(false, "1.*.3.4", RangeParameters.NO_RANGE, RangeParameters.WILDCARD_AND_RANGE);
		ipv6test(false, "a:*::1.*.3.4", RangeParameters.WILDCARD_AND_RANGE, RangeParameters.NO_RANGE);
		ipv6test(true, "a:*::1.*.3.4", RangeParameters.NO_RANGE, RangeParameters.WILDCARD_AND_RANGE);
		ipv6test(false, "a:*::", RangeParameters.WILDCARD_AND_RANGE, RangeParameters.NO_RANGE);
		ipv6test(true, "a:*::", RangeParameters.NO_RANGE, RangeParameters.WILDCARD_AND_RANGE);
		
		
//		octal, hex, dec overflow
//		do it with 1, 2, 3, 4 segments
		ipv4_inet_aton_test(true, "0.0.0.1-255");
		ipv4_inet_aton_test(false, "0.0.0.1-256");
		ipv4_inet_aton_test(true, "0.0.512-65535");
		ipv4_inet_aton_test(false, "0.0.512-65536");
		ipv4_inet_aton_test(true, "0.65536-16777215");
		ipv4_inet_aton_test(false, "0.65536-16777216");
		ipv4_inet_aton_test(true, "16777216-4294967295");
		ipv4_inet_aton_test(false, "16777216-4294967296");
		ipv4_inet_aton_test(false, "0.0.0.0x1x");
		ipv4_inet_aton_test(false, "0.0.0.1x");
		ipv4_inet_aton_test(true, "0.0.0.0x1-0xff");
		ipv4_inet_aton_test(false, "0.0.0.0x1-0x100");
		ipv4_inet_aton_test(true, "0.0.0xfffe-0xffff");
		ipv4_inet_aton_test(false, "0.0.0xfffe-0x10000");
		ipv4_inet_aton_test(false, "0.0.0x10000-0x10001");
		ipv4_inet_aton_test(true, "0.0-0xffffff");
		ipv4_inet_aton_test(false, "0.0-0x1000000");
		ipv4_inet_aton_test(true, "0x11000000-0xffffffff");
		ipv4_inet_aton_test(false, "0x11000000-0x100000000");
		ipv4_inet_aton_test(false, "0x100000000-0x100ffffff");
		ipv4_inet_aton_test(true, "0.0.0.00-0377");
		ipv4_inet_aton_test(false, "0.0.0.00-0400");
		ipv4_inet_aton_test(true, "0.0.0x100-017777");
		ipv4_inet_aton_test(false, "0.0.0x100-0200000");
		ipv4_inet_aton_test(true, "0.0x10000-077777777");
		//ipv4_inet_aton_test(false, "0.0x1-077777777"); the given address throw IncompatibleAddressException as expected, would need to rewrite the test to make that a pass
		ipv4_inet_aton_test(false, "0.0x10000-0100000000");
		ipv4_inet_aton_test(true, "0x1000000-03777777777");
		ipv4_inet_aton_test(true, "0x1000000-037777777777");
		ipv4_inet_aton_test(false, "0x1000000-040000000000");
		
		ipv4test(true, "*"); //toAddress() should not work on this, toAddress(Version) should.
		
		ipv4test(false, "*%", false, true); //because the string could represent ipv6, and we are allowing zone, we treat the % as ipv6 zone, and then we invalidate because no zone for ipv4
		ipv4test(false, "*%x", false, true); //no zone for ipv4
		ipv4test(true, "**"); //toAddress() should not work on this, toAddress(Version) should.
		ipv6test(true, "*%x"); //ipv6 which allows zone
		
		ipv4test(true, "*.*.*.*"); //toAddress() should work on this 
		
		ipv4test(true, "1.*.3");
		
		ipv4test(false, "a.*.3.4");
		ipv4test(false, "*.a.3.4");
		ipv4test(false, "1.*.a.4");
		ipv4test(false, "1.*.3.a");
		
		ipv4test(false, ".2.3.*");
		ipv4test(false, "1..*.4");
		ipv4test(false, "1.*..4");
		ipv4test(false, "*.2.3.");
		
		ipv4test(false, "256.*.3.4");
		ipv4test(false, "1.256.*.4");
		ipv4test(false, "*.2.256.4");
		ipv4test(false, "1.*.3.256");
		
		
		ipv4test(true, "0.0.*.0", false);
		ipv4test(true, "00.*.0.0", false);
		ipv4test(true, "0.00.*.0", false);
		ipv4test(true, "0.*.00.0", false);
		ipv4test(true, "*.0.0.00", false);
		ipv4test(true, "000.0.*.0", false);
		ipv4test(true, "0.000.0.*", false);
		ipv4test(true, "*.0.000.0", false);
		ipv4test(true, "0.0.*.000", false);
		
		ipv4test(true, "0.0.*.0", false);
		ipv4test(true, "00.*.0.0", false);
		ipv4test(true, "0.00.*.0", false);
		ipv4test(true, "0.*.00.0", false);
		ipv4test(true, "*.0.0.00", false); 
		ipv4test(true, "000.0.*.0", false);
		ipv4test(true, "0.000.0.*", false);
		ipv4test(true, "*.0.000.0", false);
		ipv4test(true, "0.0.*.000", false);
		
		ipv4test(true, "000.000.000.*", false);
		
		ipv4test(isLenient(), "0000.0.*.0");
		ipv4test(isLenient(), "*.0000.0.0");
		ipv4test(isLenient(), "0.*.0000.0");
		ipv4test(isLenient(), "*.0.0.0000");
		
		ipv4test(false, ".0.*.0");
		ipv4test(false, "0..*.0");
		ipv4test(false, "0.*..0");
		ipv4test(false, "*.0.0.");
		
		ipv4test(true, "1.*.3.4/255.1.0.0");
		ipv4test(false, "1.*.3.4/255.1.0.0/16");
		ipv4test(false, "1.*.3.4/255.*.0.0");//range in mask
		ipv4test(false, "1.*.3.4/255.1-2.0.0");//range in mask
		ipv4test(false, "1.*.3.4/1::1");//mask mismatch
		ipv6test(false, "1:*::/1.2.3.4");//mask mismatch
		
		ipv4test(false, "1.2.3.4/255.*.0.0");//range in mask
		ipv4test(false, "1.2.3.4/255.1-2.0.0");//range in mask
		ipv6test(false, "1:2::/1:*::");//range in mask
		ipv6test(false, "1:2::/1:1-2::");//range in mask
		
		ipv4testOnly(false, "1:2:3:4:5:*:7:8"); //fixed
		ipv4testOnly(false, "*::1"); //fixed
		
		ipv6test(1, "*"); //toAddress() should not work on this, toAddress(version) should
		ipv6test(1, "*%"); //toAddress() should not work on this, toAddress(version) should
		
		ipv6test(1, "*:*:*:*:*:*:*:*"); //toAddress() should work on this
		
		ipv6test(1,"*::1");// loopback, compressed, non-routable
		
		//this one test can take a while, since it generates (0xffff + 1) = 65536 addresses
		if(fullTest) testCount("*::1", 0xffff + 1, 0xffff + 1);
		
		testCount("1-3::1", 3, 3, RangeParameters.WILDCARD_AND_RANGE);
		testCount("0-299::1", 0x299 + 1, 0x299 + 1, RangeParameters.WILDCARD_AND_RANGE);
		
		//this one test can take a while, since it generates 3 * (0xffff + 1) = 196606 addresses
		if(fullTest) testCount("1:2:4:*:0-2::1", 3 * (0xffff + 1), 3 * (0xffff + 1), RangeParameters.WILDCARD_AND_RANGE);
		
		testCount("1:2:4:0-2:0-2::1", 3 * 3, 3 * 3, RangeParameters.WILDCARD_AND_RANGE);
		testCount("1::2:3", 1, 1);
		testCount("1::2:3/128", 1, 1);
		testCount("1::2:3/127", allPrefixesAreSubnets ? 2 : 1, 1);
		
		testPrefixCount("1::2/128", 1);
		testPrefixCount("1::2:*/127", 0x8000);
		testPrefixCount("1::2:*/113", 2);
		testPrefixCount("1::2:*/112", 1);
		testPrefixCount("*::2:*/112", 0x10000);
		testPrefixCount("*:1-3::2:*/112", 0x10000 * 3);
		testPrefixCount("*:1-3::2:*/0", 1);
		
		if(fullTest) {
			testCount("1:2::fffc:0/110", isNoAutoSubnets ? 1 : 4 * 0x10000, isNoAutoSubnets ? 0 : (4 * 0x10000) - 1);
			testCount("1-2:2::fffc:0/110", isNoAutoSubnets ? 2 : 2 * 4 * 0x10000, isNoAutoSubnets ? 0 : 2 * ((4 * 0x10000) - 1));
			testCount("*::", 0xffff + 1, 0xffff + 1);
			testCount("::*", 0xffff + 1, 0xffff + 1);
			testCount("0-199::0-199", (0x19a) * (0x19a), (0x19a) * (0x19a));
			testCount("*:*", new BigInteger("ffffffffffffffffffffffffffffffff", 16).add(BigInteger.ONE), new BigInteger("ffffffffffffffffffffffffffffffff", 16).add(BigInteger.ONE));
			
			BigInteger full = new BigInteger("10000", 16).pow(8);
			BigInteger half = new BigInteger("10000", 16).pow(4);
			 
			testCount("*:*/64", full, full.subtract(half));
		}
		ipv4test(true, "1.0-0.3.0");
		ipv4test(true, "1.0-3.3.0");
		ipv4test(true, "1.1-3.3.0");
		ipv6test(true, "1:0-0:2:0::");
		ipv6test(true, "1:0-3:2:0::");
		ipv6test(true, "1:1-3:2:0::");
		
		ipv6test(1,"::*", false);// unspecified, compressed, non-routable
		ipv6test(1,"0:0:*:0:0:0:0:1");// loopback, full
		ipv6test(1,"0:0:*:0:0:0:0:0", false);// unspecified, full
		ipv6test(1,"2001:*:0:0:8:800:200C:417A");// unicast, full
		ipv6test(1,"FF01:*:0:0:0:0:0:101");// multicast, full
		ipv6test(1,"2001:DB8::8:800:200C:*");// unicast, compressed
		ipv6test(1,"FF01::*:101");// multicast, compressed
		ipv6test(0,"2001:DB8:0:0:8:*:200C:417A:221");// unicast, full
		ipv6test(0,"FF01::101::*");// multicast, compressed
		ipv6test(1,"fe80::217:f2ff:*:ed62");
		
		
		
		ipv6test(1,"2001:*:1234:0000:0000:C1C0:ABCD:0876");
		ipv6test(1,"3ffe:0b00:0000:0000:0001:0000:*:000a");
		ipv6test(1,"FF02:0000:0000:0000:0000:0000:*:0001");
		ipv6test(1,"*:0000:0000:0000:0000:0000:0000:0001");
		ipv6test(0,"0000:0000:0000:0000:*0000:0000:0000:*0", true);
		ipv6test(isLenient(),"02001:*:1234:0000:0000:C1C0:ABCD:0876"); // extra 0 not allowed!
		ipv6test(0,"2001:0000:1234:0000:0*:C1C0:ABCD:0876"); // extra 0 not allowed!
		ipv6test(1,"2001:0000:1234:0000:*:C1C0:ABCD:0876"); 
		
		//ipv6test(1," 2001:0000:1234:0000:0000:C1C0:ABCD:0876"); // leading space
		//ipv6test(1,"2001:0000:1234:0000:0000:C1C0:ABCD:0876 "); // trailing space
		//ipv6test(1," 2001:0000:1234:0000:0000:C1C0:ABCD:0876  "); // leading and trailing space
		
		ipv6test(0,"2001:0000:1234:0000:0000:C1C0*:ABCD:0876  0"); // junk after valid address
		ipv6test(0,"0 2001:0000:123*:0000:0000:C1C0:ABCD:0876"); // junk before valid address
		ipv6test(0,"2001:0000:1234: 0000:0000:C1C0:*:0876"); // internal space
		
		
		
		ipv6test(1,"3ffe:0b00:*:0001:0000:0000:000a");
		ipv6test(0,"3ffe:0b00:1:0001:0000:0000:000a"); // seven segments
		ipv6test(0,"FF02:0000:0000:0000:0000:0000:0000:*:0001"); // nine segments
		ipv6test(0,"3ffe:*::1::a"); // double "::"
		ipv6test(0,"::1111:2222:3333:4444:5555:*::"); // double "::"
		ipv6test(1,"2::10");
		ipv6test(1,"ff02::1");
		ipv6test(1,"fe80:*::");
		ipv6test(1,"2002:*::");
		ipv6test(1,"2001:*::");
		ipv6test(1,"*:0db8:1234::");
		ipv6test(1,"::ffff:*:0");
		ipv6test(1,"*::1");
		ipv6test(1,"1:2:3:4:*:6:7:8");
		ipv6test(1,"1:2:*:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::*");
		ipv6test(1,"1:2:3:*::8");
		ipv6test(1,"1:2:3::8");
		ipv6test(1,"*:2::8");
		ipv6test(1,"1::*");
		ipv6test(1,"*::2:3:4:5:6:7");
		ipv6test(1,"*::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:*");
		ipv6test(1,"1::2:*:4");
		ipv6test(1,"1::*:3");
		ipv6test(1,"1::*");
		
		ipv6test(1,"::*:3:4:5:6:7:8");
		ipv6test(1,"*::2:3:4:5:6:7");
		ipv6test(1,"::*:3:4:5:6");
		ipv6test(1,"::*:3:4:5");
		ipv6test(1,"::2:3:*");
		ipv6test(1,"*::2:3");
		ipv6test(1,"::*");
		ipv6test(1,"1:*:3:4:5:6::");
		ipv6test(1,"1:2:3:4:*::");
		ipv6test(1,"1:2:3:*::");
		ipv6test(1,"1:2:3::*");
		ipv6test(1,"*:2::");
		ipv6test(1,"*::");
		ipv6test(1,"*:2:3:4:5::7:8");
		ipv6test(0,"1:2:3::4:5::7:*"); // Double "::"
		ipv6test(0,"12345::6:7:*");
		ipv6test(1,"1:2:3:4::*:*");
		ipv6test(1,"1:*:3::7:8");
		ipv6test(1,"*:*::7:8");
		ipv6test(1,"*::*:8");
			
		// Testing IPv4 addresses represented as dotted-quads
		// Leading zero's in IPv4 addresses not allowed: some systems treat the leading "0" in ".086" as the start of an octal number
		// Update: The BNF in RFC-3986 explicitly defines the dec-octet (for IPv4 addresses) not to have a leading zero
		//ipv6test(0,"fe80:0000:0000:*:0204:61ff:254.157.241.086");
		ipv6test(!isLenient(),"fe80:0000:0000:*:0204:61ff:254.157.241.086");
		ipv6test(1,"::*:192.0.128.*"); 
		ipv6test(0,"XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:1.2.3.4");
		ipv6test(1,"1111:2222:*:4444:5555:6666:00.00.00.00");
		ipv6test(1,"1111:2222:3333:4444:5555:6666:000.*.000.000");
		ipv6test(0,"*:2222:3333:4444:5555:6666:256.256.256.256");
			
		ipv6test(1,"*:2222:3333:4444:5555:6666:123.123.123.123");
		ipv6test(1,"1111:*:3333:4444:5555::123.123.123.123");
		ipv6test(1,"1111:2222:*:4444::123.123.123.123");
		ipv6test(1,"1111:2222:3333::*.*.123.123");
		ipv6test(1,"1111:2222::123.123.*.*");
		ipv6test(1,"1111:2222::123.123.123.*");
		ipv6test(1,"1111::123.*.123.123");
		ipv6test(1,"::123.123.123.*");
		ipv6test(1,"1111:2222:3333:4444::*:123.123.123.123");
		ipv6test(1,"1111:2222:*::6666:123.123.123.123");
		ipv6test(1,"*:2222::6666:123.123.123.123");
		ipv6test(1,"1111::6666:*.*.*.*");
		ipv6test(1,"::6666:123.123.2.123");
		ipv6test(1,"1111:*:3333::5555:6666:123.*.123.123");
		ipv6test(1,"1111:2222::*:6666:123.123.*.*");
		ipv6test(1,"1111::*:6666:*.*.123.123");
		ipv6test(1,"1111::*:6666:*.0-255.123.123");//1111::*:6666:*.123.123
		ipv6test(1,"::5555:6666:123.123.123.123");
		ipv6test(1,"1111:2222::4444:5555:*:123.123.123.123");
		ipv6test(1,"1111::4444:5555:6666:123.*.123.123");
		ipv6test(1,"*::4444:5555:6666:123.123.123.123");
		ipv6test(1,"1111::*:4444:5555:6666:123.123.123.123");
		ipv6test(1,"::2222:*:4444:5555:6666:123.123.123.123");
		ipv6test(1,"::*:*:*:*:*:*.*.*.*");
		ipv6test(1,"*::*:*:*:*:*.*.*.*");
		ipv6test(0,"*:::*:*:*:*.*.*.*");
		ipv6test(0,"*:::*:*:*:*:*.*.*.*");
		ipv6test(1,"*::*:*:*:*:*.*.*.*");
		ipv6test(0,"*::*:*:*:*:*:*.*.*.*");
		ipv6test(0,"*:*:*:*:*:*:*:*:*.*.*.*");
		ipv6test(0,"*:*:*:*:*:*:*::*.*.*.*");
		ipv6test(0,"*:*:*:*:*:*::*:*.*.*.*");
		ipv6test(1,"*:*:*:*:*:*:*.*.*.*");
		ipv6test(1,"*:*:*:*:*::*.*.*.*");
		ipv6test(1,"*:*:*:*::*:*.*.*.*");
		
		ipv6test(1,"::*", false);
		ipv6test(1,"*:0:0:0:0:0:0:*", false);

		// Additional cases: http://crisp.tweakblogs.net/blog/2031/ipv6-validation-%28and-caveats%29.html
		ipv6test(1,"0:a:b:*:d:e:f::");
		ipv6test(1,"::0:a:*:*:d:e:f"); // syntactically correct, but bad form (::0:... could be combined)
		ipv6test(1,"a:b:c:*:*:f:0::");
		ipv6test(0,"':10.*.0.1");
		
		
		ipv4test(true, "1.*.4");
		ipv4test(true, "1.2.*");
		ipv4test(true, "*.1");
		ipv4test(true, "1.*");
		ipv4test(true, "1.*.1");
		ipv4test(true, "1.*.*");
		ipv4test(true, "*.*.1");
		ipv4test(true, "*.1.*");
		ipv4test(isLenient(), "1");
		ipv4test(isLenient(), "1.1");
		ipv4test(isLenient(), "1.1.1");
		
		ipv4test(true, "*.1.2.*");
		ipv4test(true, "*.1.*.2");
		ipv4test(true, "*.*.*.2");
		ipv4test(true, "*.*.*.*");
		ipv4test(true, "1.*.2.*");
		ipv4test(true, "1.2.*.*");
		
		ipv4test(true, "*.*"); 
		ipv6test(true, "1::1.2.*");
		ipv6test(true, "1::1.2.**");
		ipv6test(false, "1::1.2.**z");
		ipv6test(true, "1::1.2.3.4");
		ipv6test(true, "1:*:1");
		ipv4test(true, "1.2.*");
		
		ipv4test(false, "%.%"); 
		ipv6test(false, "1::1.2.%");
		ipv6test(true, "1::1.2.*%");
		ipv6test(true, "1::1.2.*%z");
		ipv6test(false, "1:%:1");
		
		ipv6test(true, "1::%-.1");
		ipv6test(true, "1::%-.1/16");//that is a zone of "-." and a prefix of 16
		ipv6test(true, "1::%-1/16");//that is a zone of "-" and a prefix of 16
		ipv6test(true, "1::-1:16");//that is just an address with a ranged segment 0-1
		
		ipv6test(true, "1::%-.1-16"); // -.1-16 is the zone
		ipv6test(true, "1::%-.1/16"); //we treat /16 as prefix length
		ipv6test(false, "1::%-.1:16");//we reject ':' as part of zone
		ipv6test(false, "1::%-.1/1a");//prefix has 'a'
		ipv6test(false, "1::%-1/1a");//prefix has 'a'
		ipv6test(true, "1::%%1");//zone has '%'
		ipv6test(true, "1::%%1/16");//zone has '%'
		ipv6test(true, "1::%%ab");//zone has '%'
		ipv6test(true, "1::%%ab/16");//zone has '%'
		ipv6test(true, "1::%$1");//zone has '$'
		ipv6test(true, "1::%$1/16");//zone has '$'
		
		ipv4test(true, "1.2.%"); //we allow this now, the % is seen as a wildcard because we are ipv4 - if we allow zone and the string can be interpreted as ipv6 then % is seen as zone character
		
		ipv6test(1, "1:*");
		ipv6test(1, "*:1:*");
		ipv6test(1, "*:1");
		
		//ipv6test(1, "*:1:1.*.1");//cannot be converted to ipv6 range
		ipv6test(1, "*:1:1.*.*");
		//ipv6test(1, "*:1:*.1");//cannot be converted to ipv6 range
		ipv6test(1, "*:1:*.0-255.1.1");
		ipv6test(1, "*:1:1.*");
		
		ipv6test(0, "1:1:1.*.1");
		ipv6test(0, "1:1:1.*.1.1");
		ipv6test(1, "1:1:*.*");
		ipv6test(1, "1:2:3:4:5:*.*");
		ipv6test(1, "1:2:3:4:5:6:*.*");
		ipv6test(0, "1:1:1.*");
		
		
		ipv6test(1, "1::1:1.*.*");
		ipv6test(1, "1::1:*.*.1.1");
		ipv6test(1, "1::1:1.*");
		
		ipv6test(1, "1:*.*.*.*");//in this one, the wildcard covers both ipv6 and ipv4 parts
		ipv6test(1, "1::*.*.*.*");
		ipv6test(1, "1:*.*.1.2");//in this one, the wildcard covers both ipv6 and ipv4 parts
		ipv6test(1, "1::*.*.1.2");//compression takes precedence so the wildcard does not cover both ipv6 and ipv4 parts
		ipv6test(1, "1::2:*.*.1.2");//compression takes precedence so the wildcard does not cover both ipv6 and ipv4 parts
		ipv6test(1, "::2:*.*.1.2");//compression takes precedence so the wildcard does not cover both ipv6 and ipv4 parts
		ipv6test(0, "1:1.*.2");
		ipv6test(0, "1:1.*.2.2");
		ipv6test(isLenient(), "1:*:1.2");
		
		
		ipv6test(1, "*:1:1.*");
		ipv6test(isLenient(), "*:1:1.2.3");
		ipv6test(1, "::1:1.*");
		ipv6test(isLenient(), "::1:1.2.3");
		
		ipv6test(1, "1:*:1");
		ipv6test(1, "1:*:1:1.1.*");
		ipv6test(1, "1:*:1:1.1.*.*");
		ipv6test(1, "1:*:1:*");
		ipv6test(1, "1:*:1:*.*.1.2");
		ipv6test(1, "1:*:1:1.*");
		ipv6test(isLenient(), "1:*:1:1.2.3");
		
		ipv6test(0, "1:*:1:2:3:4:5:6:7");
		ipv6test(0, "1:*:1:2:3:4:5:1.2.3.4");
		ipv6test(1, "1:*:2:3:4:5:1.2.3.4");
		ipv6test(0, "1:*:2:3:4:5:1.2.3.4.5");
		ipv6test(0, "1:1:2:3:4:5:1.2.3.4.5");
		ipv6test(0, "1:1:2:3:4:5:6:1.2.3.4");
		ipv6test(0, "1:1:2:3:4:5:6:1.*.3.4");
		ipv6test(1, "1:2:3:4:5:6:1.2.3.4");
		ipv6test(1, "1:2:3:4:5:6:1.*.3.4");
		
		
		ipv4test(true, "255._.3.4");
		ipv4test(true, "1.255._.4");
		ipv4test(true, "_.2.255.4");
		ipv4test(true, "1._.3.255");
		
		ipv4test(true, "255.__.3.4");
		ipv4test(true, "1.255.__.4");
		ipv4test(true, "__.2.255.4");
		ipv4test(true, "1.__.3.255");
		
		ipv4test(true, "255.___.3.4");
		ipv4test(true, "1.255.___.4");
		ipv4test(true, "___.2.255.4");
		ipv4test(true, "1.___.3.255");
		
		ipv4test(isLenient(), "255.____.3.4");
		ipv4test(isLenient(), "1.255.____.4");
		ipv4test(isLenient(), "____.2.255.4");
		ipv4test(isLenient(), "1.____.3.255");
		
		ipv4test(false, "255._2_.3.4");
		ipv4test(false, "1.255._2_.4");
		ipv4test(false, "_2_.2.255.4");
		ipv4test(false, "1._2_.3.255");
		
		ipv4test(true, "255.2__.3.4");
		ipv4test(true, "1.255.2__.4");
		ipv4test(true, "2__.2.255.4");
		ipv4test(true, "1.2__.3.255");
		
		ipv4test(true, "255.2_.3.4");
		ipv4test(true, "1.255.2_.4");
		ipv4test(true, "2_.2.255.4");
		ipv4test(true, "1.2_.3.255");
		
		ipv4test(false, "255.__2.3.4");
		ipv4test(false, "1.255.__2.4");
		ipv4test(false, "__2.2.255.4");
		ipv4test(false, "1.__2.3.255");
		
		ipv4test(true, "25_.__.3.4");
		ipv4test(true, "1.255.2__._");
		ipv4test(true, "2_.2_.255.__");
		ipv4test(false, "1.2__.3__.25_");
		ipv4test(true, "1.2__.3_.25_");
		ipv4test(true, "1.2__.2__.25_");
		
		ipv4test(false, "1.1--2.1.1");
		ipv4test(false, "1.1-2-3.1.1");
		ipv4test(false, "1.1-2-.1.1");
		ipv4test(false, "1.-1-2.1.1");
		
		ipv4test(false, "1.1_2_.1.1");
		ipv4test(false, "1.1_2.1.1");
		ipv4test(true, "1.1_.1.1");
		
		ipv6test(false, "1:1--2:1:1::");
		ipv6test(false, "1:1-2-3:1:1::");
		ipv6test(false, "1:1-2-:1:1::");
		ipv6test(false, "1:-1-2:1:1::");
		
		ipv6test(false, "1:1_2_:1.1::");
		ipv6test(false, "1:1_2:1:1::");
		ipv6test(true, "1:1_:1:1::");
		
		//double -
		// _4_ single char wildcards not in trailing position

		ipv6test(1,"::ffff:_:0");
		ipv6test(1,"_::1");
		ipv6test(1,"1:2:3:4:_:6:7:8");
		ipv6test(1,"1:2:_:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::_");
		ipv6test(1,"1:2:3:_::8");
		ipv6test(1,"_:2::8");
		ipv6test(1,"1::_");
		ipv6test(1,"_::2:3:4:5:6:7");
		ipv6test(1,"_::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:_");
		ipv6test(1,"1::2:_:4");
		ipv6test(1,"1::_:3");
		ipv6test(1,"1::_");
		
		ipv6test(1,"::ffff:__:0");
		ipv6test(1,"__::1");
		ipv6test(1,"1:2:3:4:__:6:7:8");
		ipv6test(1,"1:2:__:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::__");
		ipv6test(1,"1:2:3:__::8");
		ipv6test(1,"__:2::8");
		ipv6test(1,"1::__");
		ipv6test(1,"__::2:3:4:5:6:7");
		ipv6test(1,"__::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:__");
		ipv6test(1,"1::2:__:4");
		ipv6test(1,"1::__:3");
		ipv6test(1,"1::__");
		
		ipv6test(1,"::ffff:___:0");
		ipv6test(1,"___::1");
		ipv6test(1,"1:2:3:4:___:6:7:8");
		ipv6test(1,"1:2:___:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::___");
		ipv6test(1,"1:2:3:___::8");
		ipv6test(1,"___:2::8");
		ipv6test(1,"1::___");
		ipv6test(1,"___::2:3:4:5:6:7");
		ipv6test(1,"___::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:___");
		ipv6test(1,"1::2:___:4");
		ipv6test(1,"1::___:3");
		ipv6test(1,"1::___");
		
		ipv6test(1,"::ffff:____:0");
		ipv6test(1,"____::1");
		ipv6test(1,"1:2:3:4:____:6:7:8");
		ipv6test(1,"1:2:____:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::____");
		ipv6test(1,"1:2:3:____::8");
		ipv6test(1,"____:2::8");
		ipv6test(1,"1::____");
		ipv6test(1,"____::2:3:4:5:6:7");
		ipv6test(1,"____::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:____");
		ipv6test(1,"1::2:____:4");
		ipv6test(1,"1::____:3");
		ipv6test(1,"1::____");
		
		ipv6test(0,"::ffff:_____:0");
		ipv6test(0,"_____::1");
		ipv6test(0,"1:2:3:4:_____:6:7:8");
		ipv6test(0,"1:2:_____:4:5:6::8");
		ipv6test(0,"1:2:3:4:5::_____");
		ipv6test(0,"1:2:3:_____::8");
		ipv6test(0,"_____:2::8");
		ipv6test(0,"1::_____");
		ipv6test(0,"_____::2:3:4:5:6:7");
		ipv6test(0,"_____::2:3:4:5:6");
		ipv6test(0,"1::2:3:4:_____");
		ipv6test(0,"1::2:_____:4");
		ipv6test(0,"1::_____:3");
		ipv6test(0,"1::_____");
		
		ipv6test(0,"::ffff:ff___:0");
		ipv6test(0,"f____::1");
		ipv6test(0,"1:2:3:4:ffff_:6:7:8");
		ipv6test(0,"1:2:ffff_:4:5:6::8");
		ipv6test(0,"1:2:3:4:5::f_f__");
		ipv6test(0,"1:2:3:fff__::8");
		ipv6test(0,"f___f:2::8");
		ipv6test(0,"1::ff_ff");
		ipv6test(0,"ff_ff::2:3:4:5:6:7");
		ipv6test(0,"f____::2:3:4:5:6");
		ipv6test(0,"1::2:3:4:F____");
		ipv6test(0,"1::2:FF___:4");
		ipv6test(0,"1::FFF__:3");
		ipv6test(0,"1::FFFF_");
		
		ipv6test(0,"::ffff:_2_:0");
		ipv6test(0,"_2_::1");
		ipv6test(0,"1:2:3:4:_2_:6:7:8");
		ipv6test(0,"1:2:_2_:4:5:6::8");
		ipv6test(0,"1:2:3:4:5::_2_");
		ipv6test(0,"1:2:3:_2_::8");
		ipv6test(0,"_2_:2::8");
		ipv6test(0,"1::_2_");
		ipv6test(0,"_2_::2:3:4:5:6:7");
		ipv6test(0,"_2_::2:3:4:5:6");
		ipv6test(0,"1::2:3:4:_2_");
		ipv6test(0,"1::2:_2_:4");
		ipv6test(0,"1::_2_:3");
		ipv6test(0,"1::_2_");
		
		ipv6test(0,"::ffff:_2:0");
		ipv6test(0,"_2::1");
		ipv6test(0,"1:2:3:4:_2:6:7:8");
		ipv6test(0,"1:2:_2:4:5:6::8");
		ipv6test(0,"1:2:3:4:5::_2");
		ipv6test(0,"1:2:3:_2::8");
		ipv6test(0,"_2:2::8");
		ipv6test(0,"1::_2");
		ipv6test(0,"_2::2:3:4:5:6:7");
		ipv6test(0,"_2::2:3:4:5:6");
		ipv6test(0,"1::2:3:4:_2");
		ipv6test(0,"1::2:_2:4");
		ipv6test(0,"1::_2:3");
		ipv6test(0,"1::_2");
		
		ipv6test(1,"::ffff:2_:0");
		ipv6test(1,"2_::1");
		ipv6test(1,"1:2:3:4:2_:6:7:8");
		ipv6test(1,"1:2:2_:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::2_");
		ipv6test(1,"1:2:3:2_::8");
		ipv6test(1,"2_:2::8");
		ipv6test(1,"1::2_");
		ipv6test(1,"2_::2:3:4:5:6:7");
		ipv6test(1,"2_::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:2_");
		ipv6test(1,"1::2:2_:4");
		ipv6test(1,"1::2_:3");
		ipv6test(1,"1::2_");
		
		ipv6test(1,"::ffff:2___:0");
		ipv6test(1,"2___::1");
		ipv6test(1,"1:2:3:4:2___:6:7:8");
		ipv6test(1,"1:2:2___:4:5:6::8");
		ipv6test(1,"1:2:3:4:5::2___");
		ipv6test(1,"1:2:3:2___::8");
		ipv6test(1,"2___:2::8");
		ipv6test(1,"1::2___");
		ipv6test(1,"2___::2:3:4:5:6:7");
		ipv6test(1,"2___::2:3:4:5:6");
		ipv6test(1,"1::2:3:4:2___");
		ipv6test(1,"1::2:2___:4");
		ipv6test(1,"1::2___:3");
		ipv6test(1,"1::2___");
		
		ipv6test(1,"::fff_:2___:0");
		ipv6test(1,"2___::_");
		ipv6test(1,"1:2:3:4:2___:6_:7_:8");
		ipv6test(1,"1:2:2___:4:5:6::8__");
		ipv6test(1,"1:2:3_:4:5::2___");
		ipv6test(1,"1:2:3:2___::8");
		ipv6test(1,"2___:2::8");
		ipv6test(1,"1::2___");
		ipv6test(1,"2___::2_:3__:4:5:6:7");
		ipv6test(1,"2___::2:3_:4:5:6");
		ipv6test(1,"1::2:3:4_:2___");
		ipv6test(1,"1::2:2___:4f__");
		ipv6test(1,"1___::2___:3___");
		ipv6test(1,"1_::2___");
		
		ipv6test(isLenient(), "*:1:1._.__");
		ipv6test(1, "*:1:1._.__.___");
		//ipv6test(0, "*:_:1:_.1.1._");//this passes validation but conversion to mask fails because the ipv4 ranges cannot be converted to ipv6 ranges
		ipv6test(1, "*:_:1:1._.1._");
		ipv6test(1, "*:_:1:_.___.1._");
		ipv6test(1, "*:_:1:_.___._.___");
		ipv6test(1, "1:*:1_:1:1.1_.1.1");
		
		ipv6test(0, "1:1:1.2_.1");
		ipv6test(0, "1:1:1.2__.1.1");
		ipv6test(0, "1:1:_.*");
		ipv6test(0, "1:1:1._");
		
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/0", "1:2:3:4:5:6:7:8/0", new int[] {0, 0, 0, 0, 0, 0, 0, 0, 0});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8/0", new int[] {0, 16, 32, 48, 64, 80, 96, 112, 128});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/0", "1:2:3:4:5:6:7:8", new Integer[] {null, 0, 0, 0, 0, 0, 0, 0, 0});
		
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/64", new int[] {64, 64, 64, 64, 64, 64, 64, 64, 64});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8/64", new int[] {64, 64, 64, 64, 64, 80, 96, 112, 128});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/63", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, 63, 63, 63, 63, 63});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, 64, 64, 64, 64, 64});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/65", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, null, 65, 65, 65, 65});
		
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/128", "1:2:3:4:5:6:7:8/128", new int[] {128, 128, 128, 128, 128, 128, 128, 128, 128});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8/128", new int[] {128, 128, 128, 128, 128, 128, 128, 128, 128});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/128", "1:2:3:4:5:6:7:8", new Integer[] {null, null, null, null, null, null, null, null, 128});
		
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/32", "1:2:3:4:5:6:7:8/64", new int[] {64, 64, 32, 32, 32, 32, 32, 32, 32});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/32", new int[] {32, 32, 32, 48, 64, 64, 64, 64, 64});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/0", "1:2:3:4:5:6:7:8/64", new int[] {64, 0, 0, 0, 0, 0, 0, 0, 0});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/0", new int[] {0, 16, 32, 48, 64, 64, 64, 64, 64});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/128", new int[] {128, 128, 128, 128, 64, 64, 64, 64, 64});
		testInsertAndAppend("a:b:c:d:e:f:aa:bb/128", "1:2:3:4:5:6:7:8/64", new int[] {64, 64, 64, 64, 64, 80, 96, 112, 128});
		
		testInsertAndAppend("1.2.3.4/0", "5.6.7.8/0", new int[] {0, 0, 0, 0, 0});
		testInsertAndAppend("1.2.3.4", "5.6.7.8/0", new int[] {0, 8, 16, 24, 32});
		testInsertAndAppend("1.2.3.4/0", "5.6.7.8", new Integer[] {null, 0, 0, 0, 0});
		
		testInsertAndAppend("1.2.3.4/16", "5.6.7.8/16", new int[] {16, 16, 16, 16, 16});
		testInsertAndAppend("1.2.3.4", "5.6.7.8/16", new int[] {16, 16, 16, 24, 32});
		testInsertAndAppend("1.2.3.4/16", "5.6.7.8", new Integer[] {null, null, 16, 16, 16});
		
		testInsertAndAppend("1.2.3.4/32", "5.6.7.8/32", new int[] {32, 32, 32, 32, 32});
		testInsertAndAppend("1.2.3.4", "5.6.7.8/32", new int[] {32, 32, 32, 32, 32});
		testInsertAndAppend("1.2.3.4/31", "5.6.7.8", new Integer[] {null, null, null, null, 31});
		testInsertAndAppend("1.2.3.4/32", "5.6.7.8", new Integer[] {null, null, null, null, 32});
		
		testInsertAndAppend("1.2.3.4/16", "5.6.7.8/24", new int[] {24, 24, 16, 16, 16});
		testInsertAndAppend("1.2.3.4/24", "5.6.7.8/7", new int[] {7, 8, 16, 24, 24});
		testInsertAndAppend("1.2.3.4/24", "5.6.7.8/16", new int[] {16, 16, 16, 24, 24});
		testInsertAndAppend("1.2.3.4/0", "5.6.7.8/16", new int[] {16, 0, 0, 0, 0});
		testInsertAndAppend("1.2.3.4/16", "5.6.7.8/0", new int[] {0, 8, 16, 16, 16});
		testInsertAndAppend("1.2.3.4/17", "5.6.7.8/0", new int[] {0, 8, 16, 17, 17});
		testInsertAndAppend("1.2.3.4/16", "5.6.7.8/32", new int[] {32, 32, 16, 16, 16});
		testInsertAndAppend("1.2.3.4/32", "5.6.7.8/16", new int[] {16, 16, 16, 24, 32});
		
		testReplace("a:b:c:d:e:f:aa:bb/0", "1:2:3:4:5:6:7:8/0");
		testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8/0");
		testReplace("a:b:c:d:e:f:aa:bb/0", "1:2:3:4:5:6:7:8");
		
		testReplace("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/64");
		testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8/64");
		testReplace("a:b:c:d:e:f:aa:bb/63", "1:2:3:4:5:6:7:8");
		testReplace("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8");
		testReplace("a:b:c:d:e:f:aa:bb/65", "1:2:3:4:5:6:7:8");
		
		testReplace("a:b:c:d:e:f:aa:bb/128", "1:2:3:4:5:6:7:8/128");
		testReplace("a:b:c:d:e:f:aa:bb", "1:2:3:4:5:6:7:8/128");
		testReplace("a:b:c:d:e:f:aa:bb/128", "1:2:3:4:5:6:7:8");
		
		testReplace("a:b:c:d:e:f:aa:bb/32", "1:2:3:4:5:6:7:8/64");
		testReplace("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/32");
		testReplace("a:b:c:d:e:f:aa:bb/0", "1:2:3:4:5:6:7:8/64");
		testReplace("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/0");
		testReplace("a:b:c:d:e:f:aa:bb/64", "1:2:3:4:5:6:7:8/128");
		testReplace("a:b:c:d:e:f:aa:bb/128", "1:2:3:4:5:6:7:8/64");
		
		testReplace("1.2.3.4/0", "5.6.7.8/0");
		testReplace("1.2.3.4", "5.6.7.8/0");
		testReplace("1.2.3.4/0", "5.6.7.8");
		
		testReplace("1.2.3.4/16", "5.6.7.8/16");
		testReplace("1.2.3.4", "5.6.7.8/16");
		testReplace("1.2.3.4/16", "5.6.7.8");
		
		testReplace("1.2.3.4/32", "5.6.7.8/32");
		testReplace("1.2.3.4", "5.6.7.8/32");
		testReplace("1.2.3.4/31", "5.6.7.8");
		testReplace("1.2.3.4/32", "5.6.7.8");
		
		testReplace("1.2.3.4/16", "5.6.7.8/24");
		testReplace("1.2.3.4/24", "5.6.7.8/7");
		testReplace("1.2.3.4/24", "5.6.7.8/16");
		testReplace("1.2.3.4/0", "5.6.7.8/16");
		testReplace("1.2.3.4/16", "5.6.7.8/0");
		testReplace("1.2.3.4/17", "5.6.7.8/0");
		testReplace("1.2.3.4/16", "5.6.7.8/32");
		testReplace("1.2.3.4/32", "5.6.7.8/16");
		
		testSub("1:1::/32", "1:1:1:1:1:1:1:1", isNoAutoSubnets ? new String[] { "1:1::/32" } : new String[] {
			"1:1:0:0:0:0:0:0/48",
			"1:1:2-fffe:0:0:0:0:0/47",
			"1:1:1:0:0:0:0:0/64",
			"1:1:1:2-fffe:0:0:0:0/63",
			"1:1:1:1:0:0:0:0/80",
			"1:1:1:1:2-fffe:0:0:0/79",
			"1:1:1:1:1:0:0:0/96",
			"1:1:1:1:1:2-fffe:0:0/95",
			"1:1:1:1:1:1:0:0/112",
			"1:1:1:1:1:1:2-fffe:0/111",
			"1:1:1:1:1:1:1:0",
			"1:1:1:1:1:1:1:2-fffe/127"
		});
		testSub("1:1::/32", "1:1::/16", allPrefixesAreSubnets || isNoAutoSubnets ? null : new String[] {
			"1:1:1-ffff:0:0:0:0:0/48",
			"1:1:0:1-ffff:0:0:0:0/64",
			"1:1:0:0:1-ffff:0:0:0/80",
			"1:1:0:0:0:1-ffff:0:0/96",
			"1:1:0:0:0:0:1-ffff:0/112",
			"1:1:0:0:0:0:0:1-ffff"}
		);
		testSub("1:1::/32", "1:1::/48", isNoAutoSubnets ? null : new String[] {"1:1:1-ffff:0:0:0:0:0/48"});
		testSub("1:1::/32", "1:1::/64", isNoAutoSubnets ? null : new String[] {
			"1:1:1-ffff:0:0:0:0:0/48",
			"1:1:0:1-ffff:0:0:0:0/64"
		});
		testSub("1:1::/32", "1:1:2:2::/64", isNoAutoSubnets ? new String[] { "1:1::/32" } : new String[] {
			"1:1:0:0:0:0:0:0/47",
			"1:1:3-ffff:0:0:0:0:0/48",
			"1:1:2:0:0:0:0:0/63",
			"1:1:2:3-ffff:0:0:0:0/64"
		});
		testSub("10.0.0.0/22", "10.0.0.0/24", isNoAutoSubnets ? null : new String[] {"10.0.1-3.0/24"});//[10.0.1-3.0/24]
		
		testIntersect("1:1:1-3:1:1:1:1:1", "1:1:2-4:1:1:1:1:1", "1:1:2-3:1:1:1:1:1");
		testIntersect("1:1:1-3:1:0:1:1:1", "1:1:2-4:1:1:1:1:1", null);
		
		testToPrefixBlock("1.3.*.*", "1.3.*.*");
		testToPrefixBlock("1.2-3.*.*", "1.2-3.*.*");
		testToPrefixBlock("1.3.3.4/15", "1.2-3.*.*/15");
		testToPrefixBlock("*.3.3.4/15", "*.2-3.*.*/15");
		testToPrefixBlock("1.3.3.4/16", "1.3.*.*/16");
		
		testToPrefixBlock("1:3:3:4::/15", "0-1:*/15");
		testToPrefixBlock("*:3:3:4::/15", isNoAutoSubnets ? "*:*/15" : "0-fffe::/15");
		testToPrefixBlock("1:3:3:4::/16", "1:*/16");

		testMaxHost("1.*.255.255/16", allPrefixesAreSubnets ? "1.*.255.255" : "1.*.255.255/16");
		testMaxHost("1.2.*.*/16", allPrefixesAreSubnets ? "1.2.255.255" : "1.2.255.255/16");
		testMaxHost("1.*.*.*/16", allPrefixesAreSubnets ? "1.*.255.255" : "1.*.255.255/16");
		testMaxHost("1.2.*.1/16", allPrefixesAreSubnets ? "1.2.255.255" : "1.2.255.255/16");
		testMaxHost("1.*.*.1/16", allPrefixesAreSubnets ? "1.*.255.255" : "1.*.255.255/16");
		
		testZeroHost("1.*.0.0/16", allPrefixesAreSubnets? "1.*.0.0" : "1.*.0.0/16");
		testZeroHost("1.2.*.*/16", allPrefixesAreSubnets ? "1.2.0.0" : "1.2.0.0/16");
		testZeroHost("1.*.*.*/16", allPrefixesAreSubnets ? "1.*.0.0" : "1.*.0.0/16");
		testZeroHost("1.2.*.1/16", allPrefixesAreSubnets ? "1.2.0.0" : "1.2.0.0/16");
		testZeroHost("1.*.*.1/16", allPrefixesAreSubnets ? "1.*.0.0" : "1.*.0.0/16");
		
		testMaxHost("1:*::ffff:ffff:ffff:ffff/64", allPrefixesAreSubnets ? "1:*::ffff:ffff:ffff:ffff" : "1:*::ffff:ffff:ffff:ffff/64");
		testMaxHost("1:2::ffff:ffff:ffff:ffff/64", allPrefixesAreSubnets ? "1:2::ffff:ffff:ffff:ffff" : "1:2::ffff:ffff:ffff:ffff/64");
		testMaxHost("1:*::*:*:*:*/64", allPrefixesAreSubnets ? "1:*::ffff:ffff:ffff:ffff" : "1:*::ffff:ffff:ffff:ffff/64");
		testMaxHost("1:2::*:*:*:*/64", allPrefixesAreSubnets ? "1:2::ffff:ffff:ffff:ffff" : "1:2::ffff:ffff:ffff:ffff/64");
		testMaxHost("1:2::*:*:*:1/64", allPrefixesAreSubnets ? "1:2::ffff:ffff:ffff:ffff" : "1:2::ffff:ffff:ffff:ffff/64");
		testMaxHost("1:*:1/64", allPrefixesAreSubnets ? "1:*:ffff:ffff:ffff:ffff" : "1:*:ffff:ffff:ffff:ffff/64");
		testMaxHost("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0", allPrefixesAreSubnets ? "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0");
		testMaxHost("*:*/0", allPrefixesAreSubnets ? "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0");
		testMaxHost("::/128", allPrefixesAreSubnets ? "::" : "::/128");

		testZeroHost("1:*::/64", allPrefixesAreSubnets ? "1:*::" : "1:*::/64");
		testZeroHost("1:2::/64", allPrefixesAreSubnets ? "1:2::" : "1:2::/64");
		testZeroHost("1:*::*:*:*:*/64", allPrefixesAreSubnets ? "1:*::" : "1:*::/64");
		testZeroHost("1:2::*:*:*:*/64", allPrefixesAreSubnets ? "1:2::" : "1:2::/64");
		testZeroHost("1:2::*:*:*:1/64", allPrefixesAreSubnets ? "1:2::" : "1:2::/64");
		testZeroHost("1:*:1/64", allPrefixesAreSubnets ? "1:*:*:*::" : "1:*:*:*::/64");
		testZeroHost("::/0", allPrefixesAreSubnets ? "::" : "::/0");
		testZeroHost("*:*/0", allPrefixesAreSubnets ? "::" : "::/0");
		testZeroHost("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", allPrefixesAreSubnets ? "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" : "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128");
		
		testZeroHost("1:2:3:4::/64", allPrefixesAreSubnets? "1:2:3:4::" : "1:2:3:4::/64");
		testZeroHost("1:2:3:4:*/64", allPrefixesAreSubnets ? "1:2:3:4::" : "1:2:3:4::/64");
		testZeroHost("1:2:*/64", allPrefixesAreSubnets ? "1:2:*:*::" : "1:2:*:*::/64");
		testZeroHost("1:2:3:4:*:1/64", allPrefixesAreSubnets ? "1:2:3:4::" : "1:2:3:4::/64");
		testZeroHost("1:*:1/64", allPrefixesAreSubnets ? "1:*:*:*::" : "1:*:*:*::/64");
		
		testPrefixBlocks("1.2.*.*", false, false);
		testPrefixBlocks("1.2.3.*", false, false);
		testPrefixBlocks("1.*.*.*", false, false);
		testPrefixBlocks("1.2-3.*.*", false, false);
		testPrefixBlocks("1.2.128-255.*", false, false);
		testPrefixBlocks("*.*/0", true, true);
		testPrefixBlocks("1.2.*.*/16", true, true);
		testPrefixBlocks("1.2.3.*/16", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("1.*.*.*/16", true, false);
		testPrefixBlocks("1.2-3.*.*/16", true, false);
		testPrefixBlocks("1.2.128-255.*/16", allPrefixesAreSubnets, allPrefixesAreSubnets);
		
		testPrefixBlocks("1.2.*.*", 8, false, false);
		testPrefixBlocks("1.2.3.*", 8, false, false);
		testPrefixBlocks("1.*.*.*", 8, true, true);
		testPrefixBlocks("1.2-3.*.*", 8, false, false);
		testPrefixBlocks("1.2.128-255.*", 8, false, false);
		testPrefixBlocks("*.*/0", 8, true, false);
		testPrefixBlocks("1.2.*.*/16", 8, false, false);
		testPrefixBlocks("1.2.3.*/16", 8, false, false);
		testPrefixBlocks("1.*.*.*/16", 8, true, true);
		testPrefixBlocks("1.2-3.*.*/16", 8, false, false);
		testPrefixBlocks("1.2.128-255.*/16", 8, false, false);
		
		testPrefixBlocks("1.2.*.*", 24, true, false);
		testPrefixBlocks("1.2.3.*", 24, true, true);
		testPrefixBlocks("1.*.*.*", 24, true, false);
		testPrefixBlocks("1.2-3.*.*", 24, true, false);
		testPrefixBlocks("1.2.128-255.*", 24, true, false);
		testPrefixBlocks("*.*/0", 24, true, false);
		testPrefixBlocks("1.2.*.*/16", 24, true, false);
		testPrefixBlocks("1.2.3.*/16", 24, true, !allPrefixesAreSubnets);
		testPrefixBlocks("1.*.*.*/16", 24, true, false);
		testPrefixBlocks("1.2-3.*.*/16", 24, true, false);
		testPrefixBlocks("1.2.128-255.*/16", 24, true, false);
		
		testPrefixBlocks("a:b:c:d:*/64", true, true);
		testPrefixBlocks("a:b:c:*/64", true, false);
		testPrefixBlocks("a:b:c:d-e:*/64", true, false);
		testPrefixBlocks("a:b:c:d:e:*/64", allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:0-7fff:*/64", isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("a:b:c:d:8000-ffff:*/64", allPrefixesAreSubnets, allPrefixesAreSubnets);
		
		testPrefixBlocks("a:b:c:d:*/64", 0, false, false);
		testPrefixBlocks("a:b:c:*/64", 0, false, false);
		testPrefixBlocks("a:b:c:d-e:*/64", 0, false, false);
		testPrefixBlocks("*:*/64", 0, true, true);
		testPrefixBlocks("a:b:c:d:e:*/64", 0, false, false);
		testPrefixBlocks("a:b:c:d:0-7fff:*/64", 0, false, false);

		testPrefixBlocks("a:b:c:d:*/64", 63, false, false);
		testPrefixBlocks("a:b:c:*/64", 63, true, false);
		testPrefixBlocks("a:b:c:d-e:*/64", 63, false, false);
		testPrefixBlocks("a:b:c:e-f:*/64", 63, true, true);
		testPrefixBlocks("a:b:c:d:e:*/64", 63, false, false);
		testPrefixBlocks("a:b:c:d:0-7fff:*/64", 63, false, false);

		testPrefixBlocks("a:b:c:d:*/64", 64, true, true);
		testPrefixBlocks("a:b:c:*/64", 64, true, false);
		testPrefixBlocks("a:b:c:d-e:*/64", 64, true, false);
		testPrefixBlocks("a:b:c:d:e:*/64", 64, allPrefixesAreSubnets, allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:0-7fff:*/64", 64, isAutoSubnets, isAutoSubnets);
		testPrefixBlocks("a:b:c:d:8000-ffff:*/64", 64, allPrefixesAreSubnets, allPrefixesAreSubnets);
		
		testPrefixBlocks("a:b:c:d:*/64", 65, true, false);
		testPrefixBlocks("a:b:c:*/64", 65, true, false);
		testPrefixBlocks("a:b:c:d-e:*/64", 65, true, false);
		testPrefixBlocks("a:b:c:d:e:*/64", 65, allPrefixesAreSubnets, false);
		testPrefixBlocks("a:b:c:d:0-7fff:*/64", 65, true, !isAutoSubnets);
		testPrefixBlocks("a:b:c:d:8000-ffff:*/64", 65, true, !allPrefixesAreSubnets);
		testPrefixBlocks("a:b:c:d:0-ffff:*/64", 65, true, false);

		testPrefixBlocks("a:b:c:d:*/64", 128, true, false);
		testPrefixBlocks("a:b:c:*/64", 128, true, false);
		testPrefixBlocks("a:b:c:d-e:*/64", 128, true, false);
		testPrefixBlocks("a:b:c:d:e:*/64", 128, true, false);
		testPrefixBlocks("a:b:c:d:0-7fff:*/64", 128, true, false);
		
		testSplitBytes("1.2.*.4");
		testSplitBytes("1.2-4.3.4/16");
		testSplitBytes("1.2.3.4-5/0");
		testSplitBytes("1.2.*/32");
		testSplitBytes("ffff:2:3:4:eeee:dddd:cccc-dddd:bbbb");
		testSplitBytes("ffff:2:3:4:eeee:dddd:cccc:bbbb/64");
		testSplitBytes("ffff:2:3:4:*:dddd:cccc:bbbb/0");
		testSplitBytes("*:*/128");
		testSplitBytes("*:*");

		if(isNoAutoSubnets) {
			testMerge("192.168.0.0-15/28", "192.168.0.0-7/29", "192.168.0.8-15/29");
			testMerge("1:2:3:4:*/64", "1:2:3:4:8000-ffff:*/65", "1:2:3:4:0-3fff:*/66", "1:2:3:4:4000-7fff:*/66");
			testMerge("1:2:3:4:*/64", "1:2:3:4:0-3fff:*/66", "1:2:3:4:8000-ffff:*/65", "1:2:3:4:4000-7fff:*/66");
			testMerge("1:2:3:4:*/64", "1:2:3:4:0-3fff:*/66", "1:2:3:4:4000-7fff:*/66", "1:2:3:4:8000-ffff:*/65");
			testMerge("1:2:3:4:*/64", "1:2:3:4:4000-7fff:*/66", "1:2:3:4:0-3fff:*/66", "1:2:3:4:8000-ffff:*/65");
			
			testMerge("1:2:3:4-5:*/63", "1:2:3:4:0-3fff:*/66", "1:2:3:4:8000-ffff:*/65", "1:2:3:4:4000-7fff:*/66", "1:2:3:5:0-3fff:*/66", "1:2:3:5:4000-7fff:*/66", "1:2:3:5:8000-ffff:*/65");

			testMerge("1:2:3:4-5:*/63", "1:2:3:4-5:0-3fff:*/66", "1:2:3:4-5:8000-ffff:*/65", "1:2:3:4-5:4000-7fff:*/66");
			
			testMerge2("1:2:3:4:*/64", "1:2:3:6:*/64", 
					"1:2:3:4:0-3fff:*/66", "1:2:3:4:8000-ffff:*/65", "1:2:3:6:0-3fff:*/66", "1:2:3:6:4000-7fff:*/66", "1:2:3:6:8000-ffff:*/65", "1:2:3:4:4000-7fff:*/66");
		} else {
			testMerge("192.168.0.0/28", "192.168.0.0/29", "192.168.0.8/29");
			testMerge("1:2:3:4::/64", "1:2:3:4:8000::/65", "1:2:3:4::/66", "1:2:3:4:4000::/66");
			testMerge("1:2:3:4::/64", "1:2:3:4::/66", "1:2:3:4:8000::/65", "1:2:3:4:4000::/66");
			testMerge("1:2:3:4::/64", "1:2:3:4::/66", "1:2:3:4:4000::/66", "1:2:3:4:8000::/65");
			testMerge("1:2:3:4::/64", "1:2:3:4:4000::/66", "1:2:3:4::/66", "1:2:3:4:8000::/65");
			
			testMerge("1:2:3:4::/63", "1:2:3:4:8000::/65", "1:2:3:4::/66", "1:2:3:4:4000::/66", "1:2:3:5:4000::/66", "1:2:3:5::/66", "1:2:3:5:8000::/65");
			
			testMerge("1:2:3:4::/63", "1:2:3:4-5::/66", "1:2:3:4-5:8000::/65", "1:2:3:4-5:4000::/66"); //[1:2:3:5::/65]
			
			testMerge2("1:2:3:4::/64", "1:2:3:6::/64", "1:2:3:4:8000::/65", "1:2:3:4::/66", "1:2:3:4:4000::/66", "1:2:3:6:4000::/66", "1:2:3:6::/66", "1:2:3:6:8000::/65");
		}

		testMerge("1.2.3.4/32", "1.2.3.4");
		testMergeRange("1.2.3.4", "1.2.3.4");
		
		testMerge(isNoAutoSubnets ? "192.168.0.0-15/28" : "192.168.0.0/28", "192.168.0.0", "192.168.0.1", "192.168.0.2",
                "192.168.0.3", "192.168.0.4", "192.168.0.5",
                "192.168.0.6", "192.168.0.7", "192.168.0.8",
                "192.168.0.9", "192.168.0.10", "192.168.0.11",
                "192.168.0.12", "192.168.0.13", "192.168.0.14",
                "192.168.0.15");

        testMerge(isNoAutoSubnets ? "192.168.0.0-15/28" : "192.168.0.0/28", "192.168.0.0/29", "192.168.0.1/29", "192.168.0.2/29",
                "192.168.0.3/29", "192.168.0.4/29", "192.168.0.5/29",
                "192.168.0.6/29", "192.168.0.7/29", "192.168.0.8/29",
                "192.168.0.9/29", "192.168.0.10/29", "192.168.0.11/29",
                "192.168.0.12/29", "192.168.0.13/29", "192.168.0.14/29",
                "192.168.0.15/29");
		
		
		if(isNoAutoSubnets) {
			testMerge("1.2.2-3.*/23", "1.2.3.*/24", "1.2.2.*/24"); //prefix at segment boundary
			testMerge("1.2.3.*/24", "1.2.3.128-255/25", "1.2.3.0-127/25"); //prefix just beyond segment boundary
			testMerge("1.2.2-3.*/23", "1.2.3.*/24", "1.2.2-3.*/23");
			testMerge("1.2.2-3.*/23", "1.2.2-3.*/23", "1.2.3.*/24");
		} else {
			testMerge("1.2.2.0/23", "1.2.3.0/24", "1.2.2.0/24"); //prefix at segment boundary
			testMerge("1.2.3.0/24", "1.2.3.128/25", "1.2.3.0/25"); //prefix just beyond segment boundary
			testMerge("1.2.2.0/23", "1.2.3.0/24", "1.2.2.0/23");
			testMerge("1.2.2.0/23", "1.2.2.0/23", "1.2.3.0/24");
			testMerge("1.2.0.0/16", "1.2.0.0/16", "1.2.3.0/24");
			testMerge("1.2.3.0/24", "1.2.3.0/24", "1.2.3.0/24");
			
			testMerge2("1.2.3.0/24", "1.1.2.0/24", "1.2.3.0/24", "1.1.2.0/24");
			testMerge2("1.2.3.0/24", "1.2.6.0/24", "1.2.3.0/24", "1.2.6.0/24");
			testMerge2("1.2.3.0/24", "1.2.7.0/24", "1.2.3.0/24", "1.2.7.0/24");
			testMerge2("1.2.3.128/25", "1.2.2.0/25", "1.2.3.128/25", "1.2.2.0/25");
		}
		testMerge("1.2.2-3.*/23", "1.2.3.*", "1.2.2.*");//prefix at segment boundary
		testMerge("1.2.3.*/24", "1.2.3.128-255", "1.2.3.0-127"); //prefix just beyond segment boundary
		testMerge("1.2.2-3.*/23", "1.2.2-3.*", "1.2.3.*/24");
		testMerge("1.2.*.*/16", "1.2.*.*/16", "1.2.3.*/24");
		testMerge("1.2.3.*/24", "1.2.3.*/24", "1.2.3.*/24");
		testMerge("1.2.3.*/24", "1.2.3.*", "1.2.3.*");
		
		testMerge2("1.2.3.*/24", "1.1.2.*/24", "1.2.3.*/24", "1.1.2.*/24");
		testMerge2("1.2.3.*/24", "1.2.6.*/24", "1.2.3.*/24", "1.2.6.*/24");
		testMerge2("1.2.3.*/24", "1.2.7.*/24", "1.2.3.*/24", "1.2.7.*/24");
		testMerge2("1.2.3.128-255/25", "1.2.2.0-127/25", "1.2.3.128-255/25", "1.2.2.0-127/25");

		testMergeRange("1.2.3-4.*", "1.2.3.*", "1.2.4.*");
		testMergeRange("1.2.3-4.*", "1.2.3-4.*", "1.2.4.*");
		testMergeRange2("1.2.3-4.*", "2.2.3.*", "1-2.2.3.*", "1.2.4.*");
		testMergeRange2("1.2.3-4.*", "2.2.3.*", "1.2.3-4.*", "2.2.3.*");
		
		//the following 4 are an example where prefix blocks require more addresses
		if(!isNoAutoSubnets) {
			testMerge2("1.2.3.0/24", "1.2.4.0/23", "1.2.3.0/24", "1.2.4.0/24", "1.2.5.0/24");
			testMergeRange("1.2.3-5.*", "1.2.3.0/24", "1.2.4.0/24", "1.2.5.0/24");
		}
		testMerge2("1.2.3.*", "1.2.4-5.*", "1.2.3.*", "1.2.4.*", "1.2.5.*");
		testMergeRange("1.2.3-5.*", "1.2.3.*", "1.2.4.*", "1.2.5.*");
		
		testMergeRange("1.2.3-5.*", "1.2.3.*", "1.2.4.*", "1.2.4.1-255", "1.2.5.*");
		testMergeRange2("1.2.3-5.*", "8.2.3-5.*", "1.2.3.*", "8.2.3.*", "1.2.4.*", "8.2.4.*", "8.2.5.*", "1.2.5.*");
		testMergeRange2("1.2.3-5.*", "1.7.4.1-255", "1.2.3.*", "1.2.4.*", "1.7.4.1-255", "1.2.5.*");
		
		testMergeRange2("1.2.3-5.*", "1.2.7.*", "1.2.3.*", "1.2.4.*", "1.2.7.*", "1.2.5.*");
		
		testMergeRange2("1::2:3-5:*", "8::2:3-5:*", "1::2:3:*", "8::2:3:*", "1::2:4:*", "8::2:4:*", "8::2:5:*", "1::2:5:*");
		testMergeRange2("1::2:3-5:*", "1::7:4:1-255", "1::2:3:*", "1::2:4:*", "1::7:4:1-255", "1::2:5:*");
		testMergeRange2("1:2:3-5:*", "8:2:3-5:*", "1:2:3:*", "8:2:3:*", "1:2:4:*", "8:2:4:*", "8:2:5:*", "1:2:5:*");
		testMergeRange2("1:2:3-5:*", "1:7:4:1-255:*", "1:2:3:*", "1:2:4:*", "1:7:4:1-255:*", "1:2:5:*");
		
		testIncrement("1.2.*.*/16", 0, "1.2.0.0");
		testIncrement("1.2.*.*/16", 1, "1.2.0.1");
		testIncrement("1.2.*.*/16", 65535, "1.2.255.255");
		testIncrement("1.2.*.*/16", 65536, "1.3.0.0");
		testIncrement("1.2.*.*/16", -1, "1.1.255.255");
		testIncrement("1.2.*.*/16", -65536, "1.1.0.0");
		testIncrement("1.2.*.*/16", -65537, "1.0.255.255");
		
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", 0, "ffff:ffff:ffff:ffff:ffff:1:2:ffff");
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", 1, "ffff:ffff:ffff:ffff:ffff:1:3:ffff");
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", 3, "ffff:ffff:ffff:ffff:ffff:2:3:ffff");
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", 4, "ffff:ffff:ffff:ffff:ffff:2:4::");
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", 5, "ffff:ffff:ffff:ffff:ffff:2:4:1");
		testIncrement("ffff:ffff:ffff:ffff:ffff:fffe-ffff:fffe-ffff:ffff", 5, null);
		
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", -0x10002ffffL, "ffff:ffff:ffff:ffff:ffff::");
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", -0x100030000L, "ffff:ffff:ffff:ffff:fffe:ffff:ffff:ffff");
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", -0x100030003L, "ffff:ffff:ffff:ffff:fffe:ffff:ffff:fffc");
		testIncrement("ffff:ffff:ffff:ffff:ffff:1-2:2-3:ffff", -0x100030004L, "ffff:ffff:ffff:ffff:fffe:ffff:ffff:fffb");
		
		testIncrement("::1-2:2-3:ffff", -0x100030000L, null);
		
		testIncrement("ffff:3-4:ffff:ffff:ffff:1-2:2-3::", 7, "ffff:4:ffff:ffff:ffff:2:3::");
		testIncrement("ffff:3-4:ffff:ffff:ffff:1-2:2-3::", 9, "ffff:4:ffff:ffff:ffff:2:3:2");
		
		testSpanAndMerge("1.2.3.0", "1.2.3.1", 1, isNoAutoSubnets ? new String[] {"1.2.3.0-1/31"} : new String[] {"1.2.3.0/31"}, 1, new String[] {"1.2.3.0-1"});//rangeCount
		testSpanAndMerge("1.2.3.4", "1.2.5.8", 9, new String[] {"1.2.3.4-7/30", "1.2.3.8-15/29", "1.2.3.16-31/28", "1.2.3.32-63/27", "1.2.3.64-127/26", "1.2.3.128-255/25", "1.2.4.0-255/24", "1.2.5.0-7/29", "1.2.5.8"}, 3, new String[] {"1.2.3.4-255", "1.2.4.*", "1.2.5.0-8"});
		
		testSpanAndMerge("a:b:c:d:1::", "a:b:c:d:10::", 5, 
				isNoAutoSubnets ? new String[] {"a:b:c:d:1:*:*:*/80", "a:b:c:d:2-3:*:*:*/79", "a:b:c:d:4-7:*:*:*/78", "a:b:c:d:8-f:*:*:*/77", "a:b:c:d:10::"} : new String[] {"a:b:c:d:1::/80", "a:b:c:d:2::/79", "a:b:c:d:4::/78", "a:b:c:d:8::/77", "a:b:c:d:10::"}, 2, new String[] {"a:b:c:d:1-f:*:*:*", "a:b:c:d:10::"});//[a:b:c:d:1::/80, a:b:c:d:2::/79, a:b:c:d:4::/78, a:b:c:d:8::/77, a:b:c:d:10::]
		testSpanAndMerge("a:b:c:d:1::/80", "a:b:c:d:10::", 5, 
				isNoAutoSubnets ? new String[] {"a:b:c:d:1:*:*:*/80", "a:b:c:d:2-3:*:*:*/79", "a:b:c:d:4-7:*:*:*/78", "a:b:c:d:8-f:*:*:*/77", "a:b:c:d:10::"} : new String[] {"a:b:c:d:1::/80", "a:b:c:d:2::/79", "a:b:c:d:4::/78", "a:b:c:d:8::/77", "a:b:c:d:10::"}, 2, new String[] {"a:b:c:d:1-f:*:*:*", "a:b:c:d:10::"});
		testSpanAndMerge("a:b:c:d:2::", "a:b:c:d:10::", 4,
				isNoAutoSubnets ? new String[] {"a:b:c:d:2-3:*:*:*/79", "a:b:c:d:4-7:*:*:*/78", "a:b:c:d:8-f:*:*:*/77", "a:b:c:d:10::"} : new String[] {"a:b:c:d:2::/79", "a:b:c:d:4::/78", "a:b:c:d:8::/77", "a:b:c:d:10::"}, 2, new String[] {"a:b:c:d:2-f:*:*:*", "a:b:c:d:10::"});
		testSpanAndMerge("a:b:c:d:2::", "a:b:c:d:10::/76", 4, 
				isNoAutoSubnets ? new String[] {"a:b:c:d:2-3:*:*:*/79", "a:b:c:d:4-7:*:*:*/78", "a:b:c:d:8-f:*:*:*/77", "a:b:c:d:10::"} : new String[] {"a:b:c:d:2::/79", "a:b:c:d:4::/78", "a:b:c:d:8::/77", "a:b:c:d:10::/76"}, 
				isNoAutoSubnets ? 2 : 1, isNoAutoSubnets ? new String[] {"a:b:c:d:2-f:*:*:*", "a:b:c:d:10::"} : new String[] {"a:b:c:d:2-1f:*:*:*"});
		testSpanAndMerge("a:b:c:d:2::/79", "a:b:c:d:10::/76", 4, 
				isNoAutoSubnets ? new String[] {"a:b:c:d:2-3:*:*:*/79", "a:b:c:d:4-7:*:*:*/78", "a:b:c:d:8-f:*:*:*/77", "a:b:c:d:10::"} : new String[] {"a:b:c:d:2::/79", "a:b:c:d:4::/78", "a:b:c:d:8::/77", "a:b:c:d:10::/76"},
				isNoAutoSubnets ? 2 : 1, isNoAutoSubnets ? new String[] {"a:b:c:d:2-f:*:*:*", "a:b:c:d:10::"} : new String[] {"a:b:c:d:2-1f:*:*:*"});//[a:b:c:d:2::/79, a:b:c:d:4::/78, a:b:c:d:8::/77, a:b:c:d:10::/76]

		testSpanAndMerge("1.2.3.0", "1.2.3.*", 1, new String[] {"1.2.3.*/24"}, 1, new String[] {"1.2.3.*/24"});//rangeCount
		
		super.runTest();
	}
	
}