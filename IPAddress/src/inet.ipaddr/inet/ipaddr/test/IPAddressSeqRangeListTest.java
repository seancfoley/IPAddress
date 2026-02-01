/*
 * Copyright 2026 Sean C Foley
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.Spliterator;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiPredicate;
import java.util.function.BinaryOperator;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToIntBiFunction;
import java.util.function.UnaryOperator;

import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressCollection;
import inet.ipaddr.IPAddressContainmentTrie;
import inet.ipaddr.IPAddressContainmentTrieBase;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressSeqRangeList;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.format.util.BigSpliterator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressSeqRange;
import inet.ipaddr.ipv4.IPv4AddressSeqRangeList;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSeqRange;
import inet.ipaddr.ipv6.IPv6AddressSeqRangeList;

public class IPAddressSeqRangeListTest extends TestBase {

	private static final IPAddressStringParameters DEFAULT_OPTIONS = new IPAddressStringParameters.Builder().toParams();

	public IPAddressSeqRangeListTest(AddressCreator creator) {
		super(creator);
	}

	@Override
	protected IPAddressString createAddress(String x) {
		return createAddress(x, DEFAULT_OPTIONS);
	}

	IPAddressSeqRangeList create(String[][] rngList) {
		IPAddressSeqRangeList list = new IPAddressSeqRangeList();
		for(String rngStrs[]: rngList) {
			IPAddressSeqRange rng = createRange(rngStrs);
			list.add(rng);
		}
		return list;
	}

	IPAddressSeqRange createRange(String[] rngStrs) {
		IPAddress lower = createAddr(rngStrs[0]), upper = createAddr(rngStrs[1]);
		IPAddressSeqRange rng = lower.spanWithRange(upper);
		return rng;
	}

	IPAddress createAddr(String addrStr) {
		return createAddress(addrStr).getAddress();
	}

	int rangeListTestCount, rangeListFailCount;
	int multiListTestCount, singleListTestCount, addressTestCount;

	boolean print, printPass, printResults;

	private static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);
	private static final BigInteger LONG_MIN = BigInteger.valueOf(Long.MIN_VALUE);
	private static final BigInteger INT_MAX = BigInteger.valueOf(Integer.MAX_VALUE);

	private ExecutorService threadPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors(),
	        new ThreadFactory() {
        @Override
		public Thread newThread(Runnable r) {
            Thread t = Executors.defaultThreadFactory().newThread(r);
            t.setDaemon(true);
            return t;
        }
    });

	static abstract class TestResult {
		abstract void test();
	}

	class RangeResult extends TestResult {
		private boolean isIPv6;

		private IPAddressSeqRangeList range1, range2, expectedIntersection, expectedUnion, range1RemoveRange2, range2RemoveRange1;

		RangeResult(
				boolean isIPv6,
				IPAddressSeqRangeList range1, IPAddressSeqRangeList range2, 
				IPAddressSeqRangeList intersection, 
				IPAddressSeqRangeList union,
				IPAddressSeqRangeList range1RemoveRange2,
				IPAddressSeqRangeList range2RemoveRange1) {
			this.expectedIntersection = intersection;
			this.expectedUnion = union;
			this.range1 = range1;
			this.range2 = range2;
			this.range1RemoveRange2 = range1RemoveRange2;
			this.range2RemoveRange1 = range2RemoveRange1;
			this.isIPv6 = isIPv6;
		}

		void testOverlapIndex(IPAddressSeqRangeList range1, IPAddressSeqRangeList range2) {
			boolean previousOverlaps = false;
			boolean firstTime = true;
			boolean overlapsCannotChange = false;
			IPAddressSeqRangeList rng = range1.clone();
			while(true) {
				IPAddressSeqRangeList intersection = rng.intersectIntoList(range2);
				boolean overlaps = !intersection.isEmpty();
				if(!firstTime && overlapsCannotChange && overlaps != previousOverlaps) {
					addRangeFailure("fail overlaps change for range 1: "+ range1 + " and range 2: " + range2, range1);
				}
				int index = rng.indexOfOverlappingSeqRange(range2);
				if(overlaps) {
					if(index < 0) {
						addRangeFailure("fail overlap index negative for range 1: "+ range1 + " and range 2: " + range2, range1);
					} else {
						if(printPass) {
							System.out.println("pass");
						}
					}
				} else {
					if(index >= 0) {
						addRangeFailure("fail overlap index positive for range 1: "+ range1 + " and range 2: " + range2, range1);
					} else {
						if(printPass) {
							System.out.println("pass");
						}
					}
				}
				if(rng.isEmpty()) {
					break;
				}
				overlapsCannotChange = index != 0;
				previousOverlaps = overlaps;
				rng.removeSeqRange(0);
				firstTime = false;
			}
		}

		@Override
		void test() {
			
			multiListTestCount++;
			
			testOp(range1, range2, IPAddressSeqRangeList::joinIntoList, "join", expectedUnion);

			testOp(range2, range1, IPAddressSeqRangeList::joinIntoList, "join", expectedUnion);

			testOp(range1, range2, IPAddressSeqRangeList::intersectIntoList, "intersect", expectedIntersection);

			testOp(range2, range1, IPAddressSeqRangeList::intersectIntoList, "intersect", expectedIntersection);
			
			boolean expectedOverlap = !expectedIntersection.isEmpty();
			
			testBooleanOp(range1, range2, IPAddressSeqRangeList::overlaps, "overlaps", expectedOverlap);
			
			testBooleanOp(range2, range1, IPAddressSeqRangeList::overlaps, "overlaps", expectedOverlap);
			
			testOverlapIndex(range1, range2);
			
			testOverlapIndex(range2, range1);
			
			testOp(range1, range2, IPAddressSeqRangeList::removeIntoList, "remove", range1RemoveRange2);

			testOp(range2, range1, IPAddressSeqRangeList::removeIntoList, "remove", range2RemoveRange1);

			// A contains (A intersect B)

			IPAddressSeqRangeList intersection = binaryOp(range1, range2, IPAddressSeqRangeList::intersectIntoList, "intersect");
			contains(range1,
					intersection,
					true);

			contains(range2,
					intersection,
					true);

			// (A intersect B) contains A iff B contains A

			contains(intersection,
					range1,
					range2.contains(range1));

			contains(intersection,
					range2,
					range1.contains(range2));

			IPAddressSeqRangeList union = binaryOp(range1, range2, IPAddressSeqRangeList::joinIntoList, "join");
			contains(union,
					range1,
					true);

			contains(union,
					range2,
					true);

			contains(range1,
					union,
					range1.contains(range2));

			contains(range2,
					union,
					range2.contains(range1));

			IPAddressSeqRangeList empty = new IPAddressSeqRangeList();

			// removal of oneself always results in nothing
			testOp(range1, range1, IPAddressSeqRangeList::removeIntoList, "remove", empty);

			testOp(range2, range2, IPAddressSeqRangeList::removeIntoList, "remove", empty);

			// intersection with oneself results in the same
			testOp(range1, range1, IPAddressSeqRangeList::intersectIntoList, "intersect", range1);

			testOp(range2, range2, IPAddressSeqRangeList::intersectIntoList, "intersect", range2);

			// union with oneself results in the same
			testOp(range1, range1, IPAddressSeqRangeList::joinIntoList, "join", range1);

			testOp(range2, range2, IPAddressSeqRangeList::joinIntoList, "join", range2);

			// removing one from the other, removing the other from the one, then taking the union, is the same as removing the intersection from the union
			matches(
				binaryOp(binaryOp(range1, range2, IPAddressSeqRangeList::removeIntoList, "remove"),
						binaryOp(range2, range1, IPAddressSeqRangeList::removeIntoList, "remove"), 
						IPAddressSeqRangeList::joinIntoList, "join"),		
				binaryOp(binaryOp(range1, range2, IPAddressSeqRangeList::joinIntoList, "join"),
						binaryOp(range1, range2, IPAddressSeqRangeList::intersectIntoList, "intersect"),
						IPAddressSeqRangeList::removeIntoList, "remove"));

			String everythingStr = isIPv6 ? "::/0" : "0.0.0.0/0";
			IPAddress everythingAddr = new IPAddressString(everythingStr).getAddress().toPrefixBlock();

			// De Morgan's Law 1
			// complement of the union is the same as the intersection of the complements
			matches(unaryOp(
					convertEmptyVersionForComplement(binaryOp(range1, range2, IPAddressSeqRangeList::joinIntoList, "join"), everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
					binaryOp(unaryOp(convertEmptyVersionForComplement(range1, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
							unaryOp(convertEmptyVersionForComplement(range2, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"), IPAddressSeqRangeList::intersectIntoList, "intersect"));

			// De Morgan's Law 2
			// complement of the intersection is the same as the union of the complements
			matches(
					unaryOp(convertEmptyVersionForComplement(binaryOp(range1, range2, IPAddressSeqRangeList::intersectIntoList, "intersect"), everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
					binaryOp(unaryOp(convertEmptyVersionForComplement(range1, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
							unaryOp(convertEmptyVersionForComplement(range2, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"), IPAddressSeqRangeList::joinIntoList, "join"));

			removeIntersection(range1, range2);
		
			removeIntersection(range2, range1);

			unionDoubleIntersect(range1, range2, everythingAddr);
			
			unionDoubleIntersect(range2, range1, everythingAddr);
			
			// double complement results in the original
			
			doubleComplement(range1, everythingAddr);
			
			doubleComplement(range2, everythingAddr);

			intersectUnion(range1, range2);
			
			intersectUnion(range2, range1);
			
			unionIntersect(range1, range2);
			
			unionIntersect(range2, range1);
			
			removeIntersectComplement(range1, range2, everythingAddr);
			
			removeIntersectComplement(range2, range1, everythingAddr);
			
			everythingNothing(range1, everythingAddr);
			
			everythingNothing(range2, everythingAddr);

			testIterate(range1);
			testIterate(range2);

			testSpliterate(range1);
			testSpliterate(range2);
			
			testIntegerOps(range1);
			testIntegerOps(range2);
			
			// if we had 3 to play with, these two require 3 sets:
			// A union (B intersect C) = (A union B) intersect (A union C)
			// A intersect (B union C) = (A intersect B) union (A intersect C)
			
			testRangeListSpans(expectedUnion, range1, range2);
		}
		
		void testRangeListSpans(IPAddressSeqRangeList list, IPAddressSeqRangeList joined1, IPAddressSeqRangeList joined2) {
			IPAddress[] resultPrefixBlocks = list.spanWithPrefixBlocks();
			IPAddress[] resultSequentialBlocks = list.spanWithSequentialBlocks();
			IPAddress[] prefixBlocks1 = joined1.spanWithPrefixBlocks();
			IPAddress[] prefixBlocks2 = joined2.spanWithPrefixBlocks();
			IPAddress[] seqBlocks1 = joined1.spanWithSequentialBlocks();
			IPAddress[] seqBlocks2 = joined2.spanWithSequentialBlocks();

			testPrefixBlockSpan(resultPrefixBlocks, prefixBlocks1, prefixBlocks2, list);
			testPrefixBlockSpan(resultPrefixBlocks, seqBlocks1, seqBlocks2, list);
			testSequentialBlockSpan(resultSequentialBlocks, seqBlocks1, seqBlocks2, list);
			testSequentialBlockSpan(resultSequentialBlocks, prefixBlocks1, prefixBlocks2, list);
		}
		
		// removing the intersection is the same as removing the original
		void removeIntersection(IPAddressSeqRangeList range1, IPAddressSeqRangeList range2) {
			matches(binaryOp(range1, binaryOp(range1, range2, IPAddressSeqRangeList::intersectIntoList, "intersect"), IPAddressSeqRangeList::removeIntoList, "remove"), 
					binaryOp(range1, range2, IPAddressSeqRangeList::removeIntoList, "remove"));
		}

		// double complement results in the original
		void doubleComplement(IPAddressSeqRangeList list, IPAddress everythingAddr) {
			IPAddressSeqRangeList complement = unaryOp(convertEmptyVersionForComplement(list, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement");
			matchesCount(everythingAddr.getCount(), complement.getCount().add(list.getCount()), list);
			complement = convertEmptyVersionForComplement(complement, everythingAddr);
			matches(
				list, 
				unaryOp(complement, IPAddressSeqRangeList::complementIntoList, "complement"));
		}

		// A intersect (A union B) = A
		void intersectUnion(IPAddressSeqRangeList range1, IPAddressSeqRangeList range2) {
			matches(
					range1,
					binaryOp(range1, binaryOp(range1, range2, IPAddressSeqRangeList::joinIntoList, "join"),
							IPAddressSeqRangeList::intersectIntoList, "intersect"));
		}

		// intersect with complement and then with original, take union, should be the original
		void unionDoubleIntersect(IPAddressSeqRangeList range1, IPAddressSeqRangeList range2, IPAddress everythingAddr) {
			matches(
					range2, 
					binaryOp(
							binaryOp(range1, range2, IPAddressSeqRangeList::intersectIntoList, "intersect"), 
							binaryOp(
									unaryOp(convertEmptyVersionForComplement(range1, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"), 
									range2,
									IPAddressSeqRangeList::intersectIntoList, "intersect"), 
							IPAddressSeqRangeList::joinIntoList, "join"));
		}
		
		// A union (A intersect B) = A
		void unionIntersect(IPAddressSeqRangeList range1, IPAddressSeqRangeList range2) {
			matches(
					range1,
					binaryOp(range1, binaryOp(range1, range2, IPAddressSeqRangeList::intersectIntoList, "intersect"),
							IPAddressSeqRangeList::joinIntoList, "join"));
		}
		
		// A remove B = A intersect (B complement)
		void removeIntersectComplement(IPAddressSeqRangeList range1, IPAddressSeqRangeList range2, IPAddress everythingAddr) {
			matches(
					binaryOp(range1, range2, IPAddressSeqRangeList::removeIntoList, "remove"),
					binaryOp(range1, unaryOp(convertEmptyVersionForComplement(range2, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
							IPAddressSeqRangeList::intersectIntoList, "intersect"));
		}
		
		// A Union (A complement) = everything
		// A intersect (A complement) = nothing
		void everythingNothing(IPAddressSeqRangeList range1, IPAddress everythingAddr) {
			if(!range1.isEmpty()) {
				IPAddressSeqRangeList complement = unaryOp(convertEmptyVersionForComplement(range1, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement");
				IPAddressSeqRangeList nothing = new IPAddressSeqRangeList();
				matches(
						nothing,
						binaryOp(range1, complement, IPAddressSeqRangeList::intersectIntoList, "intersect"));

				nothing.add(everythingAddr);
				IPAddressSeqRangeList everything = nothing;
				matches(
						everything,
						binaryOp(range1, complement, IPAddressSeqRangeList::joinIntoList, "join"));
			}
		}
		
		private void testOp(IPAddressSeqRangeList list1, IPAddressSeqRangeList list2, BinaryOperator<IPAddressSeqRangeList> op, String opName, IPAddressSeqRangeList expected) {
			rangeListTestCount++;
			IPAddressSeqRangeList res = op.apply(list1, list2);
			if(res.equals(expected)) {
				if(!res.getCount().equals(expected.getCount()) || res.getSeqRangeCount() != expected.getSeqRangeCount()) {
					addRangeFailure("counts fail " + opName + " for " + list1 + " and " + list2, list1);
				} else {
					if(printPass) {
						System.out.println("pass " + opName);
					}
				}
			} else {
				addRangeFailure("fail " + opName + " for range 1: "+ list1 + " and  range 2: " + list2 +  " expected: " + expected + " actual: " + res, list1);
			}
		}
		
		private void testBooleanOp(IPAddressSeqRangeList list1, IPAddressSeqRangeList list2, BiPredicate<IPAddressSeqRangeList, IPAddressSeqRangeList> op, String opName, boolean expected) {
			rangeListTestCount++;
			boolean res = op.test(list1, list2);
			if(res == expected) {
				if(printPass) {
					System.out.println("pass " + opName);
				}
			} else {
				addRangeFailure("fail " + opName + " for range 1: "+ list1 + " and  range 2: " + list2 +  " expected: " + expected + " actual: " + res, list1);
			}
		}
		
		void testIntegerOps(IPAddressSeqRangeList list) {
			if(list.isEmpty()) {
				testIntegerOpsEmptyList(list);
				return;
			}
			ArrayList<IPAddressSeqRange> ranges = new ArrayList<IPAddressSeqRange>(Arrays.asList(list.getSeqRanges()));
			BigInteger count = BigInteger.ZERO;
			for(int i = 0; i < ranges.size(); i++) {
				IPAddressSeqRange rng = ranges.get(i);
				count = count.add(rng.getCount());
			}
			BigInteger originalCount = count;
			int originalRangeCount = ranges.size();
			if(originalRangeCount != list.getSeqRangeCount()) {
				addRangeFailure("inconsistent range counts", list);
			}

			BigInteger targetIndex1 = count.divide(BigInteger.valueOf(2)).add(BigInteger.valueOf(-7));
			BigInteger targetIndex2 = count.divide(BigInteger.valueOf(2)).add(BigInteger.valueOf(7));
			int targetRangeIndex1 = -1, targetRangeIndex2 = -1;
			IPAddressSeqRange rng1 = null, rng2 = null;
			BigInteger rngTargetIndex1 = null, rngTargetIndex2 = null,
					rng1LowerIndex = null, rng2LowerIndex = null, rng1UpperIndex = null, rng2UpperIndex = null;
			IPAddress target1 = null, target2 = null;
			count = BigInteger.ZERO;
			boolean skipRange1 = false, skipRange2 = false;
			for(int i = 0; i < ranges.size() && (targetRangeIndex1 < 0 || targetRangeIndex2 < 0); i++) {
				IPAddressSeqRange rng = ranges.get(i);
				BigInteger previousCount = count;
				count = count.add(rng.getCount());
				if(targetRangeIndex1 < 0 && targetIndex1.compareTo(count) < 0) {
					targetRangeIndex1 = i;
					rng1 = rng;
					rngTargetIndex1 = targetIndex1.subtract(previousCount);
					try {
						target1 = rng.getLower().increment(rngTargetIndex1);
						rng1LowerIndex = previousCount;
						rng1UpperIndex = count.subtract(BigInteger.ONE);
					} catch(AddressValueException e) {
						skipRange1 = true;
					}
				}
				if(targetRangeIndex2 < 0 && targetIndex2.compareTo(count) < 0) {
					targetRangeIndex2 = i;
					rng2 = rng;
					rngTargetIndex2 = targetIndex2.subtract(previousCount);
					try {
						target2 = rng.getLower().increment(rngTargetIndex2);
						rng2LowerIndex = previousCount;
						rng2UpperIndex = count.subtract(BigInteger.ONE);
					} catch(AddressValueException e) {
						skipRange2 = true;
					}
				}
			}
			if(!skipRange1 && targetRangeIndex1 >= 0 && targetIndex1.signum() >= 0) {
				removeAndPutBack(list, originalCount, originalRangeCount, targetRangeIndex1, rng1, rngTargetIndex1, targetIndex1, target1);
			}
			if(!skipRange2 && targetRangeIndex2 >= 0 && targetIndex2.signum() >= 0) {
				removeAndPutBack(list, originalCount, originalRangeCount, targetRangeIndex2, rng2, rngTargetIndex2, targetIndex2, target2);
			}
			if(targetRangeIndex1 >= 0 && !skipRange1) {
				if(rng1.getCount().compareTo(BigInteger.ONE) > 0) {
					IPAddress lower = rng1.getLower();
					if(!lower.equals(target1)) {
						removeAndPutBack(list, originalCount, originalRangeCount, targetRangeIndex1, rng1, BigInteger.ZERO, rng1LowerIndex, lower);
					}
					IPAddress upper = rng1.getUpper();
					if(!upper.equals(target1)) {
						removeAndPutBack(list, originalCount, originalRangeCount, targetRangeIndex1, rng1, rng1.getCount().subtract(BigInteger.ONE), rng1UpperIndex, upper);
					}// this one
				}
			}
			if(targetRangeIndex2 >= 0 && !skipRange2) {
				if(!rng1.equals(rng2) && rng2.getCount().compareTo(BigInteger.ONE) > 0) {
					IPAddress lower = rng2.getLower();
					if(!lower.equals(target2)) {
						removeAndPutBack(list, originalCount, originalRangeCount, targetRangeIndex2, rng2, BigInteger.ZERO, rng2LowerIndex, lower);
					}
					IPAddress upper = rng2.getUpper();
					if(!upper.equals(target2)) {
						removeAndPutBack(list, originalCount, originalRangeCount, targetRangeIndex2, rng2, rng2.getCount().subtract(BigInteger.ONE), rng2UpperIndex, upper);
					}
				}
			}
			
			//Do the same with the lowest range
			IPAddressSeqRange rng = list.getLowerSeqRange();
			if(!rng.equals(rng1)) {
				BigInteger rngTargetIndex = rng.getCount().divide(BigInteger.valueOf(2));
				IPAddress target = rng.getLower().increment(rngTargetIndex);
				removeAndPutBack(list, originalCount, originalRangeCount, 0, rng, rngTargetIndex, rngTargetIndex, target);
				if(rng.getCount().compareTo(BigInteger.ONE) > 0) {
					IPAddress lower = rng.getLower();
					if(!lower.equals(target)) {
						removeAndPutBack(list, originalCount, originalRangeCount, 0, rng, BigInteger.ZERO, BigInteger.ZERO, lower);
					}
					IPAddress upper = rng.getUpper();
					if(!upper.equals(target)) {
						rngTargetIndex = rng.getCount().subtract(BigInteger.ONE);
						removeAndPutBack(list, originalCount, originalRangeCount, 0, rng, rngTargetIndex, rngTargetIndex, upper);
					}
				}
			}
			
			//Do the same with the highest range
			rng = list.getUpperSeqRange();
			if(!rng.equals(rng2)) {
				BigInteger rngCount = rng.getCount();
				BigInteger rngTargetIndex;
				if(rngCount.equals(BigInteger.ONE)) {
					rngTargetIndex = BigInteger.ZERO;
				} else {
					rngTargetIndex = rngCount.add(BigInteger.ONE).divide(BigInteger.valueOf(2));
				}
				IPAddress target = rng.getLower().increment(rngTargetIndex);
				BigInteger lastRangeAddressIndex = list.getCount().subtract(rng.getCount());
				removeAndPutBack(list, originalCount, originalRangeCount, list.getSeqRangeCount() - 1, rng, rngTargetIndex, lastRangeAddressIndex.add(rngTargetIndex), rng.getLower().increment(rngTargetIndex));
				if(rng.getCount().compareTo(BigInteger.ONE) > 0) {
					IPAddress lower = rng.getLower();
					if(!lower.equals(target)) {
						removeAndPutBack(list, originalCount, originalRangeCount, list.getSeqRangeCount() - 1, rng, BigInteger.ZERO, lastRangeAddressIndex, lower);
					}
					IPAddress upper = rng.getUpper();
					if(!upper.equals(target)) {
						BigInteger lastRangeAddressUpperIndex = rng.getCount().subtract(BigInteger.ONE);
						removeAndPutBack(list, originalCount, originalRangeCount, list.getSeqRangeCount() - 1, rng, lastRangeAddressUpperIndex, lastRangeAddressIndex.add(lastRangeAddressUpperIndex), upper);
					}
				}
			}
			
			IPAddress lower = list.getLower();
			BigInteger val = lower.getValue();
			if(val.signum() != 0) {
				IPAddress zero = lower.toZeroHost(0);
				if(val.compareTo(BigInteger.ONE) > 0) {
					BigInteger halfVal = val.divide(BigInteger.valueOf(2)).negate();
					checkAboveBelow(list, originalCount, originalRangeCount, halfVal, lower.increment(halfVal));
					checkAboveBelow(list, originalCount, originalRangeCount, val.negate(), zero);
					checkOutOfBounds(list, originalCount, originalRangeCount, val.add(BigInteger.ONE).negate());
				} else { // val is one
					checkAboveBelow(list, originalCount, originalRangeCount, BigInteger.valueOf(-1), zero);
					checkOutOfBounds(list, originalCount, originalRangeCount, BigInteger.valueOf(-2));
					checkOutOfBounds(list, originalCount, originalRangeCount, BigInteger.valueOf(-7));
				}
			} else { // val is 0.0.0.0 or ::
				checkOutOfBounds(list, originalCount, originalRangeCount, BigInteger.valueOf(-1));
				checkOutOfBounds(list, originalCount, originalRangeCount, BigInteger.valueOf(-7));
			}
			IPAddress max = lower.toMaxHost(0);
			BigInteger beyond = list.getUpper().enumerate(max);
			if(!list.getUpper().isMax()) {
				checkAboveBelow(list, originalCount, originalRangeCount, list.getCount(), list.getUpper().increment());
				checkAboveBelow(list, originalCount, originalRangeCount, list.getCount().add(beyond).subtract(BigInteger.ONE), max); 
				
			}
			checkOutOfBounds(list, originalCount, originalRangeCount, list.getCount().add(beyond));
		}
		
		int counter;
		
		void removeAndPutBack(
				IPAddressSeqRangeList list,
				BigInteger originalCount,
				int originalRangeCount,
				int targetRangeIndex,
				IPAddressSeqRange targetRange,
				BigInteger targetAddressIndexInRange,
				BigInteger targetAddressIndex,
				IPAddress target) {
			boolean isLongish = targetAddressIndex.compareTo(LONG_MAX) <= 0 && targetAddressIndex.compareTo(LONG_MIN) >= 0;
			
			boolean isFirstInRange = targetAddressIndexInRange.signum() == 0;
			boolean isLastInRange = targetAddressIndexInRange.add(BigInteger.ONE).equals(targetRange.getCount());
			boolean isLastAddress = targetRangeIndex == list.getSeqRangeCount() - 1 && isLastInRange;
			boolean isFirstAddress = targetRangeIndex == 0 && isFirstInRange;
			
			IPAddressSeqRangeList originalList = list.clone();
			if(!list.getCount().equals(originalCount)) {
				addRangeFailure("inconsistent address counts", list);
			}
			IPAddressSeqRange rng = list.getSeqRange(targetRangeIndex);
			if(!rng.equals(targetRange)) {
				addRangeFailure("unexpected range at sequential range index", list);
			}
			rng = list.getContainingSeqRange(targetAddressIndex);
			if(!rng.equals(targetRange)) {
				addRangeFailure("unexpected range at address index", list);
			}
			if(isLongish) {
				rng = list.getContainingSeqRange(targetAddressIndex.longValue());
				if(!rng.equals(targetRange)) {
					addRangeFailure("unexpected range at address index", list);
				}
			}
			IPAddress getAddr = list.get(targetAddressIndex);
			if(getAddr.isMultiple() || getAddr.isPrefixed()) {
				addRangeFailure("unexpected multiple or prefixed subnet", list);
			}
			if(!getAddr.equals(target)) {
				addRangeFailure("unexpected address at list address index", list);
			}
			if(isLongish) {
				getAddr = list.get(targetAddressIndex.longValue());
				if(getAddr.isMultiple() || getAddr.isPrefixed()) {
					addRangeFailure("unexpected multiple or prefixed subnet", list);
				}
				if(!getAddr.equals(target)) {
					addRangeFailure("unexpected address at list address index", list);
				}
			}
			IPAddress incrementAddr = list.get(targetAddressIndex);
			if(!getAddr.equals(incrementAddr)) {
				addRangeFailure("unexpected address at list increment address index", list);
			}
			if(isLongish) {
				incrementAddr = list.get(targetAddressIndex.longValue());
				if(!getAddr.equals(incrementAddr)) {
					addRangeFailure("unexpected address at list increment address index", list);
				}
			}
			if(!list.enumerate(getAddr).equals(targetAddressIndex)) {
				addRangeFailure("unexpected enumerated address at list increment address index", list);
			}
			boolean added = list.add(getAddr);
			if(added) {
				addRangeFailure("unexpected add to list of address expected to be in list already", list);
			}
			if(!list.getCount().equals(originalCount)) {
				addRangeFailure("unexpected change in list count", list);
			}
					
			// remove it
			IPAddress removedAddr;
			if(isLongish && (++counter % 2 == 0)) {
				removedAddr = list.remove(targetAddressIndex.longValue());
			} else {
				removedAddr = list.remove(targetAddressIndex);
			}
			if(removedAddr.isPrefixed()) {
				addRangeFailure("addresses in sequential ranges lists should not be prefixed", list);
			}
			if(!removedAddr.equals(target)) {
				addRangeFailure("removed address " + removedAddr + " not the expected address " + getAddr, list);
			}
			if(!removedAddr.equals(getAddr)) {
				addRangeFailure("removed address " + removedAddr + " not the expected address " + getAddr + " looked up", list);
			}
			// confirm it is gone
			try {
				IPAddress getAddrAgain = list.get(targetAddressIndex);
				if(removedAddr.equals(getAddrAgain) || isLastAddress) {
					addRangeFailure("removed address not gone", list); 
				}
			} catch(IndexOutOfBoundsException e) {
				if(!isLastAddress) {
					addRangeFailure("unexpected exception", list); 
				}
				// no longer any address at that index, must have been the top address that was removed
			}
			if(isLongish) {
				try {
					IPAddress getAddrAgain = list.get(targetAddressIndex.longValue());
					if(removedAddr.equals(getAddrAgain) || isLastAddress) {
						addRangeFailure("removed address not gone", list); 
					}
				} catch(IndexOutOfBoundsException e) {
					if(!isLastAddress) {
						addRangeFailure("unexpected exception", list); 
					}
					// no longer any address at that index, must have been the top address that was removed
				}
			}
			// confirm it is gone by removing it again
			boolean removedAgain = list.remove(removedAddr);
			if(removedAgain) {
				addRangeFailure("removed address not removed", list);
			}
			IPAddress incrementAddrAgain = list.increment(targetAddressIndex);
			if(removedAddr.equals(incrementAddrAgain)) {
				list.increment(targetAddressIndex);
			}
			if(isLongish) {
				incrementAddrAgain = list.increment(targetAddressIndex.longValue());
				if(removedAddr.equals(incrementAddrAgain)) {
					list.increment(targetAddressIndex);
				}
			}
			// check counts
			int countAdjustment = 0;
			if(!isFirstInRange && !isLastInRange) {
				countAdjustment++;
			} else if(!targetRange.isMultiple()) {
				countAdjustment--;
			}
			if(originalRangeCount + countAdjustment != list.getSeqRangeCount()) {
				addRangeFailure("range count unexpected after removing address: original " + originalRangeCount + " vs " + list.getSeqRangeCount() + " and is multiple " + targetRange.isMultiple(), list);
			}
			if(originalCount.compareTo(BigInteger.ONE) > 0) {
				if(targetRange.isMultiple() || targetRangeIndex < originalRangeCount - 1) {
					rng = list.getSeqRange(targetRangeIndex); 
					if(rng.equals(targetRange)) { 
						addRangeFailure("range in list still matches after removing address", list);
					}
				}
			} else if(list.getSeqRangeCount() != 0) {
				addRangeFailure("ranges should be gone after removng the only address", list);
			}
			if(!originalCount.equals(list.getCount().add(BigInteger.ONE))) {
				addRangeFailure("range count unexpected after removing address", list);
			}
			// check enumerate
			boolean isBorderAddress = isLastAddress || isFirstAddress;
			BigInteger enumerated = list.enumerate(removedAddr); 
			if((isBorderAddress && !list.isEmpty()) ? enumerated == null : enumerated != null) {
				addRangeFailure("removed address found in range list after being removed", list);
			}
			enumerated = list.enumerate(getAddr);
			if((isBorderAddress && !list.isEmpty()) ? enumerated == null : enumerated != null) {
				addRangeFailure("address found in range list after being removed", list);
			}
			
			// add it back
			added = list.add(getAddr);
			if(!added) {
				addRangeFailure("address not added as expected after being removed", list);
			}
			
			// confirm it is back
			IPAddress getAddrAgain = list.get(targetAddressIndex);
			if(!removedAddr.equals(getAddrAgain)) {
				addRangeFailure("address not found in list as expected after being added back", list);
			}
			if(isLongish) {
				getAddrAgain = list.get(targetAddressIndex.longValue());
				if(!removedAddr.equals(getAddrAgain)) {
					addRangeFailure("address not found in list as expected after being added back", list);
				}
			}
			incrementAddrAgain = list.get(targetAddressIndex);
			if(!removedAddr.equals(incrementAddrAgain)) {
				addRangeFailure("address added back not at expected location", list);
			}
			if(isLongish) {
				incrementAddrAgain = list.get(targetAddressIndex.longValue());
				if(!removedAddr.equals(incrementAddrAgain)) {
					addRangeFailure("address added back not at expected location", list);
				}
			}
			// check counts
			if(originalRangeCount != list.getSeqRangeCount()) {
				addRangeFailure("sequential range count not restored to original", list);
			}
			if(!originalCount.equals(list.getCount())) {
				addRangeFailure("address count not restored to original", list);
			}
			// check enumerate
			if(!list.enumerate(removedAddr).equals(targetAddressIndex)) {
				addRangeFailure("address not found at expeceted location", list);
			}
			if(!list.enumerate(getAddr).equals(targetAddressIndex)) {
				addRangeFailure("address not located at expeceted location", list);
			}
			// confirm the list is back to the same
			if(!list.equals(originalList)) {
				addRangeFailure("restored list not equal to original", list);
			}
		}
		
		void checkAboveBelow(
				IPAddressSeqRangeList list,
				BigInteger originalCount,
				int originalRangeCount,
				BigInteger targetAddressIndex,
				IPAddress target) {
			boolean isLongish = targetAddressIndex.compareTo(LONG_MAX) <= 0 && targetAddressIndex.compareTo(LONG_MIN) >= 0;
			if(!list.getCount().equals(originalCount)) {
				addRangeFailure("inconsistent address counts", list);
			}
			try {
				IPAddress getAddr = list.get(targetAddressIndex);
				addRangeFailure("unexpected address " + getAddr + " at list address index", list);
			} catch(IndexOutOfBoundsException e) {
				// no longer there
			}
			if(isLongish) {
				try {
					IPAddress getAddr = list.get(targetAddressIndex.longValue());
					addRangeFailure("unexpected address " + getAddr + " at list address index", list);
				} catch(IndexOutOfBoundsException e) {
					// no longer there
				}
			}
			IPAddress incrementAddr = list.increment(targetAddressIndex);
			if(!Objects.equals(incrementAddr, target)) {
				addRangeFailure("unexpected address " + incrementAddr + " at list increment address index, expected " + target, list);
			}
			if(isLongish) {
				incrementAddr = list.increment(targetAddressIndex.longValue());
				if(!Objects.equals(incrementAddr, target)) {
					addRangeFailure("unexpected address " + incrementAddr + " at list increment address index, expected " + target, list);
				}
			}
			try {
				IPAddressSeqRange rng = list.getContainingSeqRange(targetAddressIndex);
				addRangeFailure("unexpected range " + rng + " at address index", list);
			} catch(IndexOutOfBoundsException e) {
				// out of bounds
			}
			if(isLongish) {
				try {
					IPAddressSeqRange rng = list.getContainingSeqRange(targetAddressIndex.longValue());
					addRangeFailure("unexpected range " + rng + "  at address index", list);
				} catch(IndexOutOfBoundsException e) {
					// out of bounds
				}
			}
			// remove it
			try {
				IPAddress removedAddr = list.remove(targetAddressIndex);
				addRangeFailure("unexpected address " + removedAddr + " at list address index", list);
			} catch(IndexOutOfBoundsException e) {
				// pass
			}
			if(isLongish) {
				try {
					IPAddress removedAddr = list.remove(targetAddressIndex.longValue());
					addRangeFailure("unexpected address " + removedAddr + " at list address index", list);
				} catch(IndexOutOfBoundsException e) {
					// pass
				}
			}
			if(originalRangeCount != list.getSeqRangeCount()) {
				addRangeFailure("range count unexpected after removing address not in list: original " + originalRangeCount + " vs " + list.getSeqRangeCount(), list);
			}
			if(!originalCount.equals(list.getCount())) {
				addRangeFailure("range count unexpected after removing address", list);
			}
			// check enumerate
			if(incrementAddr != null) {
				BigInteger enumerated = list.enumerate(incrementAddr); 
				if(!list.isEmpty() ? enumerated == null : enumerated != null) {
					addRangeFailure("enumerated address found in range list unexpectedly", list);
				}
				if(!list.isEmpty()) {
					if(!targetAddressIndex.equals(enumerated)) {
						addRangeFailure("enumerated address not the inverse of increment", list);
					}
				}
			}
		}
		
		void checkOutOfBounds(
				IPAddressSeqRangeList list,
				BigInteger originalCount,
				int originalRangeCount,
				BigInteger targetAddressIndex) {
			boolean isLongish = targetAddressIndex.compareTo(LONG_MAX) <= 0 && targetAddressIndex.compareTo(LONG_MIN) >= 0;
			if(!list.getCount().equals(originalCount)) {
				addRangeFailure("inconsistent address counts", list);
			}
			try {
				IPAddress getAddr = list.get(targetAddressIndex);
				addRangeFailure("unexpected address " + getAddr + " at list address index", list);
			} catch(IndexOutOfBoundsException e) {
				// pass
			}
			if(isLongish) {
				try {
					IPAddress getAddr = list.get(targetAddressIndex.longValue());
					addRangeFailure("unexpected address " + getAddr + " at list address index", list);
				} catch(IndexOutOfBoundsException e) {
					// pass
				}
			}
			try {
				IPAddress incrementAddr = list.increment(targetAddressIndex);
				addRangeFailure("unexpected address " + incrementAddr + " at list increment address index which should throw", list);
			} catch(AddressValueException e) {
				// pass
			}
			if(isLongish) {
				try {
					IPAddress incrementAddr = list.increment(targetAddressIndex.longValue());
					addRangeFailure("unexpected address " + incrementAddr + " at list increment address index which should throw", list);
					//list.increment(targetAddressIndex.longValue());
				} catch(AddressValueException e) {
					// pass
				}
			}
			try {
				IPAddressSeqRange rng = list.getContainingSeqRange(targetAddressIndex);
				addRangeFailure("unexpected range " + rng + " at address index", list);
			} catch(IndexOutOfBoundsException e) {
				// out of bounds
			}
			if(isLongish) {
				try {
					IPAddressSeqRange rng = list.getContainingSeqRange(targetAddressIndex.longValue());
					addRangeFailure("unexpected range " + rng + "  at address index", list);
				} catch(IndexOutOfBoundsException e) {
					// out of bounds
				}
			}
			// remove it
			try {
				IPAddress removedAddr = list.remove(targetAddressIndex);
				addRangeFailure("removed address " + removedAddr + " not the expected address", list);
			} catch(IndexOutOfBoundsException e) {
				// pass
			}
			if(isLongish) {
				try {
					IPAddress removedAddr = list.remove(targetAddressIndex.longValue());
					addRangeFailure("removed address " + removedAddr + " not the expected address", list);
				} catch(IndexOutOfBoundsException e) {
					// pass
				}
			}
			if(originalRangeCount != list.getSeqRangeCount()) {
				addRangeFailure("range count unexpected after removing address not in list: original " + originalRangeCount + " vs " + list.getSeqRangeCount(), list);
			}
			if(!originalCount.equals(list.getCount())) {
				addRangeFailure("range count unexpected after removing address", list);
			}
		}
		
		void testIntegerOpsEmptyList(IPAddressSeqRangeList list) {
			testIntegerOpsEmptyListIndex(list, BigInteger.ZERO);
			testIntegerOpsEmptyListIndex(list, BigInteger.ONE);
			testIntegerOpsEmptyListIndex(list, BigInteger.valueOf(-1));
		}
		
		void testIntegerOpsEmptyListIndex(IPAddressSeqRangeList list, BigInteger targetAddressIndex) {
			
			if(list.getSeqRangeCount() != 0) {
				addRangeFailure("unexpected range count empty list", list);
			}
			
			if(list.getCount().signum() != 0) {
				addRangeFailure("unexpected count empty list", list);
			}
			
			boolean isLongish = targetAddressIndex.compareTo(LONG_MAX) <= 0 && targetAddressIndex.compareTo(LONG_MIN) >= 0;
			
			try {
				IPAddress getAddr = list.get(targetAddressIndex);
				addRangeFailure("unexpected address " + getAddr + " at list address index", list);
			} catch(IndexOutOfBoundsException e) {
				// pass
			}
			if(isLongish) {
				try {
					IPAddress getAddr = list.get(targetAddressIndex.longValue());
					addRangeFailure("unexpected address " + getAddr + " at list address index", list);
				} catch(IndexOutOfBoundsException e) {
					// pass
				}
			}

			IPAddress incrementAddr = list.increment(targetAddressIndex);
			if(incrementAddr != null) {
				addRangeFailure("unexpected address " + incrementAddr + " at list increment address index " + targetAddressIndex + " which should throw", list);
			}
			if(isLongish) {
				incrementAddr = list.increment(targetAddressIndex.longValue());
				if(incrementAddr != null) {
					addRangeFailure("unexpected address " + incrementAddr + " at list increment address index " + targetAddressIndex + " which should throw", list);
				}
			}

			try {
				IPAddressSeqRange rng = list.getContainingSeqRange(targetAddressIndex);
				addRangeFailure("unexpected range " + rng + " at address index", list);
			} catch(IndexOutOfBoundsException e) {
				// out of bounds
			}
			if(isLongish) {
				try {
					IPAddressSeqRange rng = list.getContainingSeqRange(targetAddressIndex.longValue());
					addRangeFailure("unexpected range " + rng + "  at address index", list);
				} catch(IndexOutOfBoundsException e) {
					// out of bounds
				}
			}

			// remove it
			try {
				IPAddress removedAddr = list.remove(targetAddressIndex);
				addRangeFailure("removed address " + removedAddr + " not the expected address", list);
			} catch(IndexOutOfBoundsException e) {
				// pass
			}
			if(isLongish) {
				try {
					IPAddress removedAddr = list.remove(targetAddressIndex.longValue());
					addRangeFailure("removed address " + removedAddr + " not the expected address", list);
				} catch(IndexOutOfBoundsException e) {
					// pass
				}
			}
		}
		
		<R extends IPAddressSeqRangeList, T extends IPAddress> void testIterate(R rangeList) {
			IPAddressSeqRangeListTest.this.testIterate(rangeList,
					IPAddressSeqRangeList::iterator,
					IPAddressSeqRangeList::getCount,
					IPAddressSeqRangeList::clone,
					IPAddressSeqRangeList::getLower,
					IPAddressSeqRangeList::add,
					IPAddressSeqRangeList::remove,
					IPAddressSeqRangeList::contains,
					IPAddressSeqRangeList::indexOfContainingSeqRange,
					IPAddressSeqRangeList::isEmpty,
					true);
		}
		
		void testSpliterate(IPAddressSeqRangeList list) {
			BigInteger size = list.getCount();
			IPAddressSeqRangeListTest.this.testSpliterate(list, 0, size, IPAddressSeqRangeList::spliterator);
			IPAddressSeqRangeListTest.this.testSpliterate(list, 1, size, IPAddressSeqRangeList::spliterator);
			IPAddressSeqRangeListTest.this.testSpliterate(list, 5, size, IPAddressSeqRangeList::spliterator);
			IPAddressSeqRangeListTest.this.testSpliterate(list, -1, size, IPAddressSeqRangeList::spliterator);
		}

		void incrementTestCount() {
			rangeListTestCount++;
		}
	}

	<R extends IPAddressCollection<IPAddress, IPAddressSeqRange>, T extends IPAddress> void testIterate(
			R collection,
			Function<R, Iterator<? extends T>> iteratorFunc, 
			Function<R, BigInteger> collectionSizeFunc,
			UnaryOperator<R> cloneFunc,
			Function<R, ? extends T> firstAddressFunc,
			BiPredicate<R, T> addFunc,
			BiPredicate<R, T> removeFunc,
			BiPredicate<R, T> containsFunc,
			ToIntBiFunction<R, T> indexOfRangeFunc,
			Predicate<R> isEmptyFunc,	
			boolean removeAllowed) {
		// iterate the list, confirm the size by counting
		// clone the list, iterate again, but remove each time, confirm the size
		// confirm list is empty at the end
		BigInteger totalSize = collectionSizeFunc.apply(collection);
		if(totalSize.signum() > 0) {
			R clonedRangeList = cloneFunc.apply(collection);
			T addr = firstAddressFunc.apply(clonedRangeList);
			T toAdd = addr;
			removeFunc.test(clonedRangeList, toAdd);
			Iterator<? extends T> modIterator = iteratorFunc.apply(clonedRangeList);
			long mod = collectionSizeFunc.apply(clonedRangeList).longValue() / 2;
			if(totalSize.compareTo(BigInteger.valueOf(1000)) > 0) {
				mod = 11;
			}
			int i = 0;
			boolean shouldThrow = false;
			try {
				while(modIterator.hasNext()) {
					if(++i == mod) {
						shouldThrow = true;
						addFunc.test(clonedRangeList, toAdd);
					}
					modIterator.next();
					if(shouldThrow) {
						addRangeFailure("expected throw ", clonedRangeList);
						shouldThrow = false;
					}
				}
			} catch(ConcurrentModificationException e) {
				if(!shouldThrow) {
					addRangeFailure("unexpected throw ", clonedRangeList);
				}
			}
		}
		if(totalSize.compareTo(BigInteger.valueOf(1000)) < 0) {
			for(int i = 0; i < 3; i++) {
				boolean firstTime = i == 0;
				boolean secondTime = i == 1;
				
				long expectedSize = collectionSizeFunc.apply(collection).longValue();
				int actualSize = 0;
				Set<T> addressSet = new HashSet<>();
				Iterator<? extends T> iterator = iteratorFunc.apply(collection);
				int j= 0;
				while(iterator.hasNext()) {
					j++;
					
					T next = iterator.next();
					addressSet.add(next);
					actualSize++;
					
					if(firstTime || (secondTime && ((j % 3) != 1))) {
						if(!containsFunc.test(collection, next)) {
							addRangeFailure("after iteration " + next + " not in list ", collection);
						} else if(indexOfRangeFunc != null && indexOfRangeFunc.applyAsInt(collection, next) < 0) {
							addRangeFailure("after iteration address " + next + " not in list ", collection);
						}
					} else {
						try {
							iterator.remove();
							if(!removeAllowed) {
								addRangeFailure("removal " + next + " should not be supported", collection);
							} else if(containsFunc.test(collection, next)) {
								addRangeFailure("after removal " + next + " still in trie ", collection);
							}
						} catch(UnsupportedOperationException e) {
							if(removeAllowed) {
								addRangeFailure("removal " + next + " should be supported", collection);
							}
						}
					}
					
				}
				if(addressSet.size() != expectedSize) {
					addRangeFailure("set count was " + addressSet.size() + " instead of expected " + expectedSize, collection);
				} else if(actualSize != expectedSize) {
					addRangeFailure("count was " + actualSize + " instead of expected " + expectedSize, collection);
				}
				collection = cloneFunc.apply(collection);
			}
			if(removeAllowed) {
				if(!isEmptyFunc.test(collection)) {
					addRangeFailure("list not empty, size " + collectionSizeFunc.apply(collection) + " after removing everything", collection);
				} else if(collectionSizeFunc.apply(collection).signum() > 0) {
					addRangeFailure("range list size not 0, " + collectionSizeFunc.apply(collection) + " after removing everything", collection);
				}
			}
		}
		incrementTestCount();
	}

	private int COUNT_LIMIT = 1024;
	private int SET_COUNT_LIMIT = 2048;

	int spliterateTestCounter = 0;
	
	<R extends IPAddressCollection<IPAddress, IPAddressSeqRange>, T extends IPAddress> Set<T> testSpliterate(R val, int splitCount, BigInteger number, 
			Function<R, Spliterator<T>> spliteratorFunc) {
		spliterateTestCounter++;
		boolean limitedSplit =  number.compareTo(BigInteger.valueOf(COUNT_LIMIT)) > 0;
		ArrayList<Spliterator<T>> list = new ArrayList<>();
		Spliterator<T> spliterator = spliteratorFunc.apply(val);
		list.add(spliterator);
		boolean checkSize = spliterator instanceof BigSpliterator;
		BigInteger originalSize = null;
		boolean isLongish = false;
		if(checkSize) {
			originalSize = ((BigSpliterator<T>) spliterator).getSize();
			isLongish = originalSize.compareTo(LONG_MAX) < 0;
		}
		long originalLongSize = spliterator.getExactSizeIfKnown();
		for(int i = 0; splitCount < 0 || i < splitCount; i++) {
			if(limitedSplit) {
				boolean didSplit = false;
				Spliterator<T> first = list.get(0);
				Spliterator<T> split = first.trySplit();
				if(split != null) {
					didSplit = true;
					list.add(split);
				}
				if(list.size() > 1) {
					Spliterator<T> last = list.get(list.size() - 1);
					split = last.trySplit();
					if(split != null) {
						didSplit = true;
						list.add(split);
					}
				}
				if(!didSplit) {
					break;
				}
			} else {
				ArrayList<Spliterator<T>> newList = new ArrayList<>();
				for(Spliterator<T> toSplit : list) {
					Spliterator<T> split = toSplit.trySplit();
					if(split != null) {
						newList.add(split);
					}
					newList.add(toSplit);
				}
				if(list.size() == newList.size()) {
					for(Spliterator<T> splitter : list) {
						long exactSize = splitter.getExactSizeIfKnown();
						if(exactSize > 2) {
							addRangeFailure("unable to split " + splitter + " but size is " + exactSize, val);
						}
					}
					break;
				}
				list = newList;
			}
			if(checkSize && spliterateTestCounter % 5 == 0) { // we don't always get size, we also want to test splitting and iterating without getting it first
				BigInteger newSize = BigInteger.ZERO;
				long newLongSize = 0;
				for(Spliterator<T> splitter : list) {
					
					newSize = newSize.add(((BigSpliterator<T>) splitter).getSize());
					if(isLongish) {
						long exact = splitter.getExactSizeIfKnown();
						long estimate = splitter.estimateSize();
						if(exact != estimate) {
							addRangeFailure("long value mismatch exact " + exact + " and estimate " + estimate, val);
						}
						newLongSize += exact;
					} else {
						long exact = splitter.getExactSizeIfKnown();
						long estimate = splitter.estimateSize();
						if(exact != Long.MAX_VALUE) {
							addRangeFailure("long value invalid " + exact + " and expected " + Long.MAX_VALUE, val);
						} else if(estimate != -1L) {
							addRangeFailure("long value invalid " + exact + " and expected " + -1L, val);
						}
					}
				}
				// check that total spliterator sizes match the original
				if(!newSize.equals(originalSize)) {
					addRangeFailure("size mismatch, before splits " + originalSize + " and after " + newSize, val);
				} else if(isLongish && newLongSize != originalLongSize) {
					addRangeFailure("long size mismatch, before splits " + originalLongSize + " and after " + newLongSize, val);
				}
			}
		}
		AtomicInteger counter = new AtomicInteger();
		List<Future<?>> jobs = new ArrayList<Future<?>>(list.size());

		int spliteratorCount = list.size();
		int newSpliteratorCount = 0;
		int subSpliteratorCount = 0;
		
		
		Set<T> set = Collections.synchronizedSet(new HashSet<T>());
		
		
		boolean isSmallEnough;
		if(checkSize) {
			isSmallEnough = originalSize.compareTo(INT_MAX) <= 0;
			isSmallEnough &= originalSize.compareTo(BigInteger.valueOf(SET_COUNT_LIMIT)) <= 0;
		} else {
			isSmallEnough = originalLongSize >= 0 && originalLongSize <= SET_COUNT_LIMIT;
		}
		
		if(isSmallEnough) {
			while(true) {
				ArrayList<Spliterator<T>> newList = new ArrayList<>();
				int splitsCounter = 0;
				for(Spliterator<T> splitter : list) {
					int ctr = ++splitsCounter;
					int adjustedCtr = spliterateTestCounter % 3 == 0 ? ctr - 1 : ctr; // this means sometimes we will split off the first spliterator, sometimes not the first
					
					Future<?> job = threadPool.submit(new Runnable() {
						Spliterator<T> toSplit = splitter;
						boolean doTryAdvance = (adjustedCtr % 3) == 0;
						boolean doAdditionalSplit = (adjustedCtr % 6) == 0;
						boolean doTryMultiAdvance = (adjustedCtr % 9) == 0;
						int iteratedCount;
						
						@Override
						public void run() {
							if(doTryMultiAdvance) {
								BigInteger originalSpliteratorSize = checkSize ? ((BigSpliterator<T>) toSplit).getSize() : null;
								for(int i = 0; i < 5; i++) {
									toSplit.tryAdvance(next -> {
										set.add(next);
										counter.incrementAndGet();
										iteratedCount++;
									});
								}
								if(checkSize && !((BigSpliterator<T>) toSplit).getSize().add(BigInteger.valueOf(iteratedCount)).equals(originalSpliteratorSize)) {
									addRangeFailure("size mismatch after advance of 5: " + ((BigSpliterator<T>) toSplit).getSize() + " vs " + originalSpliteratorSize, val);
								}
								if(doAdditionalSplit) {
									Spliterator<T> split = toSplit.trySplit();
									if(split != null) {
										synchronized(newList) {
											newList.add(split);
										}
									}
								}
							} else if(doTryAdvance) {
								BigInteger originalSpliteratorSize = checkSize ? ((BigSpliterator<T>) toSplit).getSize() : null;
								toSplit.tryAdvance(next -> {
									set.add(next);
									counter.incrementAndGet();
									iteratedCount++;
								});
								if(checkSize && !((BigSpliterator<T>) toSplit).getSize().add(BigInteger.valueOf(iteratedCount)).equals(originalSpliteratorSize)) {
									addRangeFailure("size mismatch after advance of 1: " + ((BigSpliterator<T>) toSplit).getSize() + " vs " + originalSpliteratorSize, val);
								}
								if(doAdditionalSplit) {
									Spliterator<T> split = toSplit.trySplit();
									if(split != null) {
										synchronized(newList) {
											newList.add(split);
										}
									}
								}
							}
							toSplit.forEachRemaining(next -> {
								set.add(next);
								counter.incrementAndGet();
							});
						}
					});
					jobs.add(job);
				}
				try {
					for(Future<?> job : jobs) {
						job.get();
					}
				} catch (InterruptedException | ExecutionException e) {
					addRangeFailure("unexpected interruption " + e, val);
				}
				
				if(newList.size() == 0) {
					break;
				}
				if(newSpliteratorCount == 0) {
					if(spliteratorCount == 0 || subSpliteratorCount > 0) {
						throw new Error();
					}
					newSpliteratorCount += newList.size();
				} else {
					subSpliteratorCount += newList.size();
				}
				list = newList;
			}
			if(set.size() != number.intValue()) {
				addRangeFailure("set count was " + set.size() + " instead of expected " + number, val);
			} else if(counter.intValue() != number.intValue()) {
				addRangeFailure("count was " + counter + " instead of expected " + number, val);
			}
			
			if(val instanceof IPAddressSeqRangeList) {
				IPAddressSeqRangeList rangeVal = (IPAddressSeqRangeList) val;
				if(originalSize.compareTo(BigInteger.valueOf(50)) <= 0) {
					spliterator = spliteratorFunc.apply(val);
					// iterate up to, or into, the final range, then split
					// this tests the transition into a spliterator of an individual range from a spliterator of multiple ranges
					
					final HashSet<T> hset = new HashSet<T>();
					counter.set(0);
					int rngCount = rangeVal.getSeqRangeCount();
					Consumer<? super T> action = t -> {
						hset.add(t);
						counter.incrementAndGet();
					};
					for(int i = 0; i < rngCount - 1; i++) { // advance through all the ranges except the last
						IPAddressSeqRange rng = rangeVal.getSeqRange(i);
						int count = rng.getCount().intValueExact();
						for(int j = 0; j < count; j++) {
							spliterator.tryAdvance(action);
						}
					}
					// in some cases, let's move into the final range
					if(spliterateTestCounter % 2 == 0) {
						spliterator.tryAdvance(action);
					}
					
					// do the split
					Spliterator<T> split = spliterator.trySplit();
					if(split != null) {
						split.forEachRemaining(action);
					}
					spliterator.forEachRemaining(action);
					
					if(set.size() != originalSize.intValue()) {
						addRangeFailure("set count was " + hset.size() + " instead of expected " + originalSize, val);
					} else if(set.size() != number.intValue()) {
						addRangeFailure("set count was " + hset.size() + " instead of expected " + number, val);
					} else if(counter.intValue() != number.intValue()) {
						addRangeFailure("count was " + counter + " instead of expected " + number, val);
					}
				}
			}
		}
		return set;
	}
	
	<R extends IPAddressContainmentTrie, T extends IPAddress> void testIterate(R trie) {
		testIterate(trie,
				IPAddressContainmentTrie::iterator,
				IPAddressContainmentTrie::getCount,
				IPAddressContainmentTrie::clone,
				IPAddressContainmentTrie::getLower,
				IPAddressContainmentTrie::add,
				IPAddressContainmentTrie::remove,
				IPAddressContainmentTrie::contains,
				null,
				IPAddressContainmentTrie::isEmpty,
				false);
	}
	
	void testSpliterate(IPAddressContainmentTrie trie) {
		BigInteger size = trie.getCount();
		testSpliterate(trie, 0, size, IPAddressContainmentTrie::spliterator);
		testSpliterate(trie, 1, size, IPAddressContainmentTrie::spliterator);
		testSpliterate(trie, 5, size, IPAddressContainmentTrie::spliterator);
		testSpliterate(trie, -1, size, IPAddressContainmentTrie::spliterator);
	}

	class SingleRangeResult extends TestResult {
		private boolean isIPv6;
		
		private IPAddressSeqRangeList list, expectedIntersection, expectedUnion, expectedRemove;
		
		private IPAddressContainmentTrie listTrie, rngTrie; // the equivalent containment tries

		IPAddressSeqRange rng;
		
		SingleRangeResult(
				boolean isIPv6,
				IPAddressSeqRangeList list, IPAddressSeqRange rng,
				IPAddressContainmentTrie listTrie,
				IPAddressContainmentTrie rngTrie,
				IPAddressSeqRangeList intersection, 
				IPAddressSeqRangeList union,
				IPAddressSeqRangeList remove) {
			this.expectedIntersection = intersection;
			this.expectedUnion = union;
			this.list = list;
			this.rng = rng;
			this.expectedRemove = remove;
			this.isIPv6 = isIPv6;
			this.listTrie = listTrie;
			this.rngTrie = rngTrie;
		}

		@Override
		void test() {

			singleListTestCount++;

			testCollectionOpSingleRange(list, rng, listTrie, IPAddressCollection::add, "add", expectedUnion); // collection test

			testOpSingleRange(list, rng, IPAddressSeqRangeList::intersect, "intersect", expectedIntersection);

			boolean expectedOverlap = !expectedIntersection.isEmpty();

			testCollectionBooleanOpSingleRange(list, rng, listTrie, IPAddressCollection::overlaps, "overlaps", expectedOverlap); // collection test 

			testCollectionOpSingleRange(list, rng, listTrie, IPAddressCollection::remove, "remove", expectedRemove); // collection test 

			// A contains (A intersect B)
			
			IPAddressSeqRangeList intersection = binaryOpSingleRange(list, rng, IPAddressSeqRangeList::intersect, "intersect");
			contains(list,
					intersection,
					true);

			// (A intersect B) contains A iff B contains A

			containsRange(intersection,
					rng,
					list.contains(rng));

			IPAddressSeqRangeList union = binaryOpSingleRange(list, rng, IPAddressSeqRangeList::add, "add");
			contains(union, list, true);

			containsRange(union, rng, true);

			contains(list, union, list.contains(rng));
			
			
			IPAddressCollection<IPAddress, IPAddressSeqRange> unionTrie = collectionBinaryOpSingleRange(listTrie, rng, IPAddressCollection::add, "add");
			
			collectionsMatch(union, unionTrie); // collection test 
			
			containsRange(unionTrie, rng, true); // collection test 
			
			

			IPAddressSeqRangeList empty = new IPAddressSeqRangeList();
			
			// removal of oneself always results in nothing
			testCollectionOpSingleRange(inList(rng), rng, rngTrie, IPAddressCollection::remove, "remove", empty); // collection test 
			
			// intersection with oneself results in the same
			testOpSingleRange(inList(rng), rng, IPAddressSeqRangeList::intersect, "intersect", inList(rng));
			
			// union with oneself results in the same
			testCollectionOpSingleRange(inList(rng), rng, rngTrie, IPAddressCollection::add, "add", inList(rng)); // collection test 

			// removing one from the other, removing the other from the one, then taking the union, is the same as removing the intersection from the union
			matches(
				binaryOp(binaryOpSingleRange(list, rng, IPAddressSeqRangeList::remove, "remove"),
						binaryOp(inList(rng), list, IPAddressSeqRangeList::removeIntoList, "remove"), 
						IPAddressSeqRangeList::joinIntoList, "join"),		
				binaryOp(binaryOpSingleRange(list, rng, IPAddressSeqRangeList::add, "add"),
						binaryOpSingleRange(list, rng, IPAddressSeqRangeList::intersect, "intersect"),
						IPAddressSeqRangeList::removeIntoList, "remove"));
	
			String everythingStr = isIPv6 ? "::/0" : "0.0.0.0/0";
			IPAddress everythingAddr = new IPAddressString(everythingStr).getAddress().toPrefixBlock();
			
			// De Morgan's Law 1
			// complement of the union is the same as the intersection of the complements
			matches(unaryOp(
					convertEmptyVersionForComplement(binaryOpSingleRange(list, rng, IPAddressSeqRangeList::add, "add"), everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
					binaryOp(unaryOp(convertEmptyVersionForComplement(list, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
							unaryOp(inList(rng), IPAddressSeqRangeList::complementIntoList, "complement"), IPAddressSeqRangeList::intersectIntoList, "intersect"));
			
			
			// De Morgan's Law 2
			// complement of the intersection is the same as the union of the complements
			matches(
					unaryOp(convertEmptyVersionForComplement(binaryOpSingleRange(list, rng, IPAddressSeqRangeList::intersect, "intersect"), everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
					binaryOp(unaryOp(convertEmptyVersionForComplement(list, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
							unaryOp(inList(rng), IPAddressSeqRangeList::complementIntoList, "complement"), IPAddressSeqRangeList::joinIntoList, "join"));

			removeIntersection(list, rng);

			unionDoubleIntersect(list, rng, everythingAddr);

			doubleComplement(rng, everythingAddr);

			intersectUnion(list, rng);

			unionIntersect(list, rng);

			removeIntersectComplement(list, rng);

			everythingNothing(rng, everythingAddr);
			
			testRangeListAndRangeSpans(expectedUnion, list, rng, listTrie); // collection test
			
			testIterate(listTrie); // collection test

			testSpliterate(listTrie); // collection test
			
			testEdges(list, listTrie, isIPv6);
			
			testCover(list, listTrie, rng);
		}		
		
		void testRangeListAndRangeSpans(IPAddressSeqRangeList list, IPAddressSeqRangeList joined1, IPAddressSeqRange joined2, IPAddressContainmentTrie joined1Trie) {
			IPAddress[] resultPrefixBlocks = list.spanWithPrefixBlocks();
			IPAddress[] resultSequentialBlocks = list.spanWithSequentialBlocks();
			IPAddress[] prefixBlocks1 = joined1.spanWithPrefixBlocks();
			IPAddress[] prefixBlocks2 = joined2.spanWithPrefixBlocks();
			IPAddress[] seqBlocks1 = joined1.spanWithSequentialBlocks();
			IPAddress[] seqBlocks2 = joined2.spanWithSequentialBlocks();
			
			testPrefixBlockSpan(resultPrefixBlocks, prefixBlocks1, prefixBlocks2, list);
			testPrefixBlockSpan(resultPrefixBlocks, seqBlocks1, seqBlocks2, list);
			testSequentialBlockSpan(resultSequentialBlocks, seqBlocks1, seqBlocks2, list);
			testSequentialBlockSpan(resultSequentialBlocks, prefixBlocks1, prefixBlocks2, list);
			
			compareBlocks(prefixBlocks1, joined1Trie.prefixBlockIterator(), joined1Trie.getPrefixBlockCount(), list); 
		}

		// removing the intersection is the same as removing the original
		void removeIntersection(IPAddressSeqRangeList list, IPAddressSeqRange rng) {
			matches(binaryOp(list, binaryOpSingleRange(list, rng, IPAddressSeqRangeList::intersect, "intersect"), IPAddressSeqRangeList::removeIntoList, "remove"), 
					binaryOpSingleRange(list, rng, IPAddressSeqRangeList::remove, "remove"));
		}
		
		// double complement results in the original
		void doubleComplement(IPAddressSeqRange rng, IPAddress everythingAddr) {
			
			IPAddressSeqRange complement[] = rng.complement();
			BigInteger count = BigInteger.ZERO;
			for(IPAddressSeqRange r : complement) {
				count = count.add(r.getCount());
			}
			matchesCount(everythingAddr.getCount(), count.add(rng.getCount()), list);
			IPAddressSeqRangeList listComplement = convertEmptyVersionForComplement(inList(complement), everythingAddr);
			matches(
				inList(rng), 
				listComplement.complementIntoList());
			
			
			IPAddressSeqRangeList listCompl = rng.complementIntoList();
			matchesCount(everythingAddr.getCount(), listCompl.getCount().add(rng.getCount()), list);
			listComplement = convertEmptyVersionForComplement(listCompl, everythingAddr);
			matches(
					inList(rng), 
					listComplement.complementIntoList());
		}
		
		// A intersect (A union B) = A
		void intersectUnion(IPAddressSeqRangeList list, IPAddressSeqRange rng) {
			matches(
					list,
					binaryOp(list, binaryOpSingleRange(list, rng, IPAddressSeqRangeList::add, "add"),
							IPAddressSeqRangeList::intersectIntoList, "intersect"));
		}
		
		// A union (A intersect B) = A
		void unionIntersect(IPAddressSeqRangeList list, IPAddressSeqRange rng) {
			matches(
					list,
					binaryOp(list, binaryOpSingleRange(list, rng, IPAddressSeqRangeList::intersect, "intersect"),
							IPAddressSeqRangeList::joinIntoList, "join"));
		}
		
		// intersect with complement and then with original, take union, should be the original
		void unionDoubleIntersect(IPAddressSeqRangeList list, IPAddressSeqRange rng, IPAddress everythingAddr) {
			matches(
					binaryOp(
							binaryOpSingleRange(list, rng, IPAddressSeqRangeList::intersect, "intersect"), 
							binaryOpSingleRange(
									unaryOp(convertEmptyVersionForComplement(list, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"), 
									rng,
									IPAddressSeqRangeList::intersect, "intersect"), 
							IPAddressSeqRangeList::joinIntoList, "join"),
					inList(rng));
		}
		
		// A remove B = A intersect (B complement)
		void removeIntersectComplement(IPAddressSeqRangeList list, IPAddressSeqRange rng) {
			matches(
					binaryOpSingleRange(list, rng, IPAddressSeqRangeList::remove, "remove"),
					binaryOp(list, inList(rng.complement()), IPAddressSeqRangeList::intersectIntoList, "intersect"));
		}
		
		// A Union (A complement) = everything
		// A intersect (A complement) = nothing
		void everythingNothing(IPAddressSeqRange rng, IPAddress everythingAddr) {
			IPAddressSeqRange complement[] = rng.complement();
			IPAddressSeqRangeList nothing = new IPAddressSeqRangeList();
			matches(
					nothing,
					binaryOpSingleRange(inList(complement), rng, IPAddressSeqRangeList::intersect, "intersect"));

			nothing.add(everythingAddr);
			IPAddressSeqRangeList everything = nothing;
			matches(
					everything,
					binaryOpSingleRange(inList(complement), rng, IPAddressSeqRangeList::add, "add"));
		}
				
		void containsRange(IPAddressCollection<IPAddress, IPAddressSeqRange> containing, IPAddressSeqRange contained, boolean expected) {
			rangeListTestCount++;
			if(containing.contains(contained) == expected) {
				if(expected && containing.getCount().compareTo(contained.getCount()) < 0) {
					addRangeFailure("failed count for containment for list: " + containing + " and single range: " + contained +  " expected containment: " + expected, list);
				} else {
					if(printPass) {
						System.out.println("pass");
					}
				}
			} else {
				addRangeFailure("fail contains for collection: " + containing + " and contained address: " + contained +  " expected containment: " + expected, list);
			}
		}
		
		private IPAddressSeqRangeList binaryOpSingleRange(IPAddressSeqRangeList list, IPAddressSeqRange list2, BiPredicate<IPAddressSeqRangeList, IPAddressSeqRange> op, String opName) {
			IPAddressSeqRangeList res = list.clone();
			boolean val = op.test(res, list2);
			if(list.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
				addRangeFailure("failed return value for " + opName + " for list: "+ list + " and single range: " + list2 +  " expected same: " + val + " original: " + list + " result: " + res, list);
			} else {
				if(printPass) {
					System.out.println("pass " + opName);
				}
			}
			if(print) {
				System.out.println(list);
				System.out.println(list2);
				System.out.println(opName);
				System.out.println(res);
				System.out.println(val);
				System.out.println();
			}
			return res;
		}
		
		private IPAddressCollection<IPAddress, IPAddressSeqRange> collectionBinaryOpSingleRange(IPAddressCollection<IPAddress, IPAddressSeqRange> coll, IPAddressSeqRange list2, BiPredicate<IPAddressCollection<IPAddress, IPAddressSeqRange> , IPAddressSeqRange> op, String opName) {
			IPAddressCollection<IPAddress, IPAddressSeqRange> res = coll.clone();
			boolean val = op.test(res, list2);
			if(list.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
				addRangeFailure("failed return value for " + opName + " for list: "+ list + " and single range: " + list2 +  " expected same: " + val + " original: " + list + " result: " + res, list);
			} else {
				if(printPass) {
					System.out.println("pass " + opName);
				}
			}
			if(print) {
				System.out.println(list);
				System.out.println(list2);
				System.out.println(opName);
				System.out.println(res);
				System.out.println(val);
				System.out.println();
			}
			return res;
		}
		
		private void testCollectionOpSingleRange(IPAddressSeqRangeList list, IPAddressSeqRange rng, IPAddressContainmentTrie containmentTrie, BiPredicate<IPAddressCollection<IPAddress, IPAddressSeqRange>, IPAddressSeqRange> op, String opName, IPAddressSeqRangeList expected) {
			rangeListTestCount++;
			IPAddressSeqRangeList res = list.clone();
			boolean val = op.test(res, rng);
			if(res.equals(expected)) {
				if(!res.getCount().equals(expected.getCount()) || res.getSeqRangeCount() != expected.getSeqRangeCount()) {
					addRangeFailure("failed count for " + opName + " for list: " + list + " and single range: " + rng +  " expected: " + expected + " result: " + res, list);
				} else if(list.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
					addRangeFailure("failed return value for " + opName + " for list: " + list + " and single range: " + rng +  " expected same: " + val + " original: " + list + " result: " + res, list);
				} else {
					if(printPass) {
						System.out.println("pass " + opName);
					}
				}
			} else {
				addRangeFailure("fail " + opName + " for list: "+ list + " and single range: " + rng +  " expected: " + expected + " actual: " + res, list);
			}
			
			rangeListTestCount++;
			IPAddressContainmentTrie trieRes = containmentTrie.clone();
			val = op.test(trieRes, rng);
			if(trieRes.equals(expected)) {
				if(!trieRes.getCount().equals(expected.getCount())) {
					addRangeFailure("failed count for " + opName + " for trie: " + containmentTrie + " and single range: " + rng +  " expected: " + expected + " result: " + trieRes, list);
				} else if(containmentTrie.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
					addRangeFailure("failed return value for " + opName + " for trie: " + containmentTrie + " and single range: " + rng +  " expected same: " + val + " original: " + containmentTrie + " result: " + trieRes, list);
				} else {
					if(printPass) {
						System.out.println("pass " + opName);
					}
				}
			} else {
				addRangeFailure("fail " + opName + " for trie: "+ trieRes + " and single range: " + rng +  " expected: " + expected + " actual: " + res, trieRes);
				trieRes = containmentTrie.clone();
				val = op.test(trieRes, rng);
			}
		}
		
		private void testOpSingleRange(IPAddressSeqRangeList list, IPAddressSeqRange rng, BiPredicate<IPAddressSeqRangeList, IPAddressSeqRange> op, String opName, IPAddressSeqRangeList expected) {
			rangeListTestCount++;
			IPAddressSeqRangeList res = list.clone();
			boolean val = op.test(res, rng);
			if(res.equals(expected)) {
				if(!res.getCount().equals(expected.getCount()) || res.getSeqRangeCount() != expected.getSeqRangeCount()) {
					addRangeFailure("failed count for " + opName + " for list: " + list + " and single range: " + rng +  " expected: " + expected + " result: " + res, list);
				} else if(list.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
					addRangeFailure("failed return value for " + opName + " for list: " + list + " and single range: " + rng +  " expected same: " + val + " original: " + list + " result: " + res, list);
				} else {
					if(printPass) {
						System.out.println("pass " + opName);
					}
				}
			} else {
				addRangeFailure("fail " + opName + " for list: "+ list + " and single range: " + rng +  " expected: " + expected + " actual: " + res, list);
			}
		}

		private void testCollectionBooleanOpSingleRange(IPAddressSeqRangeList list1, IPAddressSeqRange list2, IPAddressContainmentTrie containmentTrie, BiPredicate<IPAddressCollection<IPAddress, IPAddressSeqRange>, IPAddressSeqRange> op, String opName, boolean expected) {
			rangeListTestCount++;
			boolean res = op.test(list1, list2);
			if(res == expected) {
				if(printPass) {
					System.out.println("pass " + opName);
				}
			} else {
				addRangeFailure("fail " + opName + " for list: "+ list1 + " and single range: " + list2 +  " expected: " + expected + " actual: " + res, list);
			}
			
			rangeListTestCount++;
			res = op.test(containmentTrie, list2);
			if(res == expected) {
				if(printPass) {
					System.out.println("pass " + opName);
				}
			} else {
				addRangeFailure("fail " + opName + " for trie: "+ containmentTrie + " and single range: " + list2 +  " expected: " + expected + " actual: " + res, containmentTrie);
			}
		}
	}
	
	void testCover(IPAddressSeqRangeList list, IPAddressContainmentTrie listTrie, IPAddress addr) {
		testCover(list, listTrie);
		testCover(addr.intoSequentialRangeList(), createContainmentTrie(addr));
	}
	
	void testCover(IPAddressSeqRangeList list, IPAddressContainmentTrie listTrie, IPAddressSeqRange rng) {
		testCover(list, listTrie);
		testCover(rng.intoSequentialRangeList(), createContainmentTrie(rng));
	}
	
	void testCover(IPAddressSeqRangeList list, IPAddressContainmentTrieBase<? extends IPAddress, ? extends IPAddressSeqRange> listTrie) {
		if(!Objects.equals(list.coverWithPrefixBlock(), listTrie.coverWithPrefixBlock())) {
			addRangeFailure("cover with prefix block mismatch, " + list.coverWithPrefixBlock() +  " and " + listTrie.coverWithPrefixBlock(), list);
		} else if(!Objects.equals(list.coverWithSequentialRange(), listTrie.coverWithSequentialRange())) {
			addRangeFailure("cover with sequential range mismatch, " + list.coverWithSequentialRange() +  " and " + listTrie.coverWithSequentialRange(), list);
		} else if(list.isSequential() != listTrie.isSequential()) {
			addRangeFailure("isSequential mismatch, " + list.isSequential() +  " and " + listTrie.isSequential(), list);
		}
//		if(listTrie.isSequential()) {
//			System.out.println("is sequential: " + listTrie.isSequential());
//			System.out.println(listTrie);
//		}
		rangeListTestCount++;
	}

	void testEdges(IPAddressSeqRangeList list, IPAddressContainmentTrie listTrie, boolean isIPv6) {
		int rangeCount = list.getSeqRangeCount();
		if(rangeCount == 0) {
			String everythingStr = isIPv6 ? "::/0" : "0.0.0.0/0";
			IPAddress everythingAddr = new IPAddressString(everythingStr).getAddress();
			matches(list.floor(everythingAddr), null, list);
			matches(list.ceiling(everythingAddr), null, list);
			matches(list.lower(everythingAddr), null, list);
			matches(list.higher(everythingAddr), null, list);
			
			matches(listTrie.floor(everythingAddr), null, listTrie);
			matches(listTrie.ceiling(everythingAddr), null, listTrie);
			matches(listTrie.lower(everythingAddr), null, listTrie);
			matches(listTrie.higher(everythingAddr), null, listTrie);
			
			String zeroStr = isIPv6 ? "::" : "0.0.0.0";
			IPAddress zeroAddr = new IPAddressString(zeroStr).getAddress();
			matches(list.floor(zeroAddr), null, list);
			matches(list.ceiling(zeroAddr), null, list);
			matches(list.lower(zeroAddr), null, list);
			matches(list.higher(zeroAddr), null, list);
			
			matches(listTrie.floor(zeroAddr), null, listTrie);
			matches(listTrie.ceiling(zeroAddr), null, listTrie);
			matches(listTrie.lower(zeroAddr), null, listTrie);
			matches(listTrie.higher(zeroAddr), null, listTrie);
			
			String maxStr = isIPv6 ? "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" : "255.255.255.255";
			IPAddress maxAddr = new IPAddressString(maxStr).getAddress();
			matches(list.floor(maxAddr), null, list);
			matches(list.ceiling(maxAddr), null, list);
			matches(list.lower(maxAddr), null, list);
			matches(list.higher(maxAddr), null, list);
			
			matches(listTrie.floor(maxAddr), null, listTrie);
			matches(listTrie.ceiling(maxAddr), null, listTrie);
			matches(listTrie.lower(maxAddr), null, listTrie);
			matches(listTrie.higher(maxAddr), null, listTrie);
			
			String str = isIPv6 ? "1:2:3:4::" : "1.2.3.4";
			IPAddress addr = new IPAddressString(str).getAddress();
			matches(list.floor(addr), null, list);
			matches(list.ceiling(addr), null, list);
			matches(list.lower(addr), null, list);
			matches(list.higher(addr), null, list);
			
			matches(listTrie.floor(addr), null, listTrie);
			matches(listTrie.ceiling(addr), null, listTrie);
			matches(listTrie.lower(addr), null, listTrie);
			matches(listTrie.higher(addr), null, listTrie);

			rangeListTestCount++;
			
		} else if(rangeCount == 1) {
			IPAddressSeqRange rng = list.getSeqRange(0);
			testRangeEdges(list, listTrie, null, rng, null);
		} else if(rangeCount == 2) {
			IPAddressSeqRange rng0 = list.getSeqRange(0);
			IPAddressSeqRange rng1 = list.getSeqRange(1);
			testRangeEdges(list, listTrie, null, rng0, rng1);
			testRangeEdges(list, listTrie, rng0, rng1, null);
		} else if(rangeCount == 3) {
			IPAddressSeqRange rng0 = list.getSeqRange(0);
			IPAddressSeqRange rng1 = list.getSeqRange(1);
			IPAddressSeqRange rng2 = list.getSeqRange(2);
			testRangeEdges(list, listTrie, null, rng0, rng1);
			testRangeEdges(list, listTrie, rng0, rng1, rng2);
			testRangeEdges(list, listTrie, rng1, rng2, null);
		} else {
			//take the lower range, one in middle, and the upper range
			
			IPAddressSeqRange rng0 = list.getLowerSeqRange();
			IPAddressSeqRange rng1 = list.getSeqRange(1);
			testRangeEdges(list, listTrie, null, rng0, rng1);
			
			int middleIndex = rangeCount >> 1;
			IPAddressSeqRange rngMiddlePrevious = list.getSeqRange(middleIndex - 1);
			IPAddressSeqRange rngMiddle = list.getSeqRange(middleIndex);
			IPAddressSeqRange rngMiddleNext = list.getSeqRange(middleIndex + 1);
			testRangeEdges(list, listTrie, rngMiddlePrevious, rngMiddle, rngMiddleNext);
			
			IPAddressSeqRange rngUpperPrevious = list.getSeqRange(rangeCount - 2);
			IPAddressSeqRange rngUpper = list.getUpperSeqRange();
			testRangeEdges(list, listTrie, rngUpperPrevious, rngUpper, null);
		}
			
	}

	void testRangeEdges(IPAddressSeqRangeList list, IPAddressContainmentTrie listTrie, IPAddressSeqRange left, IPAddressSeqRange middle, IPAddressSeqRange right) {
		boolean hasLeft = left != null;
		boolean hasRight = right != null;
		boolean isMultiple = middle.isMultiple();
		
		IPAddress lowerAddr = middle.getLower();
		
		// lower: highest < addr
		// floor: highest <= addr
		// ceiling: lowest >= addr
		// higher: lower > addr
		
		// address to the left
		if(!lowerAddr.isZero()) {
			IPAddress lower = hasLeft ? left.getUpper() : null;
			testFourEdges(list, listTrie, lowerAddr.decrement(), lower, lower, lowerAddr, lowerAddr);
		}
		
	
		// lower boundary
		testFourEdges(list, listTrie, lowerAddr, hasLeft ? left.getUpper() : null, lowerAddr, lowerAddr, isMultiple ? lowerAddr.increment() : (hasRight ? right.getLower() : null));
		
		if(isMultiple || !lowerAddr.isMax()) {
			IPAddress lowerNext = lowerAddr.increment();
			IPAddress upperAddr = middle.getUpper();
			
			if(isMultiple) {
				//addresses in the middle
				if(!lowerNext.equals(upperAddr)) {
					IPAddress lowerNextNext = lowerNext.increment();
					testFourEdges(list, listTrie, lowerNext, lowerAddr, lowerNext, lowerNext, lowerNextNext);
					
					if(!lowerNextNext.equals(upperAddr)) {
						IPAddress upperPrevious = upperAddr.decrement();
						testFourEdges(list, listTrie, upperPrevious, upperPrevious.decrement(), upperPrevious, upperPrevious, upperAddr);
					}
				}

				// upper boundary
				testFourEdges(list, listTrie, upperAddr, isMultiple ? upperAddr.decrement() : (hasLeft ? left.getUpper() : null), upperAddr, upperAddr, hasRight ? right.getLower() : null);
			}
			
			// address to the right
			if(!upperAddr.isMax()) {
				IPAddress upper = hasRight ? right.getLower() : null;
				testFourEdges(list, listTrie, upperAddr.increment(), upperAddr, upperAddr, upper, upper);
			}
		}
	}
	
	void testFourEdges(IPAddressSeqRangeList list, IPAddressContainmentTrie listTrie, IPAddress addr,
			IPAddress expectedLower, IPAddress expectedFloor, IPAddress expectedCeiling, IPAddress expectedHigher) {
		matches(list.lower(addr), expectedLower, list);
		matches(list.floor(addr), expectedFloor, list);
		matches(list.ceiling(addr), expectedCeiling, list);
		matches(list.higher(addr), expectedHigher, list);
		
		matches(listTrie.lower(addr), expectedLower, listTrie);
		matches(listTrie.floor(addr), expectedFloor, listTrie);
		matches(listTrie.ceiling(addr), expectedCeiling, listTrie);
		matches(listTrie.higher(addr), expectedHigher, listTrie);
		
		rangeListTestCount++;
	}
	
	class AddressResult extends TestResult {
		private boolean isIPv6;
		
		private IPAddressSeqRangeList list, expectedIntersection, expectedUnion, expectedRemove;
		
		private IPAddressContainmentTrie listTrie, addrTrie; // the equivalent containment tries

		IPAddress addr;
		
		AddressResult(
				boolean isIPv6,
				IPAddressSeqRangeList list, IPAddress address, 
				IPAddressContainmentTrie listTrie,
				IPAddressContainmentTrie addrTrie,
				IPAddressSeqRangeList intersection, 
				IPAddressSeqRangeList union,
				IPAddressSeqRangeList remove) {
			this.expectedIntersection = intersection;
			this.expectedUnion = union;
			this.list = list;
			this.addr = address;
			this.expectedRemove = remove;
			this.isIPv6 = isIPv6;
			this.listTrie = listTrie;
			this.addrTrie = addrTrie;
		}

		@Override
		void test() {
			addressTestCount++;
			
			testCollectionOpSingleAddress(list, addr, listTrie, IPAddressCollection::add, "add", expectedUnion);

			testOpSingleAddress(list, addr, IPAddressSeqRangeList::intersect, "intersect", expectedIntersection);

			boolean expectedOverlap = !expectedIntersection.isEmpty();
			
			tesCollectionBooleanOpSingleAddress(list, addr, listTrie, IPAddressCollection::overlaps, "overlaps", expectedOverlap);

			testCollectionOpSingleAddress(list, addr, listTrie, IPAddressCollection::remove, "remove", expectedRemove);
			
			// A contains (A intersect B)
			
			IPAddressSeqRangeList intersection = binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::intersect, "intersect");
			contains(list,
					intersection,
					true);

			// (A intersect B) contains A iff B contains A
			
			containsAddress(intersection,
					addr,
					list.contains(addr));
			
			IPAddressSeqRangeList union = binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::add, "add");
			contains(union, list, true); 

			containsAddress(union, addr, true);

			contains(list, union, list.contains(addr));
			
			
			IPAddressCollection<IPAddress, IPAddressSeqRange> unionTrie = collectionBinaryOpSingleAddress(listTrie, addr, IPAddressCollection::add, "add");
			
			collectionsMatch(union, unionTrie); // collection test 
			
			containsAddress(unionTrie, addr, true); // collection test 
			

			IPAddressSeqRangeList empty = new IPAddressSeqRangeList();
			
			// removal of oneself always results in nothing
			testCollectionOpSingleAddress(inList(addr), addr, addrTrie, IPAddressCollection::remove, "remove", empty); // collection test 
			
			// intersection with oneself results in the same
			testOpSingleAddress(inList(addr), addr, IPAddressSeqRangeList::intersect, "intersect", inList(addr));
			
			// union with oneself results in the same
			testCollectionOpSingleAddress(inList(addr), addr, addrTrie, IPAddressCollection::add, "add", inList(addr)); // collection test 

			// removing one from the other, removing the other from the one, then taking the union, is the same as removing the intersection from the union
			matches(
				binaryOp(binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::remove, "remove"),
						binaryOp(inList(addr), list, IPAddressSeqRangeList::removeIntoList, "remove"), 
						IPAddressSeqRangeList::joinIntoList, "join"),		
				binaryOp(binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::add, "add"),
						binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::intersect, "intersect"),
						IPAddressSeqRangeList::removeIntoList, "remove"));
	
			String everythingStr = isIPv6 ? "::/0" : "0.0.0.0/0";
			IPAddress everythingAddr = new IPAddressString(everythingStr).getAddress().toPrefixBlock();
			
			// De Morgan's Law 1
			// complement of the union is the same as the intersection of the complements
			matches(unaryOp(
					convertEmptyVersionForComplement(binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::add, "add"), everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
					binaryOp(unaryOp(convertEmptyVersionForComplement(list, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
							unaryOp(inList(addr), IPAddressSeqRangeList::complementIntoList, "complement"), IPAddressSeqRangeList::intersectIntoList, "intersect"));
			
			// De Morgan's Law 2
			// complement of the intersection is the same as the union of the complements
			matches(
					unaryOp(convertEmptyVersionForComplement(binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::intersect, "intersect"), everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
					binaryOp(unaryOp(convertEmptyVersionForComplement(list, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"),
							unaryOp(inList(addr), IPAddressSeqRangeList::complementIntoList, "complement"), IPAddressSeqRangeList::joinIntoList, "join"));

			removeIntersection(list, addr);
						
			unionDoubleIntersect(list, addr, everythingAddr);
			
			// double complement results in the original
			
			doubleComplement(addr, everythingAddr);

			intersectUnion(list, addr);
			
			unionIntersect(list, addr);
			
			removeIntersectComplement(list, addr);
			
			everythingNothing(addr, everythingAddr);
			
			testRangeListAndAddressSpans(expectedUnion, list, addr, listTrie); // collection test
			
			testIterate(listTrie); // collection test

			testSpliterate(listTrie); // collection test
			
			testEdges(list, listTrie, isIPv6);
			
			testCover(list, listTrie, addr);
		}
		
		void testRangeListAndAddressSpans(IPAddressSeqRangeList list, IPAddressSeqRangeList joined1, IPAddress joined2, IPAddressContainmentTrie joined1Trie) {
			
			IPAddress[] resultPrefixBlocks = list.spanWithPrefixBlocks();
			IPAddress[] resultSequentialBlocks = list.spanWithSequentialBlocks();
			IPAddress[] prefixBlocks1 = joined1.spanWithPrefixBlocks();
			IPAddress[] prefixBlocks2 = joined2.spanWithPrefixBlocks();
			IPAddress[] seqBlocks1 = joined1.spanWithSequentialBlocks();
			IPAddress[] seqBlocks2 = joined2.spanWithSequentialBlocks();
			
			
			testPrefixBlockSpan(resultPrefixBlocks, prefixBlocks1, prefixBlocks2, list);
			testPrefixBlockSpan(resultPrefixBlocks, seqBlocks1, seqBlocks2, list);
			testPrefixBlockSpan(resultPrefixBlocks, prefixBlocks1, new IPAddress[] {joined2}, list);
			testSequentialBlockSpan(resultSequentialBlocks, seqBlocks1, seqBlocks2, list);
			testSequentialBlockSpan(resultSequentialBlocks, prefixBlocks1, prefixBlocks2, list);
			testSequentialBlockSpan(resultSequentialBlocks, seqBlocks1, new IPAddress[] {joined2}, list);
			
			compareBlocks(prefixBlocks1, joined1Trie.prefixBlockIterator(), joined1Trie.getPrefixBlockCount(), list);
		}
		
		// removing the intersection is the same as removing the original
		void removeIntersection(IPAddressSeqRangeList list, IPAddress addr) {
			matches(binaryOp(list, binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::intersect, "intersect"), IPAddressSeqRangeList::removeIntoList, "remove"), 
					binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::remove, "remove"));
		}
				
		// double complement results in the original
		void doubleComplement(IPAddress addr, IPAddress everythingAddr) {
			IPAddressSeqRangeList list = new IPAddressSeqRangeList();
			list.add(addr);
			IPAddressSeqRangeList complement = list.complementIntoList();
			BigInteger count = complement.getCount();
			matchesCount(everythingAddr.getCount(), count.add(addr.getCount()), list);
			IPAddressSeqRangeList listComplement = convertEmptyVersionForComplement(complement, everythingAddr);
			matches(
				inList(addr), 
				listComplement.complementIntoList());
		}

		// A intersect (A union B) = A
		void intersectUnion(IPAddressSeqRangeList list, IPAddress addr) {
			matches(
					list,
					binaryOp(list, binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::add, "add"),
							IPAddressSeqRangeList::intersectIntoList, "intersect"));
		}
		
		// A union (A intersect B) = A
		void unionIntersect(IPAddressSeqRangeList list, IPAddress addr) {
			matches(
					list,
					binaryOp(list, binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::intersect, "intersect"),
							IPAddressSeqRangeList::joinIntoList, "join"));
		}
		
		// intersect with complement and then with original, take union, should be the original
		void unionDoubleIntersect(IPAddressSeqRangeList list, IPAddress addr, IPAddress everythingAddr) {
			matches(
					binaryOp(
							binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::intersect, "intersect"), 
							binaryOpSingleAddress(
									unaryOp(convertEmptyVersionForComplement(list, everythingAddr), IPAddressSeqRangeList::complementIntoList, "complement"), 
									addr,
									IPAddressSeqRangeList::intersect, "intersect"), 
							IPAddressSeqRangeList::joinIntoList, "join"),
					inList(addr));
		}
		
		// A remove B = A intersect (B complement)
		void removeIntersectComplement(IPAddressSeqRangeList list, IPAddress addr) {
			IPAddressSeqRangeList addrList = new IPAddressSeqRangeList();
			addrList.add(addr);
			IPAddressSeqRangeList complement = addrList.complementIntoList();
			matches(
					binaryOpSingleAddress(list, addr, IPAddressSeqRangeList::remove, "remove"),
					binaryOp(list, /* inList(addr.complement())*/ complement, IPAddressSeqRangeList::intersectIntoList, "intersect"));
		}
		
		// A Union (A complement) = everything
		// A intersect (A complement) = nothing
		void everythingNothing(IPAddress addr, IPAddress everythingAddr) {
			IPAddressSeqRangeList list = new IPAddressSeqRangeList();
			list.add(addr);
			IPAddressSeqRangeList complement = list.complementIntoList();
			IPAddressSeqRangeList nothing = new IPAddressSeqRangeList();
			matches(
					nothing,
					binaryOpSingleAddress(complement, addr, IPAddressSeqRangeList::intersect, "intersect"));

			nothing.add(everythingAddr);
			IPAddressSeqRangeList everything = nothing;
			matches(
					everything,
					binaryOpSingleAddress(complement, addr, IPAddressSeqRangeList::add, "add"));
		}

		void containsAddress(IPAddressCollection<IPAddress, IPAddressSeqRange> containing, IPAddress contained, boolean expected) {
			rangeListTestCount++;
			if(containing.contains(contained) == expected) {
				if(expected && containing.getCount().compareTo(contained.getCount()) < 0) {
					addRangeFailure("failed count for containment for list: " + containing + " and address: " + contained +  " expected containment: " + expected, list);
				} else {
					if(printPass) {
						System.out.println("pass");
					}
				}
			} else {
				addRangeFailure("fail contains for collection: "+ containing + " and contained address: " + contained +  " expected containment: " + expected, list);
			}
		}

		private IPAddressSeqRangeList binaryOpSingleAddress(IPAddressSeqRangeList list, IPAddress address, BiPredicate<IPAddressSeqRangeList, IPAddress> op, String opName) {
			IPAddressSeqRangeList res = list.clone();
			boolean val = op.test(res, address);
			if(list.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
				addRangeFailure("failed return value for " + opName + " for list: "+ list + " and address: " + addr +  " expected same: " + val + " original: " + list + " result: " + res, list);
			}
			if(print) {
				System.out.println(list);
				System.out.println(address);
				System.out.println(opName);
				System.out.println(res);
				System.out.println(val);
				System.out.println();
			}
			return res;
		}

		private IPAddressCollection<IPAddress, IPAddressSeqRange> collectionBinaryOpSingleAddress(IPAddressCollection<IPAddress, IPAddressSeqRange> collection, IPAddress address, BiPredicate<IPAddressCollection<IPAddress, IPAddressSeqRange>, IPAddress> op, String opName) {
			IPAddressCollection<IPAddress, IPAddressSeqRange> res = collection.clone();
			boolean val = op.test(res, address);
			if(collection.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
				addRangeFailure("failed return value for " + opName + " for list: "+ list + " and address: " + addr +  " expected same: " + val + " original: " + list + " result: " + res, list);
			}
			if(print) {
				System.out.println(collection);
				System.out.println(address);
				System.out.println(opName);
				System.out.println(res);
				System.out.println(val);
				System.out.println();
			}
			return res;
		}

		private void testOpSingleAddress(IPAddressSeqRangeList list, IPAddress addr, BiPredicate<IPAddressSeqRangeList, IPAddress> op, String opName, IPAddressSeqRangeList expected) {
			rangeListTestCount++;
			IPAddressSeqRangeList res = list.clone();
			boolean val = op.test(res, addr);
			if(res.equals(expected)) {
				if(!res.getCount().equals(expected.getCount()) || res.getSeqRangeCount() != expected.getSeqRangeCount()) {
					addRangeFailure("failed count for " + opName + " for list: " + list + " and address: " + addr +  " expected: " + expected + " result: " + res, list);
				} else if(list.equals(res) == val) { 
					addRangeFailure("failed return value for " + opName + " for list: " + list + " and address: " + addr +  " expected same: " + val + " original: " + list + " result: " + res, list);
				} else {
					if(printPass) {
						System.out.println("pass " + opName);
					}
				}
			} else {
				addRangeFailure("fail " + opName + " for list: "+ list + " and address: " + addr +  " expected: " + expected + " actual: " + res, list);
			}
		}

		private void testCollectionOpSingleAddress(IPAddressSeqRangeList list, IPAddress addr, IPAddressContainmentTrie containmentTrie, BiPredicate<IPAddressCollection<IPAddress, IPAddressSeqRange>, IPAddress> op, String opName, IPAddressSeqRangeList expected) {
			rangeListTestCount++;
			IPAddressSeqRangeList res = list.clone();
			boolean val = op.test(res, addr);
			if(res.equals(expected)) {
				if(!res.getCount().equals(expected.getCount()) || res.getSeqRangeCount() != expected.getSeqRangeCount()) {
					addRangeFailure("failed count for " + opName + " for list: " + list + " and address: " + addr +  " expected: " + expected + " result: " + res, list);
				} else if(list.equals(res) == val) { 
					addRangeFailure("failed return value for " + opName + " for list: " + list + " and address: " + addr +  " expected same: " + val + " original: " + list + " result: " + res, list);
				} else {
					if(printPass) {
						System.out.println("pass " + opName);
					}
				}
			} else {
				addRangeFailure("fail " + opName + " for list: "+ list + " and address: " + addr +  " expected: " + expected + " actual: " + res, list);
			}

			rangeListTestCount++;
			IPAddressContainmentTrie trieRes = containmentTrie.clone();
			val = op.test(trieRes, addr);
			if(trieRes.equals(expected)) {
				if(!trieRes.getCount().equals(expected.getCount())) {
					addRangeFailure("failed count for " + opName + " for trie: " + containmentTrie + " and address: " + addr +  " expected: " + expected + " result: " + trieRes, list);
				} else if(containmentTrie.equals(res) == val) { // val true changed, list equal res then false, then false != true is true
					addRangeFailure("failed return value for " + opName + " for trie: " + containmentTrie + " and address: " + addr +  " expected same: " + val + " original: " + containmentTrie + " result: " + trieRes, list);
				} else {
					if(printPass) {
						System.out.println("pass " + opName);
					}
				}
			} else {
				addRangeFailure("fail " + opName + " for trie: "+ trieRes + " and address: " + addr +  " expected: " + expected + " actual: " + res, trieRes);
			}
		}

		private void tesCollectionBooleanOpSingleAddress(IPAddressSeqRangeList list, IPAddress addr, IPAddressContainmentTrie containmentTrie, BiPredicate<IPAddressCollection<IPAddress, IPAddressSeqRange>, IPAddress> op, String opName, boolean expected) {
			rangeListTestCount++;
			boolean res = op.test(list, addr);
			if(res == expected) {
				if(printPass) {
					System.out.println("pass " + opName);
				}
			} else {
				addRangeFailure("fail " + opName + " for list: "+ list + " and address: " + addr +  " expected: " + expected + " actual: " + res, list);
			}
			
			rangeListTestCount++;
			res = op.test(containmentTrie, addr);
			if(res == expected) {
				if(printPass) {
					System.out.println("pass " + opName);
				}
			} else {
				addRangeFailure("fail " + opName + " for trie: "+ containmentTrie + " and address: " + addr +  " expected: " + expected + " actual: " + res, containmentTrie);
			}
		}
	}

	// all failures in this test module go through addRangeFailure
	void addRangeFailure(String message, IPAddressCollection<IPAddress, IPAddressSeqRange> list) {
		rangeListFailCount++;
		addFailure(new Failure(message, list));
	}

	// You cannot take the complement of an empty IPAddressSeqRangeList, because you do not know which address space to use, IPv4 or IPv6.
	// However, when using a subclass like IPv4AddressSeqRangeList, you do know it is the IPv4 address space, you can determine the complement as being the range 0 -> 255.255.255.255
	// So, prior to any complement operation, this function checks if the operand is empty, and if so, substitutes the appropriate subtype  empty list so that the complement operation will succeed.
	IPAddressSeqRangeList convertEmptyVersionForComplement(IPAddressSeqRangeList list, IPAddress everythingAddr) {
		if(list.isEmpty()) {
			IPAddressSeqRangeList res = everythingAddr.intoSequentialRangeList();
			res.clear();
			return res;
		}
		return list;
	}

	//unaryOp and binaryOp are unnecessary, we could just call the op.  But they can be useful for debugging.

	IPAddressSeqRangeList binaryOp(IPAddressSeqRangeList list1, IPAddressSeqRangeList list2, BinaryOperator<IPAddressSeqRangeList> op, String opName) {
		IPAddressSeqRangeList res = op.apply(list1, list2);
		if(print) {
			System.out.println(list1);
			System.out.println(list2);
			System.out.println(opName);
			System.out.println(res);
			System.out.println();
		}
		return res;
	}

	IPAddressSeqRangeList unaryOp(IPAddressSeqRangeList list, UnaryOperator<IPAddressSeqRangeList> op, String opName) {
		IPAddressSeqRangeList res = op.apply(list);
		if(print) {
			System.out.println(list);
			System.out.println(opName);
			System.out.println(res);
			System.out.println();
		}
		return res;
	}

	IPAddressSeqRangeList inList(IPAddressSeqRange ...rngs) {
		IPAddressSeqRangeList list = new IPAddressSeqRangeList();
		for(IPAddressSeqRange rng : rngs) {
			list.add(rng);
		}
		return list;
	}

	IPAddressSeqRangeList inList(IPAddress addr) {
		return addr.intoSequentialRangeList();
	}

	void contains(IPAddressSeqRangeList containing, IPAddressSeqRangeList contained, boolean expected) {
		rangeListTestCount++;
		if(containing.contains(contained) == expected) {
			if(expected && containing.getCount().compareTo(contained.getCount()) < 0) {
				addRangeFailure("failed count for containment for list: " + containing + " and address: " + contained +  " expected containment: " + expected, containing);
			} else {
				if(printPass) {
					System.out.println("pass");
				}
			}
		} else {
			addRangeFailure("fail contains for list: "+ containing + " and contained address: " + contained +  " expected containment: " + expected, containing);
		}
	}

	void matchesCount(BigInteger res, BigInteger expected, IPAddressSeqRangeList list) {
		rangeListTestCount++;
		if(res.equals(expected)) {
			if(printPass) {
				System.out.println("pass");
			}
		} else {
			addRangeFailure("fail match, got: "+ res +  ", expected match: " + expected, list);
		}
	}

	void collectionsMatch(IPAddressCollection<IPAddress, IPAddressSeqRange> res, IPAddressCollection<IPAddress, IPAddressSeqRange> expected) {
		rangeListTestCount++;
		if(res.equals(expected) && expected.equals(res)) {
			if(!res.getCount().equals(expected.getCount())) {
				addRangeFailure("failed count for list, got " + res.getCount() +  " expected " + expected.getCount(), expected);
			//} else if(res.getSeqRangeCount() != expected.getSeqRangeCount()) {
			//	addRangeFailure("failed sequential range count for list, got " + res.getSeqRangeCount() +  " expected " + expected.getSeqRangeCount(), expected);
			} else {
				if(printPass) {
					System.out.println("pass");
				}
			}
		} else {
			addRangeFailure("fail match for list, got: "+ res +  ", expected match: " + expected, expected);
		}
	}

	void matches(IPAddress one, IPAddress two, IPAddressCollection<IPAddress, IPAddressSeqRange> coll) {
		if(!Objects.equals(one, two)) {
			addRangeFailure("address mismatch, " + one +  " and " + two, coll);
		} else if(one != null && one.getPrefixLength() != null) {
			addRangeFailure("prefix unexpected: " + one.getPrefixLength(), coll);
		} else if(two != null && two.getPrefixLength() != null) {
			addRangeFailure("prefix unexpected: " + two.getPrefixLength(), coll);
		}
	}
	
	void matches(IPAddressSeqRangeList res, IPAddressSeqRangeList expected) {
		rangeListTestCount++;
		if(res.equals(expected)) {
			if(!res.getCount().equals(expected.getCount())) {
				addRangeFailure("failed count for list, got " + res.getCount() +  " expected " + expected.getCount(), expected);
			} else if(res.getSeqRangeCount() != expected.getSeqRangeCount()) {
				addRangeFailure("failed sequential range count for list, got " + res.getSeqRangeCount() +  " expected " + expected.getSeqRangeCount(), expected);
			} else {
				if(printPass) {
					System.out.println("pass");
				}
			}
		} else {
			addRangeFailure("fail match for list, got: "+ res +  ", expected match: " + expected, expected);
		}
	}

	void testPrefixBlockSpan(IPAddress prefixBlocks[], IPAddress joined1[], IPAddress joined2[], IPAddressSeqRangeList list) {
		IPAddress merged[];
		if(joined1.length > 0) {
			merged = joined1[0].mergeToPrefixBlocks(join(joined1, joined2));
		} else if(joined2.length > 0) {
			merged = joined2[0].mergeToPrefixBlocks(join(joined1, joined2));
		} else {
			merged = new IPAddress[0];
		}
		compareBlocks(prefixBlocks, merged, list);
	}

	void testSequentialBlockSpan(IPAddress sequentialBlocks[], IPAddress joined1[], IPAddress joined2[], IPAddressSeqRangeList list) {
		IPAddress merged[];
		if(joined1.length > 0) {
			merged = joined1[0].mergeToSequentialBlocks(join(joined1, joined2));
		} else if(joined2.length > 0) {
			merged = joined2[0].mergeToSequentialBlocks(join(joined1, joined2));
		} else {
			merged = new IPAddress[0];
		}
		compareBlocks(sequentialBlocks, merged, list);
	}

	static <T> T[] join(T one[], T two[]) {
		if (one.length == 0) {
	        return two;
	    } else if (two.length == 0) {
	        return one;
	    }
		T result[] = Arrays.copyOf(one, one.length + two.length);
		System.arraycopy(two, 0, result, one.length, two.length);
		return result;
	}

	void compareBlocks(IPAddress blocks1[], IPAddress blocks2[], IPAddressSeqRangeList list) {
		if(blocks1.length != blocks2.length) {
			addRangeFailure("blocks mismatch, matching " + Arrays.asList(blocks1) + " and " + Arrays.asList(blocks2), list);
		} else {
			for(int i = 0; i < blocks1.length; i++) {
				if(!blocks1[i].equals(blocks2[i])) {
					addRangeFailure("blocks mismatch with block " + blocks1[i] + " and " + blocks2[i] + ", matching " + Arrays.asList(blocks1) + " and " + Arrays.asList(blocks2), list);
				} else if(!Objects.equals(blocks1[i].getPrefixLength(), blocks2[i].getPrefixLength())) {
					addRangeFailure("blocks prefix mismatch with block " + blocks1[i] + " and " + blocks2[i] + ", matching " + Arrays.asList(blocks1) + " and " + Arrays.asList(blocks2), list);
				}
			}
		}
	}
	
	void compareBlocks(IPAddress spanningBlocks[], Iterator<IPAddress> blocks2, int blocks2Count, IPAddressSeqRangeList list) {
		if(spanningBlocks.length != blocks2Count) {
			addRangeFailure("blocks mismatch, matching " + Arrays.asList(spanningBlocks) + " with count " + blocks2Count, list);
		} else {
			int i = 0;
			while(blocks2.hasNext()) {
				IPAddress block2 = blocks2.next();
				IPAddress spanningBlock = spanningBlocks[i];
				if(!spanningBlock.equals(block2)) {
					addRangeFailure("blocks mismatch with block " + spanningBlock + " and " + block2 + ", matching " + Arrays.asList(spanningBlocks) + " and " + Arrays.asList(blocks2), list);
				} else {
					if(spanningBlock.isPrefixed() && spanningBlock.getPrefixLength() == spanningBlock.getBitCount()) {
						spanningBlock = spanningBlock.withoutPrefixLength();
					}
					if(!Objects.equals(spanningBlock.getPrefixLength(), block2.getPrefixLength())) {
						addRangeFailure("blocks prefix mismatch with block " + spanningBlock + " and " + block2 + ", matching " + Arrays.asList(spanningBlocks) + " and " + Arrays.asList(blocks2), list);
					}
				}
				i++;
			}
		}
	}

	void testRangeListIncrement() {
		IPAddressSeqRangeList list = new IPAddressSeqRangeList();
		IPAddress last = new IPAddressString("2.255.3.4").getAddress();
		int increment = -1;
		int len = 211;
		for(int i = 0; i < len; i++) {
			IPAddress first = last.increment(99);
			increment++;
			if(i % 2 == 0) {
				increment += 7;
				last = first.increment(7);
			} else {
				increment += 9;
				last = first.increment(9);
			}
			IPAddressSeqRange rng = first.spanWithRange(last);
			list.add(rng);
		}
		
		rangeListTestCount++;
		IPAddress inc = list.increment(BigInteger.valueOf(increment));
		IPAddress longInc = list.increment(increment);
		if(!inc.equals(last) || !longInc.equals(last)) {
			addRangeFailure("failed increment for list " + list + ", increment was " + increment + " result was " + inc + ", long increment result was " + longInc + ", expected " + last, list);
		} else {
			if(list.enumerate(inc).intValue() != increment) {
				addRangeFailure("failed enumerate for list, got: "+ list.enumerate(inc) + ", enumerate: " + inc + ", expected: " + increment, list);
			} else if(!list.getUpperSeqRange().contains(inc)) {
				addRangeFailure("fail containment for list: upper range: "+ list.getUpperSeqRange() + ", enumerate: " + inc + ", increment: " + increment, list);
			} else {
				if(printPass) {
					System.out.println("pass increment");
				}
				
				rangeListTestCount++;
				// do it again, this time it does binary search on the existing range sizes
				inc = list.increment(BigInteger.valueOf(increment));
				longInc = list.increment(increment);
				if(!inc.equals(last) || !longInc.equals(last)) {
					addRangeFailure("failed increment for list " + list + ", increment was " + increment + " result was " + inc + ", long increment result was " + longInc + ", expected " + last, list);
				} else {
					if(list.enumerate(inc).intValue() != increment) {
						addRangeFailure("fail enumerate for list, got: "+ list.enumerate(inc) + ", enumerate: " + inc + ", expected: " + increment, list);
					} else {
						if(printPass) {
							System.out.println("pass increment");
						}
					}
				}
			}
		}
		
		list.clear();
		last = new IPAddressString("2.255.3.4").getAddress();
		increment = -1;
		IPAddressSeqRange midRange = null, firstRange = null;
		int midRangeIncrement = 0;
		len = 131;
		int firstLen = 7;
		for(int i = 0; i < len; i++) {
			IPAddress first = last.increment(99);
			increment++;
			if(i % 2 == 0) {
				increment += firstLen;
				last = first.increment(7);
			} else {
				increment += 9;
				last = first.increment(9);
			}
			IPAddressSeqRange rng = first.spanWithRange(last);
			if(i == len/2) {
				midRangeIncrement = increment;
				midRange = rng;
			}
			if(i == 0) {
				firstRange = rng;
			}
			list.add(rng);
		}
		
		// now we do various increments that incrementally populate the rangeSizes

		rangeListTestCount++;
		int firstRangeIncrement = firstLen/2 + firstLen/4;
		IPAddress expectedFirstIncrement = firstRange.getLower().increment(firstRangeIncrement);
		IPAddress firstIncrement = list.increment(BigInteger.valueOf(firstRangeIncrement));
		IPAddress longFirstIncrement = list.increment(firstRangeIncrement);
		if(!firstIncrement.equals(expectedFirstIncrement) || !longFirstIncrement.equals(expectedFirstIncrement)) {
			addRangeFailure("failed increment for list " + list + ", increment was " + firstRangeIncrement + " result was " + firstIncrement + ", long increment result was " + longFirstIncrement + ", expected " + expectedFirstIncrement, list);
		} else {
			if(list.enumerate(firstIncrement).intValue() != firstRangeIncrement) {
				addRangeFailure("fail enumerate for list " + list + ", got: "+ list.enumerate(firstIncrement) + ", enumerate: " + firstIncrement + ", expected: " + firstRangeIncrement, list);
			} else if(!list.getLowerSeqRange().contains(firstIncrement)) {
				addRangeFailure("fail containment for list: lower range: "+ list.getLowerSeqRange() + ", enumerate: " + firstIncrement + ", increment: " + firstRangeIncrement, list);
			} else {
				if(printPass) {
					System.out.println("pass increment");
				}
				
				rangeListTestCount++;
				// do it gain, this time it does binary search on the existing range sizes
				firstIncrement = list.increment(BigInteger.valueOf(firstRangeIncrement));
				longFirstIncrement = list.increment(firstRangeIncrement);
				if(!firstIncrement.equals(expectedFirstIncrement) || !longFirstIncrement.equals(expectedFirstIncrement)) {
					addRangeFailure("failed increment for list " + list + ", increment was " + firstRangeIncrement + " result was " + firstIncrement + ", long increment result was " + longFirstIncrement + ", expected " + expectedFirstIncrement, list);
				} else {
					if(list.enumerate(firstIncrement).intValue() != firstRangeIncrement) {
						addRangeFailure("fail enumerate for list " + list + ", got: "+ list.enumerate(firstIncrement) + ", enumerate: " + firstIncrement + ", expected: " + firstRangeIncrement, list);
					} else if(!list.getLowerSeqRange().contains(firstIncrement)) {
						addRangeFailure("fail containment for list: lower range: "+ list.getLowerSeqRange() + ", enumerate: " + firstIncrement + ", increment: " + firstRangeIncrement, list);
					} else {
						if(printPass) {
							System.out.println("pass increment");
						}

						// we do a mid range increment next, it creates some of the range sizes, so some of them are there for the next search
						rangeListTestCount++;
						IPAddress midIncrement = list.increment(BigInteger.valueOf(midRangeIncrement));
						IPAddress longMidIncrement = list.increment(midRangeIncrement);
						if(!midIncrement.equals(midRange.getUpper()) || !longMidIncrement.equals(midRange.getUpper())) {
							addRangeFailure("failed increment for list " + list + ", increment was " + midRangeIncrement + " result was " + midIncrement + ", long increment result was " + longMidIncrement + ", expected " + midRange.getUpper(), list);
						} else {
							if(list.enumerate(midIncrement).intValue() != midRangeIncrement) {
								addRangeFailure("fail enumerate for list " + list + ", got: "+ list.enumerate(midIncrement) + ", enumerate: " + midIncrement + ", expected: " + midRangeIncrement, list);
							} else if(!midRange.contains(midIncrement)) {
								addRangeFailure("fail containment for list: mid range: "+ midRange + ", enumerate: " + midIncrement + ", increment: " + midRangeIncrement, list);
							} else {
								if(printPass) {
									System.out.println("pass increment");
								}
								
								rangeListTestCount++;
								// do it gain, this time it does binary search on the existing range sizes
								midIncrement = list.increment(BigInteger.valueOf(midRangeIncrement));
								longMidIncrement = list.increment(midRangeIncrement);
								if(!midIncrement.equals(midRange.getUpper())|| !longMidIncrement.equals(midRange.getUpper())) {
									addRangeFailure("failed increment for list " + list + ", increment was " + midRangeIncrement + " result was " + midIncrement + ", long increment result was " + longMidIncrement + ", expected " + midRange.getUpper(), list);
								} else {
									if(list.enumerate(midIncrement).intValue() != midRangeIncrement) {
										addRangeFailure("fail enumerate for list " + list + ", got: "+ list.enumerate(midIncrement) + ", enumerate: " + midIncrement + ", expected: " + midRangeIncrement, list);
									} else if(!midRange.contains(midIncrement)) {
										addRangeFailure("fail containment for list: mid range: "+ midRange + ", enumerate: " + midIncrement + ", increment: " + midRangeIncrement, list);
									} else {
										if(printPass) {
											System.out.println("pass increment");
										}
										// now do a range search to the end, some of the range sizes will be there, some not, this tests the switch-over
										rangeListTestCount++;
										inc = list.increment(BigInteger.valueOf(increment));
										longInc = list.increment(increment);
										if(!inc.equals(last) || !longInc.equals(last)) {
											addRangeFailure("failed increment for list " + list + ", increment was " + increment + " result was " + inc + ", long increment result was " + longInc + ", expected " + last, list);
										} else {
											if(list.enumerate(inc).intValue() != increment) {
												addRangeFailure("fail enumerate for list " + list + ", got: "+ list.enumerate(inc) + ", enumerate: " + inc + ", expected: " + increment, list);
											} else if(!list.getUpperSeqRange().contains(inc)) {
												addRangeFailure("fail containment for list: upper range: "+ list.getUpperSeqRange() + ", enumerate: " + inc + ", increment: " + increment, list);
											} else {
												if(printPass) {
													System.out.println("pass increment");
												}
												
												rangeListTestCount++;
												// do it again, this time it does binary search on the existing range sizes
												inc = list.increment(BigInteger.valueOf(increment));
												longInc = list.increment(increment);
												if(!inc.equals(last) || !longInc.equals(last)) {
													addRangeFailure("failed increment for list " + list + ", increment was " + increment + " result was " + inc + ", long increment result was " + longInc + ", expected " + last, list);
												} else {
													if(list.enumerate(inc).intValue() != increment) {
														addRangeFailure("fail enumerate for list " + list + ", got: "+ list.enumerate(inc) + ", enumerate: " + inc + ", expected: " + increment, list);
													} else if(!list.getUpperSeqRange().contains(inc)) {
														addRangeFailure("fail containment for list: upper range: "+ list.getUpperSeqRange() + ", enumerate: " + inc + ", increment: " + increment, list);
													} else {
														if(printPass) {
															System.out.println("pass increment");
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
		}
	}

	void test(TestResult tests[]) {
		for(TestResult r : tests) {
			r.test();
		}
	}

	@Override
	void runTest() {
		String range1[][] = {
			{"0.0.0.1", "0.0.0.2"},
			{"0.0.0.10", "0.0.0.12"},
			{"0.0.0.20", "0.0.0.22"},	
		};

		String range2[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.11"},
			{"0.0.0.21", "0.0.0.25"},
		};
		
		String range1range2Union[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.12"},
			{"0.0.0.20", "0.0.0.25"},
		};
		
		String range1range2Intersection[][] = {
			{"0.0.0.1", "0.0.0.2"},
			{"0.0.0.10", "0.0.0.11"},
			{"0.0.0.21", "0.0.0.22"},
		};
		
		String range1range2Remove[][] = {
			{"0.0.0.12", "0.0.0.12"},
			{"0.0.0.20", "0.0.0.20"},
		};

		String range2range1Remove[][] = {
			{"0.0.0.3", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.9"},
			{"0.0.0.23", "0.0.0.25"},
		};

		String empty[][] = {};

		TestResult[] result = initIPv4Lists(
				range1, range2, range1range2Intersection, range1range2Union, range1range2Remove, range2range1Remove);
		
		TestResult result2[] = initIPv4Lists(
				range1, range1, range1, range1, empty, empty);
		
		TestResult result3[] = initIPv4Lists(
				range2, range2, range2, range2, empty, empty);
		
		test(result);

		test(result2);

		test(result3);

		
		String range3[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.7"},
			{"0.0.0.9", "0.0.0.25"},		
		};
		
		String range2range3Union[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.25"},
		};
		
		String range2range3Intersection[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.7"},
			{"0.0.0.9", "0.0.0.11"},
			{"0.0.0.21", "0.0.0.25"},
		};
		
		String range2range3Remove[][] = {
			{"0.0.0.8", "0.0.0.8"},
		};
		
		String range3range2Remove[][] = {
			{"0.0.0.12", "0.0.0.20"},	
		};
		
		TestResult result4[] = initIPv4Lists(
				range2, range3, range2range3Intersection, range2range3Union, range2range3Remove, range3range2Remove);
		
		test(result4);
		
		String range3a[][] = {
				{"0.0.0.1", "0.0.0.3"},
				{"0.0.0.7", "0.0.0.7"},
				{"0.0.0.9", "0.0.0.25"},
				{"0.0.0.50", "0.0.0.75"},
				{"0.0.0.80", "0.0.0.255"},
			};
		
		String range2range3aUnion[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.25"},
			{"0.0.0.50", "0.0.0.75"},
			{"0.0.0.80", "0.0.0.255"},
		};
		
		String range2range3aIntersection[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.7"},
			{"0.0.0.9", "0.0.0.11"},
			{"0.0.0.21", "0.0.0.25"},
		};
		
		String range2range3aRemove[][] = {
			{"0.0.0.8", "0.0.0.8"},
		};
		
		String range3arange2Remove[][] = {
			{"0.0.0.12", "0.0.0.20"},
			{"0.0.0.50", "0.0.0.75"},
			{"0.0.0.80", "0.0.0.255"},
		};
		
		test(initIPv4Lists(
				range2, range3a, range2range3aIntersection, range2range3aUnion, range2range3aRemove, range3arange2Remove));
			
		
		
		String range4[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.9"},
			{"0.0.0.12", "0.0.0.25"},
		};
		
		String range2range4Union[][] = range2range3Union;
		
		String range2range4Intersection[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.9"},
			{"0.0.0.21", "0.0.0.25"},		
		};
		
		String range2range4Remove[][] = {
			{"0.0.0.10", "0.0.0.11"},
		};
		
		String range4range2Remove[][] = {
			{"0.0.0.12", "0.0.0.20"},
		};
		
		TestResult result5[] = initIPv4Lists(
				range2, range4, range2range4Intersection, range2range4Union, range2range4Remove, range4range2Remove);
		
		test(result5);

		String range3range4Union[][] = range2range3Union;
		
		String range3range4Intersection[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.7"},
			{"0.0.0.9", "0.0.0.9"},
			{"0.0.0.12", "0.0.0.25"},		
		};
		
		String range3range4Remove[][] = {
			{"0.0.0.10", "0.0.0.11"},
		};
		
		String range4range3Remove[][] = {
			{"0.0.0.8", "0.0.0.8"},
		};
		
		TestResult result6[] = initIPv4Lists(
				range3, range4, range3range4Intersection, range3range4Union, range3range4Remove, range4range3Remove);
		
		test(result6);

		String range5[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.8", "0.0.0.9"},
			{"0.0.0.12", "0.0.0.25"},		
		};

		String range3range5Union[][] = range2range3Union;
		
		String range3range5Intersection[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.9", "0.0.0.9"},
			{"0.0.0.12", "0.0.0.25"},
		};

		String range3range5Remove[][] = {
			{"0.0.0.7", "0.0.0.7"},
			{"0.0.0.10", "0.0.0.11"},
		};
		
		String range5range3Remove[][] = {
			{"0.0.0.8", "0.0.0.8"},
		};
		
		TestResult result7[] = initIPv4Lists(
				range3, range5, range3range5Intersection, range3range5Union, range3range5Remove, range5range3Remove);
		
		test(result7);
		
		String range6[][] = {
			{"0.0.0.0", "0.0.3.0"},
			{"0.0.5.0", "0.0.13.0"},
			{"0.0.21.0", "0.0.26.0"},
			{"0.0.36.0", "0.0.40.0"},
			{"0.0.42.0", "0.0.50.0"},
		};
		
		String range7[][] = {
			{"0.0.1.0", "0.0.8.0"},
			{"0.0.13.0", "0.0.20.0"},
			{"0.0.27.0", "0.0.35.0"},
			{"0.0.37.0", "0.0.42.0"},	
			{"0.0.45.0", "0.0.55.0"},
		};
		
		String range6range7Union[][] = {
			{"0.0.0.0", "0.0.20.0"},
			{"0.0.21.0", "0.0.26.0"},
			{"0.0.27.0", "0.0.35.0"},
			{"0.0.36.0", "0.0.55.0"},
		};
		
		String range6range7Intersection[][] = {
			{"0.0.1.0", "0.0.3.0"},
			{"0.0.5.0", "0.0.8.0"},
			{"0.0.13.0", "0.0.13.0"},
			{"0.0.37.0", "0.0.40.0"},
			{"0.0.42.0", "0.0.42.0"},
			{"0.0.45.0", "0.0.50.0"},
		};
		
		String range6range7Remove[][] = {
			{"0.0.0.0", "0.0.0.255"},
			{"0.0.8.1", "0.0.12.255"},
			{"0.0.21.0", "0.0.26.0"},
			{"0.0.36.0", "0.0.36.255"},
			{"0.0.42.1", "0.0.44.255"},
		};
		
		String range7range6Remove[][] = {
			{"0.0.3.1", "0.0.4.255"},
			{"0.0.13.1", "0.0.20.0"},
			{"0.0.27.0", "0.0.35.0"},
			{"0.0.40.1", "0.0.41.255"},
			{"0.0.50.1", "0.0.55.0"},
		};
		
		TestResult result8[] = initIPv4Lists(
				range6, range7, range6range7Intersection, range6range7Union, range6range7Remove, range7range6Remove);
		
		test(result8);
		
		String range8[][] = {
			{"0.0.0.0", "0.0.255.0"},
		};
		
		String range7range8Remove[][] = {};
		
		String range8range7Remove[][] = {
			{"0.0.0.0", "0.0.0.255"},
			{"0.0.8.1", "0.0.12.255"},
			{"0.0.20.1", "0.0.26.255"},
			{"0.0.35.1", "0.0.36.255"},
			{"0.0.42.1", "0.0.44.255"},
			{"0.0.55.1", "0.0.255.0"},
		};
		
		TestResult result9[] = initIPv4Lists(
				range7, range8, range7, range8, range7range8Remove, range8range7Remove);
		
		test(result9);
		
		String range9[][] = {
			{"0.0.0.1", "0.0.254.0"},
		};
		
		String range7range9Remove[][] = empty;
		
		String range9range7Remove[][] = {
			{"0.0.0.1", "0.0.0.255"},
			{"0.0.8.1", "0.0.12.255"},
			{"0.0.20.1", "0.0.26.255"},
			{"0.0.35.1", "0.0.36.255"},
			{"0.0.42.1", "0.0.44.255"},
			{"0.0.55.1", "0.0.254.0"},
		};

		TestResult result10[] = initIPv4Lists(
				range7, range9, range7, range9, range7range9Remove, range9range7Remove);

		test(result10);

		String range10[][] = {
			{"0.0.0.0", "0.0.0.3"},
			{"0.0.0.5", "0.0.0.13"},
			{"0.0.0.21", "0.0.0.26"},
			{"0.0.0.36", "0.0.0.40"},	
			{"0.0.0.42", "0.0.0.50"},	
		};

		String range11[][] = {
			{"0.0.0.1", "0.0.0.8"},
			{"0.0.0.13", "0.0.0.20"},
			{"0.0.0.27", "0.0.0.35"},		
			{"0.0.0.37", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.55"},
		};

		String range10range11Union[][] = {
			{"0.0.0.0", "0.0.0.55"},
		};

		String range10range11Intersection[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.5", "0.0.0.8"},
			{"0.0.0.13", "0.0.0.13"},
			{"0.0.0.37", "0.0.0.40"},
			{"0.0.0.42", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.50"},
		};
		
		String range10range11Remove[][] = {
			{"0.0.0.0", "0.0.0.0"},
			{"0.0.0.9", "0.0.0.12"},
			{"0.0.0.21", "0.0.0.26"},
			{"0.0.0.36", "0.0.0.36"},
			{"0.0.0.43", "0.0.0.44"},
		};
		
		String range11range10Remove[][] = {
			{"0.0.0.4", "0.0.0.4"},
			{"0.0.0.14", "0.0.0.20"},
			{"0.0.0.27", "0.0.0.35"},
			{"0.0.0.41", "0.0.0.41"},
			{"0.0.0.51", "0.0.0.55"},
		};

		test(initIPv4Lists(
				range10, range11, range10range11Intersection, range10range11Union, range10range11Remove, range11range10Remove));
		
		String range12[][] = {
			{"0.0.0.1", "0.0.0.3"},
			{"0.0.0.7", "0.0.0.25"},		
		};

		String range12range4Union[][] = range12;
		
		String range12range4Intersection[][] = range4;
		
		String range12range4Remove[][] = {
			{"0.0.0.10", "0.0.0.11"},
		};
		
		String range4range12Remove[][] = empty;
		
		test(initIPv4Lists(
				range4, range12, range12range4Intersection, range12range4Union, range4range12Remove, range12range4Remove));
		
		
		test(initIPv4Lists(
			new String[][] {
			}, // multi range 1
			new String[][]{
				{"0.0.0.1", "0.0.0.8"},
				{"0.0.0.13", "0.0.0.20"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
			}, //  multi range 2
			new String[][] {	
			}, // intersection
			new String[][] {
				{"0.0.0.1", "0.0.0.8"},
				{"0.0.0.13", "0.0.0.20"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
			}, // union
			new String[][] {
			}, // multi 1 remove multi 2
			new String[][] {
				{"0.0.0.1", "0.0.0.8"},
				{"0.0.0.13", "0.0.0.20"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
			} // multi 2 remove multi 1
	
		));
		
		test(initIPv4Lists(
			new String[][] {
			}, // multi range 1
			new String[][]{
			}, //  multi range 2
			new String[][] {	
			}, // intersection
			new String[][] {
			}, // union
			new String[][] {
			}, // multi 1 remove multi 2
			new String[][] {
			} // multi 2 remove multi 1
		));

		String singleRange0[] = {"0.0.0.24", "0.0.0.36"};
		
		String range11single0Intersection[][] = {
			{"0.0.0.27", "0.0.0.35"}
		};
		String range11single0union[][] = {
			{"0.0.0.1", "0.0.0.8"},
			{"0.0.0.13", "0.0.0.20"},
			{"0.0.0.24", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.55"},
		};
		String range11Single0Remove[][] = {
			{"0.0.0.1", "0.0.0.8"},
			{"0.0.0.13", "0.0.0.20"},
			{"0.0.0.37", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.55"},
		};
		String range11Single0ReverseRemove[][] = {
			{"0.0.0.24", "0.0.0.26"},
			{"0.0.0.36", "0.0.0.36"},
		};
		test(initIPv4SingleList(
			range11, 
			singleRange0, 
			range11single0Intersection,
			range11single0union,
			range11Single0Remove,
			range11Single0ReverseRemove));


		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.36"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.20", "0.0.0.36"}, // single range
				new String[][] {
					{"0.0.0.20", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13","0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.19"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.19", "0.0.0.36"}, // single range
				new String[][] {
					{"0.0.0.19", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13","0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.18"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.14", "0.0.0.36"}, // single range
				new String[][] {
					{"0.0.0.14", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13","0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.13"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.13", "0.0.0.36"}, // single range
				new String[][] {
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13","0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.12", "0.0.0.36"}, // single range
				new String[][] {
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.12","0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.12","0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.37"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.37"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.38", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.38"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.38"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.39", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.41"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.41"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.42", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.42"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.42"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.43"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.42"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.43"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.43"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.44"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.42"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.24", "0.0.0.45"}, // single range
				new String[][] {
					{"0.0.0.27", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.45"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.24", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.46", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.24", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "255.0.0.0"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "255.0.0.0"},
				}, // union
				new String[][] {}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "255.0.0.0"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "255.0.0.0"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "255.0.0.0"},
				}, // union
				new String[][] {}, // multi remove single
				new String[][] {
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "255.0.0.0"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.2", "255.0.0.0"}, // single range
				new String[][] {
					{"0.0.0.2", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "255.0.0.0"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.1"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "255.0.0.0"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "255.255.255.255"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "255.255.255.255"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "255.255.255.255"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "255.255.255.254"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "255.255.255.254"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "255.255.255.254"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "255.255.255.254"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "255.255.255.254"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "255.255.255.254"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "255.255.255.255"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "255.255.255.255"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "255.255.255.255"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "0.0.0.56"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "0.0.0.56"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "0.0.0.56"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "0.0.0.56"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.56"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
					{"0.0.0.56", "0.0.0.56"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "0.0.0.55"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "0.0.0.55"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "0.0.0.55"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.55"},
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "0.0.0.54"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.54"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.55", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "0.0.0.54"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.54"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.55", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					//{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
					{"0.0.0.36", "0.0.0.36"},
					{"0.0.0.43", "0.0.0.44"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "0.0.0.1"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.1"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.2", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
				} // single remove multi
		));

		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "0.0.0.0"}, // single range
				new String[][] {
					//{"0.0.0.1", "0.0.0.1"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "0.0.0.1"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.1"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.2", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					//{"0.0.0.0", "0.0.0.0"},
				} // single remove multi
		));

		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.54", "0.0.0.55"}, // single range
				new String[][] {
					{"0.0.0.54", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.53"},
				}, // multi remove single
				new String[][] {
				} // single remove multi
		));
		
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.54", "0.0.0.54"}, // single range
				new String[][] {
					{"0.0.0.54", "0.0.0.54"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.53"},
					{"0.0.0.55", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.55", "0.0.0.55"}, // single range
				new String[][] {
					{"0.0.0.55", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.54"},
				}, // multi remove single
				new String[][] {
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.56", "0.0.0.56"}, // single range
				new String[][] {
					//{"0.0.0.55", "0.0.0.55"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.56"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.56", "0.0.0.56"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.14", "0.0.0.14"}, // single range
				new String[][] {
					{"0.0.0.14", "0.0.0.14"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.13"},
					{"0.0.0.15", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					//{"0.0.0.56", "0.0.0.56"},
				} // single remove multi
		));
		
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.0", "0.0.0.30"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.30"},
				}, // intersection
				new String[][] {
					{"0.0.0.0", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.31", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
				} // single remove multi
		));
		
///////////////////////////////////////////////////////
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.1", "0.0.0.30"}, // single range
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.30"},
				}, // intersection
				new String[][] {
					{"0.0.0.1", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.31", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					//{"0.0.0.0", "0.0.0.0"},
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
					{"0.0.0.1", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, //  multi range
				new String[]{"0.0.0.2", "0.0.0.30"}, // single range
				new String[][] {
					{"0.0.0.2", "0.0.0.8"},
					{"0.0.0.13", "0.0.0.20"},
					{"0.0.0.27", "0.0.0.30"},
				}, // intersection
				new String[][] {
					{"0.0.0.01", "0.0.0.35"},
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // union
				new String[][] {
					{"0.0.0.1", "0.0.0.1"},
					{"0.0.0.31", "0.0.0.35"},		
					{"0.0.0.37", "0.0.0.42"},
					{"0.0.0.45", "0.0.0.55"},
				}, // multi remove single
				new String[][] {
					{"0.0.0.9", "0.0.0.12"},
					{"0.0.0.21", "0.0.0.26"},
				} // single remove multi
		));
		
		test(initIPv4SingleList(
				new String[][] {
				}, //  multi range
				new String[]{
					"0.0.0.2", "0.0.0.30"}, // single range
				new String[][] {		
				}, // intersection
				new String[][] {
					{"0.0.0.2", "0.0.0.30"}
				}, // union
				new String[][] {
				}, // multi remove single
				new String[][] {
					{"0.0.0.2", "0.0.0.30"}
				} // single remove multi
		));


		test(initIPv4Lists(
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
			}, // multi range 1
			new String[][]{
				{"0.0.0.50", "0.0.0.75"},
			}, //  multi range 2
			new String[][] {
				{"0.0.0.50", "0.0.0.55"},
			}, // intersection
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.75"},
			}, // union
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.49"},
			}, // multi 1 remove multi 2
			new String[][] {
				{"0.0.0.56", "0.0.0.75"},
			} // multi 2 remove multi 1
		));
		
		test(initIPv4Lists(
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
			}, // multi range 1
			new String[][]{
				{"0.0.0.80", "0.0.0.255"},
			}, //  multi range 2
			new String[][] {
			}, // intersection
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
				{"0.0.0.80", "0.0.0.255"},
			}, // union
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
			}, // multi 1 remove multi 2
			new String[][] {
				{"0.0.0.80", "0.0.0.255"},
			} // multi 2 remove multi 1
		));
		
		test(initIPv4Lists(
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.55"},
			}, // multi range 1
			new String[][]{
				{"0.0.0.50", "0.0.0.75"},
				{"0.0.0.80", "0.0.0.255"},
			}, //  multi range 2
			new String[][] {
				{"0.0.0.50", "0.0.0.55"},
			}, // intersection
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.75"},
				{"0.0.0.80", "0.0.0.255"},
			}, // union
			new String[][] {
				{"0.0.0.1", "0.0.0.4"},
				{"0.0.0.8", "0.0.0.14"},
				{"0.0.0.17", "0.0.0.17"},
				{"0.0.0.19", "0.0.0.19"},
				{"0.0.0.21", "0.0.0.25"},
				{"0.0.0.27", "0.0.0.35"},		
				{"0.0.0.37", "0.0.0.42"},
				{"0.0.0.45", "0.0.0.49"},
			}, // multi 1 remove multi 2
			new String[][] {
				{"0.0.0.56", "0.0.0.75"},
				{"0.0.0.80", "0.0.0.255"},
			} // multi 2 remove multi 1
		));
	
		boolean isNoAutoSubnets = prefixConfiguration.prefixedSubnetsAreExplicit();
		boolean allPrefixesAreSubnets = prefixConfiguration.allPrefixedAddressesAreSubnets();

		String address0 = isNoAutoSubnets ? "0.0.0.0-7/29" : "0.0.0.0/29"; //0.0.0.0 to 0.0.0.7
		
		String range11addr0Intersection[][] = {
			{"0.0.0.1", "0.0.0.7"}
		};
		String range11addr0union[][] = {
			{"0.0.0.0", "0.0.0.8"},
			{"0.0.0.13", "0.0.0.20"},
			{"0.0.0.27", "0.0.0.35"},		
			{"0.0.0.37", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.55"},
		};
		String range11addr0Remove[][] = {
			{"0.0.0.8", "0.0.0.8"},
			{"0.0.0.13", "0.0.0.20"},
			{"0.0.0.27", "0.0.0.35"},		
			{"0.0.0.37", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.55"},
		};
		String range11addr0ReverseRemove[][] = {
			{"0.0.0.0", "0.0.0.0"},
		};

		test(initIPv4SingleAddress(
			range11, address0, 
			range11addr0Intersection, 
			range11addr0union,
			range11addr0Remove,
			range11addr0ReverseRemove));
		
	
		String address1 = isNoAutoSubnets ? "0.0.0.8-15/29" : "0.0.0.8/29"; //0.0.0.8 to 0.0.0.15
		
		String range11addr1Intersection[][] = {
			{"0.0.0.8", "0.0.0.8"},
			{"0.0.0.13", "0.0.0.15"}
		};
		String range11addr1union[][] = {
			{"0.0.0.1", "0.0.0.20"},
			{"0.0.0.27", "0.0.0.35"},		
			{"0.0.0.37", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.55"},
		};
		String range11addr1Remove[][] = {
			{"0.0.0.1", "0.0.0.7"},
			{"0.0.0.16", "0.0.0.20"},
			{"0.0.0.27", "0.0.0.35"},		
			{"0.0.0.37", "0.0.0.42"},
			{"0.0.0.45", "0.0.0.55"},
		};
		String range11addr1ReverseRemove[][] = {
			{"0.0.0.9", "0.0.0.12"},
		};

		test(initIPv4SingleAddress(
			range11, address1, 
			range11addr1Intersection, 
			range11addr1union,
			range11addr1Remove,
			range11addr1ReverseRemove));
		
		
		String address2 = "30-34.2.3-5.4";
		
		test(initIPv4SingleAddress(
				new String[][] {
					{"31.2.2.3", "31.2.3.3"},
					{"33.2.5.4", "34.0.0.0"},
				}, //range
				address2,
				new String[][] {
					{"33.2.5.4", "33.2.5.4"},
				}, // intersection
				new String[][] {
					{"30.2.3.4", "30.2.3.4"},
					{"30.2.4.4", "30.2.4.4"},
					{"30.2.5.4", "30.2.5.4"},
					
					{"31.2.2.3", "31.2.3.4"},
					{"31.2.4.4", "31.2.4.4"},
					{"31.2.5.4", "31.2.5.4"},

					{"32.2.3.4", "32.2.3.4"},
					{"32.2.4.4", "32.2.4.4"},
					{"32.2.5.4", "32.2.5.4"},
					
					{"33.2.3.4", "33.2.3.4"},
					{"33.2.4.4", "33.2.4.4"},
					{"33.2.5.4", "34.0.0.0"},
					
					{"34.2.3.4", "34.2.3.4"},
					{"34.2.4.4", "34.2.4.4"},
					{"34.2.5.4", "34.2.5.4"},
				}, //union
				new String[][] {
					{"31.2.2.3", "31.2.3.3"},
					{"33.2.5.5", "34.0.0.0"},
				}, // remove
				new String[][] {
					{"30.2.3.4", "30.2.3.4"},
					{"30.2.4.4", "30.2.4.4"},
					{"30.2.5.4", "30.2.5.4"},
					
					{"31.2.3.4", "31.2.3.4"},
					{"31.2.4.4", "31.2.4.4"},
					{"31.2.5.4", "31.2.5.4"},

					{"32.2.3.4", "32.2.3.4"},
					{"32.2.4.4", "32.2.4.4"},
					{"32.2.5.4", "32.2.5.4"},
					
					{"33.2.3.4", "33.2.3.4"},
					{"33.2.4.4", "33.2.4.4"},
					
					{"34.2.3.4", "34.2.3.4"},
					{"34.2.4.4", "34.2.4.4"},
					{"34.2.5.4", "34.2.5.4"},
				} // reverse remove
		));
		
		test(initIPv4SingleAddress(
				new String[][] {
					{"31.2.2.3", "31.2.3.3"},
					{"33.2.5.5", "34.0.0.0"},
				}, //range
				address2,
				new String[][] {
				}, // intersection
				new String[][] {
					{"30.2.3.4", "30.2.3.4"},
					{"30.2.4.4", "30.2.4.4"},
					{"30.2.5.4", "30.2.5.4"},
					
					{"31.2.2.3", "31.2.3.4"},
					{"31.2.4.4", "31.2.4.4"},
					{"31.2.5.4", "31.2.5.4"},

					{"32.2.3.4", "32.2.3.4"},
					{"32.2.4.4", "32.2.4.4"},
					{"32.2.5.4", "32.2.5.4"},
					
					{"33.2.3.4", "33.2.3.4"},
					{"33.2.4.4", "33.2.4.4"},
					{"33.2.5.4", "34.0.0.0"},
					
					{"34.2.3.4", "34.2.3.4"},
					{"34.2.4.4", "34.2.4.4"},
					{"34.2.5.4", "34.2.5.4"},
				}, //union
				new String[][] {
					{"31.2.2.3", "31.2.3.3"},
					{"33.2.5.5", "34.0.0.0"},
				}, // remove
				new String[][] {
					{"30.2.3.4", "30.2.3.4"},
					{"30.2.4.4", "30.2.4.4"},
					{"30.2.5.4", "30.2.5.4"},
					
					{"31.2.3.4", "31.2.3.4"},
					{"31.2.4.4", "31.2.4.4"},
					{"31.2.5.4", "31.2.5.4"},

					{"32.2.3.4", "32.2.3.4"},
					{"32.2.4.4", "32.2.4.4"},
					{"32.2.5.4", "32.2.5.4"},
					
					{"33.2.3.4", "33.2.3.4"},
					{"33.2.4.4", "33.2.4.4"},
					{"33.2.5.4", "33.2.5.4"},
					
					{"34.2.3.4", "34.2.3.4"},
					{"34.2.4.4", "34.2.4.4"},
					{"34.2.5.4", "34.2.5.4"},
				} // reverse remove
		));
		
		String address3 = allPrefixesAreSubnets ? "255.3-5.2.0/24" : "255.3-5.2.*/16";
		
		test(initIPv4SingleAddress(
				new String[][] {
					{"255.3.1.0", "255.3.1.255"},
					{"255.5.3.0", "255.6.3.0"},
				}, //range
				address3,
				new String[][] {
				}, // intersection
				new String[][] {
					{"255.3.1.0", "255.3.2.255"},
					{"255.4.2.0", "255.4.2.255"},
					{"255.5.2.0", "255.6.3.0"},
				}, //union
				new String[][] {
					{"255.3.1.0", "255.3.1.255"},
					{"255.5.3.0", "255.6.3.0"},
				}, // remove
				new String[][] {
					{"255.3.2.0", "255.3.2.255"},
					{"255.4.2.0", "255.4.2.255"},
					{"255.5.2.0", "255.5.2.255"},
				} // reverse remove
		));
		
		String address4 = "200.248-255.200.25-45";
		test(initIPv4SingleAddress(
				new String[][] {
					{"200.250.200.0", "200.250.200.10"},
					{"200.250.200.20", "200.250.200.30"},
					{"200.250.200.40", "200.252.200.10"},
					{"200.252.200.20", "200.252.200.30"},
					{"200.252.200.40", "200.252.200.50"},
				}, //range
				address4,
				new String[][] {
					{"200.250.200.25", "200.250.200.30"},
					{"200.250.200.40", "200.250.200.45"},
					{"200.251.200.25", "200.251.200.45"},
					{"200.252.200.25", "200.252.200.30"},
					{"200.252.200.40", "200.252.200.45"},
				}, // intersection
				new String[][] {
					{"200.248.200.25", "200.248.200.45"},
					{"200.249.200.25", "200.249.200.45"},
					{"200.250.200.0", "200.250.200.10"},
					{"200.250.200.20", "200.252.200.10"},
					{"200.252.200.20", "200.252.200.50"},
					{"200.252.200.25", "200.252.200.45"},
					{"200.253.200.25", "200.253.200.45"},
					{"200.254.200.25", "200.254.200.45"},
					{"200.255.200.25", "200.255.200.45"},
				}, //union
				new String[][] {
					{"200.250.200.0", "200.250.200.10"},
					{"200.250.200.20", "200.250.200.24"},
					{"200.250.200.46", "200.251.200.24"},
					{"200.250.200.46", "200.251.200.10"},
					{"200.251.200.20", "200.251.200.24"},
					{"200.251.200.46", "200.252.200.10"},
					{"200.252.200.20", "200.252.200.24"},
					{"200.252.200.46", "200.252.200.50"},
				}, // remove
				new String[][] {
					{"200.248.200.25", "200.248.200.45"},
					{"200.249.200.25", "200.249.200.45"},
					{"200.250.200.31", "200.250.200.39"},
					{"200.252.200.31", "200.252.200.39"},
					{"200.253.200.25", "200.253.200.45"},
					{"200.254.200.25", "200.254.200.45"},
					{"200.255.200.25", "200.255.200.45"},
				} // reverse remove
		));
		
		
		
		
		IPAddressSeqRangeList list1 = new IPAddressSeqRangeList();
		IPAddressSeqRangeList list2 = new IPAddressSeqRangeList();
		IPAddressSeqRangeList union = new IPAddressSeqRangeList();
		IPAddress last = new IPAddressString("1.2.3.4").getAddress();
		for(int i = 0; i < 200; i++) {
			IPAddress first = last.increment(100);
			if(i % 2 == 0) {
				last = first.increment(20);
			} else {
				last = first.increment(21);
			}
			IPAddressSeqRange rng = first.spanWithRange(last);
			list1.add(rng);
			union.add(rng);
			if(i % 2 == 0) {
				first = last.increment(11);
			} else {
				first = last.increment(10);
			}
			last = first.increment(11);
			rng = first.spanWithRange(last);
			list2.add(rng);
			union.add(rng);
		}
		
		test(initIPv4ListTests(
				list1, // range1
				list2, // range2
				new IPAddressSeqRangeList(), // intersection
				union, // union
				list1, // range1 remove range2
				list2 // range2 remove range1
		));
		
		
		list1.clear();
		list2.clear();
		union.clear();
		IPAddressSeqRangeList intersection = new IPAddressSeqRangeList();
		IPAddressSeqRangeList range1Remove2 = new IPAddressSeqRangeList();
		IPAddressSeqRangeList range2Remove1 = new IPAddressSeqRangeList();
		last = new IPAddressString("1.2.3.4").getAddress();
		for(int i = 0; i < 200; i++) {
			IPAddress first = last.increment(100);
			if(i % 2 == 0) {
				last = first.increment(20);
			} else {
				last = first.increment(21);
			}
			IPAddressSeqRange rng = first.spanWithRange(last);
			list1.add(rng);
			
			IPAddress otherFirst, otherLast;
			if(i % 2 == 1) {
				otherFirst = first.increment(10);
			} else {
				otherFirst = first.increment(11);
			}
			if(i % 2 == 0) {
				otherLast = otherFirst.increment(20);
			} else {
				otherLast = otherFirst.increment(21);
			}
			list2.add(otherFirst.spanWithRange(otherLast));
			union.add(first.spanWithRange(otherLast));
			intersection.add(otherFirst.spanWithRange(last));
			range1Remove2.add(first.spanWithRange(otherFirst.decrement()));
			range2Remove1.add(last.increment().spanWithRange(otherLast));
		}
		
		test(initIPv4ListTests(
				list1, // range1
				list2, // range2
				intersection, // intersection
				union, // union
				range1Remove2, // range1 remove range2
				range2Remove1 // range2 remove range1
		));
		
		
		list1.clear();
		list2.clear();
		union.clear();
		intersection = new IPAddressSeqRangeList();
		range1Remove2 = new IPAddressSeqRangeList();
		range2Remove1 = new IPAddressSeqRangeList();

		last = new IPAddressString("2.2.3.4").getAddress();
		for(int i = 0; i < 200; i++) {
			IPAddress first = last.increment(100);
			if(i % 2 == 0) {
				last = first.increment(20);
			} else {
				last = first.increment(21);
			}
			IPAddressSeqRange rng = first.spanWithRange(last);
			list1.add(rng);
			
			IPAddress otherFirst, otherLast;
			if(i % 2 == 1) {
				otherFirst = last.increment();
			} else {
				otherFirst = last.increment(2);
			}
			if(i % 2 == 0) {
				otherLast = otherFirst.increment(20);
			} else {
				otherLast = otherFirst.increment(21);
			}
			list2.add(otherFirst.spanWithRange(otherLast));
			
			if(i % 2 == 1) {
				union.add(first.spanWithRange(otherLast));
			} else {
				union.add(first.spanWithRange(last));
				union.add(otherFirst.spanWithRange(otherLast));
			}
		}
		
		test(initIPv4ListTests(
				list1, // range1
				list2, // range2
				new IPAddressSeqRangeList(), // intersection
				union, // union
				list1, // range1 remove range2
				list2 // range2 remove range1
		));
		
		list1.clear();
		list2.clear();
		union.clear();
		
		last = new IPAddressString("100.2.3.4").getAddress();
		for(int i = 0; i < 200; i++) {
			IPAddress first = last.increment(100);
			last = first.increment(19);
			IPAddressSeqRange rng = first.spanWithRange(last);
			list1.add(rng);
			
			IPAddress otherFirst;
			if(i % 2 == 0) {
				otherFirst = first;
			} else {
				range1Remove2.add(first.coverWithSequentialRange());
				otherFirst = first.increment();
			}
			for(int j = 0; j < 10; j++) {
				list2.add(otherFirst.coverWithSequentialRange());
				if(i % 2 == 0 || j < 9) {
					otherFirst = otherFirst.increment();
					range1Remove2.add(otherFirst.coverWithSequentialRange());
					otherFirst = otherFirst.increment();
				}
			}
		}
		
		test(initIPv4ListTests(
				list1, // range1
				list2, // range2
				list2, // intersection
				list1, // union
				range1Remove2, // range1 remove range2
				new IPAddressSeqRangeList() // range2 remove range1
		));
		
		list1.clear();
		list2.clear();
		range1Remove2.clear();
		last = new IPAddressString("2.255.3.4").getAddress();
		for(int i = 0; i < 201; i++) {
			IPAddress first = last.increment(99);
			if(i % 2 == 0) {
				last = first.increment(7);
			} else {
				last = first.increment(9);
			}
			IPAddressSeqRange rng = first.spanWithRange(last);
			list1.add(rng);

			if(i == 198) {
				IPAddress otherFirst = first.increment();
				IPAddress otherLast = last.decrement();
				IPAddressSeqRange rng2 = otherFirst.spanWithRange(otherLast);
				list2.add(rng2);
				intersection.add(rng2);
				range1Remove2.add(first.coverWithSequentialRange());
				range1Remove2.add(last.coverWithSequentialRange());
			} else {
				range1Remove2.add(rng);
			}
		}
		test(initIPv4ListTests(
				list1, // range1
				list2, // range2
				intersection, // intersection
				list1, // union
				range1Remove2, // range1 remove range2
				new IPAddressSeqRangeList() // range2 remove range1
		));
		

		list1.clear();
		list2.clear();
		range1Remove2.clear();
		intersection.clear();
		last = new IPAddressString("2.255.3.4").getAddress();
		for(int i = 0; i < 201; i++) {
			IPAddress first = last.increment(99);
			if(i % 2 == 0) {
				last = first.increment(7);
			} else {
				last = first.increment(9);
			}
			IPAddressSeqRange rng = first.spanWithRange(last);
			list1.add(rng);

			if(i == 197) {
				IPAddress otherFirst = last;
				IPAddress otherLast = last;
				IPAddressSeqRange rng2 = otherFirst.spanWithRange(otherLast);
				list2.add(rng2);
				intersection.add(rng2);
				range1Remove2.add(first.spanWithRange(otherLast.decrement()));
			} else {
				range1Remove2.add(rng);
			}
		}
		test(initIPv4ListTests(
				list1, // range1
				list2, // range2
				intersection, // intersection
				list1, // union
				range1Remove2, // range1 remove range2
				new IPAddressSeqRangeList() // range2 remove range1
		));
		
		testRangeListIncrement();

		if(printResults) {
			System.out.println();
			System.out.println("IPAddressSeqRangeList multi list tests: " + multiListTestCount);
			System.out.println("IPAddressSeqRangeList single list tests: " + singleListTestCount);
			System.out.println("IPAddressSeqRangeList address tests: " + addressTestCount);
			System.out.println("IPAddressSeqRangeList tests: " + rangeListTestCount);
			System.out.println("IPAddressSeqRangeList failures: " + rangeListFailCount);
			System.out.println();
		}
		
		incrementTestCount(rangeListTestCount);
	}
	
	TestResult[] initIPv4Lists(
			String[][] range1Strs, String[][] range2Strs, 
			String[][] intersectionStrs, 
			String[][] unionStrs,
			String[][] range1RemoveRange2Strs,
			String[][] range2RemoveRange1Strs) {
		IPAddressSeqRangeList range1 = create(range1Strs);
		IPAddressSeqRangeList range2 = create(range2Strs);
		IPAddressSeqRangeList expectedIntersection = create(intersectionStrs);
		IPAddressSeqRangeList expectedUnion = create(unionStrs);
		IPAddressSeqRangeList range1RemoveRange2 = create(range1RemoveRange2Strs);
		IPAddressSeqRangeList range2RemoveRange1 = create(range2RemoveRange1Strs);
		return initIPv4ListTests(range1, range2, expectedIntersection, expectedUnion, range1RemoveRange2, range2RemoveRange1);
	}

	static IPAddressContainmentTrie createContainmentTrie(IPAddressSeqRangeList list) {
		IPAddressContainmentTrie trie = new IPAddressContainmentTrie();
		for(int i = 0; i < list.getSeqRangeCount(); i++) {
			trie.add(list.getSeqRange(i));
		}
		return trie;
	}
	
	static IPAddressContainmentTrie createContainmentTrie(IPAddressSeqRange rng) {
		IPAddressContainmentTrie trie = new IPAddressContainmentTrie();
		trie.add(rng);
		return trie;
	}
	
	static IPAddressContainmentTrie createContainmentTrie(IPAddress addr) {
		IPAddressContainmentTrie trie = new IPAddressContainmentTrie();
		trie.add(addr);
		return trie;
	}

	TestResult[] initIPv4ListTests(
			IPAddressSeqRangeList range1, 
			IPAddressSeqRangeList range2, 
			IPAddressSeqRangeList expectedIntersection, 
			IPAddressSeqRangeList expectedUnion, 
			IPAddressSeqRangeList range1RemoveRange2, 
			IPAddressSeqRangeList range2RemoveRange1) {
		
		boolean isIPv6 = false;

		ArrayList<TestResult> tests = new ArrayList<>();
		
		IPAddressContainmentTrie range1Trie = null, range2Trie = null;
		if(range1.getSeqRangeCount() == 1) {
			range2Trie = createContainmentTrie(range2);
		}
		if(range2.getSeqRangeCount() == 1) {
			range1Trie = createContainmentTrie(range1);
		}
		
		tests.add(new RangeResult(isIPv6, range1, range2, expectedIntersection, expectedUnion, range1RemoveRange2, range2RemoveRange1));
		if(range1.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range1.getLowerSeqRange();
			IPAddressContainmentTrie rngTrie = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range2, rng, range2Trie, rngTrie, expectedIntersection, expectedUnion, range2RemoveRange1));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {
				tests.add(new AddressResult(isIPv6, range2, blocks[0], range2Trie, rngTrie, expectedIntersection, expectedUnion, range2RemoveRange1));
			}
		}
		if(range2.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range2.getLowerSeqRange();
			IPAddressContainmentTrie rngTrie = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range1, rng, range1Trie, rngTrie, expectedIntersection, expectedUnion, range1RemoveRange2));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {// [0.0.0-254.*, 0.0.255.0]
				tests.add(new AddressResult(isIPv6, range1, blocks[0], range1Trie, rngTrie, expectedIntersection, expectedUnion, range1RemoveRange2));
			}
		}

		// the following tests use the more specific types for IPv4/6
		range1 = convertToSpecific(range1);
		range2 = convertToSpecific(range2);
		expectedIntersection = convertToSpecific(expectedIntersection);
		expectedUnion = convertToSpecific(expectedUnion);
		range1RemoveRange2 = convertToSpecific(range1RemoveRange2);
		range2RemoveRange1 = convertToSpecific(range2RemoveRange1);
		tests.add(new RangeResult(isIPv6, range1, range2, expectedIntersection, expectedUnion, range1RemoveRange2, range2RemoveRange1));
		
		if(range1.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range1.getLowerSeqRange();
			IPAddressContainmentTrie rngTrie = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range2, rng, range2Trie, rngTrie, expectedIntersection, expectedUnion, range2RemoveRange1));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {
				tests.add(new AddressResult(isIPv6, range2, blocks[0], range2Trie, rngTrie, expectedIntersection, expectedUnion, range2RemoveRange1));
			}
		}
		if(range2.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range2.getLowerSeqRange();
			IPAddressContainmentTrie rngTrie = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range1, rng, range1Trie, rngTrie, expectedIntersection, expectedUnion, range1RemoveRange2));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {// [0.0.0-254.*, 0.0.255.0]
				tests.add(new AddressResult(isIPv6, range1, blocks[0], range1Trie, rngTrie, expectedIntersection, expectedUnion, range1RemoveRange2));
			}
		}
		
		isIPv6 = true;
		
		IPAddressSeqRangeList range1IPv6 = convert(range1);
		IPAddressSeqRangeList range2IPv6 = convert(range2);
		IPAddressSeqRangeList expectedIntersectionIPv6 = convert(expectedIntersection);
		IPAddressSeqRangeList expectedUnionIPv6 = convert(expectedUnion);
		IPAddressSeqRangeList range1RemoveRange2IPv6 = convert(range1RemoveRange2);
		IPAddressSeqRangeList range2RemoveRange1IPv6 = convert(range2RemoveRange1);
		tests.add(new RangeResult(isIPv6, range1IPv6, range2IPv6, expectedIntersectionIPv6, expectedUnionIPv6, range1RemoveRange2IPv6, range2RemoveRange1IPv6));
		
		IPAddressContainmentTrie range1TrieIPv6 = null, range2TrieIPv6 = null;
		if(range1IPv6.getSeqRangeCount() == 1) {
			range2TrieIPv6 = createContainmentTrie(range2IPv6); 
		}
		if(range2IPv6.getSeqRangeCount() == 1) {
			range1TrieIPv6 = createContainmentTrie(range1IPv6);
		}
		if(range1IPv6.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range1IPv6.getLowerSeqRange();
			IPAddressContainmentTrie rngTrieIPv6 = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range2IPv6, rng, range2TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range2RemoveRange1IPv6));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {
				tests.add(new AddressResult(isIPv6, range2IPv6, blocks[0], range2TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range2RemoveRange1IPv6));
			}
		}
		if(range2IPv6.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range2IPv6.getLowerSeqRange();
			IPAddressContainmentTrie rngTrieIPv6 = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range1IPv6, rng, range1TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range1RemoveRange2IPv6));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {
				tests.add(new AddressResult(isIPv6, range1IPv6, blocks[0], range1TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range1RemoveRange2IPv6));
			}
		}
			
		range1IPv6 = convertToSpecific(range1IPv6);
		range2IPv6 = convertToSpecific(range2IPv6);
		expectedIntersectionIPv6 = convertToSpecific(expectedIntersectionIPv6);
		expectedUnionIPv6 = convertToSpecific(expectedUnionIPv6);
		range1RemoveRange2IPv6 = convertToSpecific(range1RemoveRange2IPv6);
		range2RemoveRange1IPv6 = convertToSpecific(range2RemoveRange1IPv6);
		tests.add(new RangeResult(isIPv6, range1IPv6, range2IPv6, expectedIntersectionIPv6, expectedUnionIPv6, range1RemoveRange2IPv6, range2RemoveRange1IPv6));

		if(range1IPv6.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range1IPv6.getLowerSeqRange();
			IPAddressContainmentTrie rngTrieIPv6 = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range2IPv6, rng, range2TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range2RemoveRange1IPv6));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {
				tests.add(new AddressResult(isIPv6, range2IPv6, blocks[0], range2TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range2RemoveRange1IPv6));
			}
		}
		if(range2IPv6.getSeqRangeCount() == 1) {
			IPAddressSeqRange rng = range2IPv6.getLowerSeqRange();
			IPAddressContainmentTrie rngTrieIPv6 = createContainmentTrie(rng);
			tests.add(new SingleRangeResult(isIPv6, range1IPv6, rng, range1TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range1RemoveRange2IPv6));
			IPAddress[] blocks = rng.spanWithSequentialBlocks();
			if(blocks.length == 1) {
				tests.add(new AddressResult(isIPv6, range1IPv6, blocks[0], range1TrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, range1RemoveRange2IPv6));
			}
		}

		return tests.toArray(new TestResult[tests.size()]);
	}
	
	TestResult[] initIPv4SingleList(
			String[][] rangeStrs, String[] rangeStr, 
			String[][] intersectionStrs, 
			String[][] unionStrs,
			String[][] removeStrs,
			String[][] reverseRemoveStrs) {
		
		ArrayList<TestResult> tests = new ArrayList<>();
		IPAddressSeqRangeList list = create(rangeStrs);
		IPv4AddressSeqRange rng = createRange(rangeStr).toIPv4();
		IPAddressSeqRangeList expectedIntersection = create(intersectionStrs);
		IPAddressSeqRangeList expectedUnion = create(unionStrs);
		IPAddressSeqRangeList expectedRemove = create(removeStrs);
		IPAddressSeqRangeList expectedReverseRemove = create(reverseRemoveStrs);
		
		IPAddressContainmentTrie listTrie = createContainmentTrie(list);
		
		boolean isIPv6 = false;
		IPAddressContainmentTrie rngTrie = createContainmentTrie(rng);
		tests.add(new SingleRangeResult(isIPv6, list, rng, listTrie, rngTrie, expectedIntersection, expectedUnion, expectedRemove));
		tests.add(new RangeResult(isIPv6, list, inList(rng), expectedIntersection, expectedUnion, expectedRemove, expectedReverseRemove));
		IPAddress[] blocks = rng.spanWithSequentialBlocks();
		if(blocks.length == 1) {
			tests.add(new AddressResult(isIPv6, list, blocks[0], listTrie, rngTrie, expectedIntersection, expectedUnion, expectedRemove));
		}
		
		// convert to the more specific range list type IPv4SequentialRangeList
		
		list = convertToSpecific(list);
		expectedIntersection = convertToSpecific(expectedIntersection);
		expectedUnion = convertToSpecific(expectedUnion);
		expectedRemove = convertToSpecific(expectedRemove);
		expectedReverseRemove = convertToSpecific(expectedReverseRemove);
		tests.add(new SingleRangeResult(isIPv6, list, rng, listTrie, rngTrie, expectedIntersection, expectedUnion, expectedRemove));
		tests.add(new RangeResult(isIPv6, list, inList(rng), expectedIntersection, expectedUnion, expectedRemove, expectedReverseRemove));
		if(blocks.length == 1) {
			tests.add(new AddressResult(isIPv6, list, blocks[0], listTrie, rngTrie, expectedIntersection, expectedUnion, expectedRemove));
		}

		// IPv6 (IPv4-mapped)
		
		isIPv6 = true;
		
		IPAddressSeqRangeList listIPv6 = convert(list);
		IPAddressSeqRange rngIPv6 = convertRange(rng);
		IPAddressSeqRangeList expectedIntersectionIPv6 = convert(expectedIntersection);
		IPAddressSeqRangeList expectedUnionIPv6 = convert(expectedUnion);
		IPAddressSeqRangeList expectedRemoveIPv6 = convert(expectedRemove);
		IPAddressSeqRangeList expectedReverseRemoveIPv6 = convert(expectedReverseRemove);
		
		IPAddressContainmentTrie listTrieIPv6 = createContainmentTrie(listIPv6);
		IPAddressContainmentTrie rngTrieIPv6 = createContainmentTrie(rngIPv6);
		
		tests.add(new SingleRangeResult(isIPv6, listIPv6, rngIPv6, listTrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
		tests.add(new RangeResult(isIPv6, listIPv6, inList(rngIPv6), expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6, expectedReverseRemoveIPv6));
		blocks = rngIPv6.spanWithSequentialBlocks();
		if(blocks.length == 1) {
			tests.add(new AddressResult(isIPv6, listIPv6, blocks[0], listTrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
		}
		
		// convert to the more specific range list type IPv6SequentialRangeList
		
		listIPv6 = convertToSpecific(listIPv6);
		expectedIntersectionIPv6 = convertToSpecific(expectedIntersectionIPv6);
		expectedUnionIPv6 = convertToSpecific(expectedUnionIPv6);
		expectedRemoveIPv6 = convertToSpecific(expectedRemoveIPv6);
		expectedReverseRemoveIPv6 = convertToSpecific(expectedReverseRemoveIPv6);

		tests.add(new SingleRangeResult(isIPv6, listIPv6, rngIPv6, listTrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
		tests.add(new RangeResult(isIPv6, listIPv6, inList(rngIPv6), expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6, expectedReverseRemoveIPv6));
		blocks = rngIPv6.spanWithSequentialBlocks();
		if(blocks.length == 1) {
			tests.add(new AddressResult(isIPv6, listIPv6, blocks[0], listTrieIPv6, rngTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
		}
		
		return tests.toArray(new TestResult[tests.size()]);
	}
	
	TestResult[] initIPv4SingleAddress(
			String[][] rangeStrs, String addressStr, 
			String[][] intersectionStrs, 
			String[][] unionStrs,
			String[][] removeStrs,
			String[][] reverseRemoveStrs) {
		
		boolean isIPv6 = false;
		
		ArrayList<TestResult> tests = new ArrayList<>();
		IPAddressSeqRangeList list = create(rangeStrs);
		IPv4Address addr = createAddr(addressStr).toIPv4();
		IPAddressSeqRangeList expectedIntersection = create(intersectionStrs);
		IPAddressSeqRangeList expectedUnion = create(unionStrs);
		IPAddressSeqRangeList expectedRemove = create(removeStrs);
		IPAddressSeqRangeList expectedReverseRemove = create(reverseRemoveStrs);
		
		IPAddressContainmentTrie listTrie = createContainmentTrie(list);
		
		IPAddressContainmentTrie addrTrie = createContainmentTrie(addr);
		tests.add(new AddressResult(isIPv6, list, addr, listTrie, addrTrie, expectedIntersection, expectedUnion, expectedRemove));
		if(addr.isSequential()) {
			tests.add(new SingleRangeResult(isIPv6, list, addr.coverWithSequentialRange(), listTrie, addrTrie, expectedIntersection, expectedUnion, expectedRemove));
			tests.add(new RangeResult(isIPv6, list, inList(addr.coverWithSequentialRange()), expectedIntersection, expectedUnion, expectedRemove, expectedReverseRemove));
		} else {
			tests.add(new RangeResult(isIPv6, list, inList(addr), expectedIntersection, expectedUnion, expectedRemove, expectedReverseRemove));
		}

		list = convertToSpecific(list);
		expectedIntersection = convertToSpecific(expectedIntersection);
		expectedUnion = convertToSpecific(expectedUnion);
		expectedRemove = convertToSpecific(expectedRemove);
		expectedReverseRemove = convertToSpecific(expectedReverseRemove);

		tests.add(new AddressResult(isIPv6, list, addr, listTrie, addrTrie, expectedIntersection, expectedUnion, expectedRemove));
		if(addr.isSequential()) {
			tests.add(new SingleRangeResult(isIPv6, list, addr.coverWithSequentialRange(), listTrie, addrTrie, expectedIntersection, expectedUnion, expectedRemove));
			tests.add(new RangeResult(isIPv6, list, inList(addr.coverWithSequentialRange()), expectedIntersection, expectedUnion, expectedRemove, expectedReverseRemove));
		} else {
			tests.add(new RangeResult(isIPv6, list, inList(addr), expectedIntersection, expectedUnion, expectedRemove, expectedReverseRemove));
		}

		isIPv6 = true;
		try {
			IPAddressSeqRangeList listIPv6 = convert(list);
			IPAddress addrIPv6 = convertAddress(addr);
			IPAddressSeqRangeList expectedIntersectionIPv6 = convert(expectedIntersection);
			IPAddressSeqRangeList expectedUnionIPv6 = convert(expectedUnion);
			IPAddressSeqRangeList expectedRemoveIPv6 = convert(expectedRemove);
			IPAddressSeqRangeList expectedReverseRemoveIPv6 = convert(expectedReverseRemove);
			
			IPAddressContainmentTrie listTrieIPv6 = createContainmentTrie(listIPv6);
			
			IPAddressContainmentTrie addrTrieIPv6 = createContainmentTrie(addrIPv6);
			
			tests.add(new AddressResult(isIPv6, listIPv6, addrIPv6, listTrieIPv6, addrTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
			if(addrIPv6.isSequential()) {
				tests.add(new SingleRangeResult(isIPv6, listIPv6, addrIPv6.coverWithSequentialRange(), listTrieIPv6, addrTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
				tests.add(new RangeResult(isIPv6, listIPv6, inList(addrIPv6.coverWithSequentialRange()), expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6, expectedReverseRemoveIPv6));
			} else {
				tests.add(new RangeResult(isIPv6, listIPv6, inList(addrIPv6), expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6, expectedReverseRemoveIPv6));
			}

			listIPv6 = convertToSpecific(listIPv6);
			expectedIntersectionIPv6 = convertToSpecific(expectedIntersectionIPv6);
			expectedUnionIPv6 = convertToSpecific(expectedUnionIPv6);
			expectedRemoveIPv6 = convertToSpecific(expectedRemoveIPv6);
			expectedReverseRemoveIPv6 = convertToSpecific(expectedReverseRemoveIPv6);

			tests.add(new AddressResult(isIPv6, listIPv6, addrIPv6, listTrieIPv6, addrTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
			if(addrIPv6.isSequential()) {
				tests.add(new SingleRangeResult(isIPv6, listIPv6, addrIPv6.coverWithSequentialRange(), listTrieIPv6, addrTrieIPv6, expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6));
				tests.add(new RangeResult(isIPv6, listIPv6, inList(addrIPv6.coverWithSequentialRange()), expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6, expectedReverseRemoveIPv6));
			} else {
				tests.add(new RangeResult(isIPv6, listIPv6, inList(addrIPv6), expectedIntersectionIPv6, expectedUnionIPv6, expectedRemoveIPv6, expectedReverseRemoveIPv6));
			}
		} catch(IncompatibleAddressException e) {
			// this can happen with non-sequential IPv4 addresses
		}
		return tests.toArray(new TestResult[tests.size()]);
	}

	static IPAddressSeqRangeList convertToSpecific(IPAddressSeqRangeList list) {
		if(!list.isEmpty()) {
			IPAddressSeqRangeList newList = list.getLower().isIPv4() ? new IPv4AddressSeqRangeList() : new IPv6AddressSeqRangeList();
			for(IPAddressSeqRange rng : list.getSeqRangeIterable()) {
				newList.add(rng);
			}
			return newList;
		}
		return list;
	}
	
	static IPAddressSeqRangeList convert(IPAddressSeqRangeList ipv4List) {
		IPAddressSeqRangeList ipv6List = new IPAddressSeqRangeList();
		for(IPAddressSeqRange rng : ipv4List.getSeqRangeIterable()) {
			IPv6AddressSeqRange converted = convertRange(rng.toIPv4());
			ipv6List.add(converted);
		}
		return ipv6List;
	}
	
	static IPv6AddressSeqRange convertRange(IPv4AddressSeqRange ipv4Range) {
		return convertAddress(ipv4Range.getLower()).spanWithRange(convertAddress(ipv4Range.getUpper()));
	}
	
	static IPv6Address convertAddress(IPv4Address addr) {
		return addr.getIPv4MappedAddress();
	}
}
