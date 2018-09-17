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

package inet.ipaddr.format.standard;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.BiFunction;
import java.util.function.IntFunction;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;

import inet.ipaddr.Address;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressSegmentSeries;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.NetworkMismatchException;
import inet.ipaddr.format.AddressDivisionBase;
import inet.ipaddr.format.AddressDivisionGroupingBase;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.string.AddressStringDivision;
import inet.ipaddr.format.string.AddressStringDivisionSeries;
import inet.ipaddr.format.util.AddressDivisionWriter;
import inet.ipaddr.format.util.AddressSegmentParams;
import inet.ipaddr.format.validate.ParsedAddressGrouping;

/**
 * AddressDivisionGrouping objects consist of a series of AddressDivision objects, each division containing one or more segments.
 * <p>
 * AddressDivisionGrouping objects are immutable.  This also makes them thread-safe.
 * <p>
 * AddressDivision objects use long to represent their values, so this places a cap on the size of the divisions in AddressDivisionGrouping.
 * <p>
 *  @author sfoley
 */
public class AddressDivisionGrouping extends AddressDivisionGroupingBase /*implements AddressDivisionSeries , Comparable<AddressDivisionGrouping>*/ {

	private static final long serialVersionUID = 4L;
	
	private static BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);
	
	/* caches objects to avoid recomputing them */
	protected static class SectionCache<R extends AddressSegmentSeries> {
		public R lower;
		public R lowerNonZeroHost;
		public R upper;
		
		public boolean lowerNonZeroHostIsNull;
		
		public SectionCache() {}
	}
	
	/* the various string representations - these fields are for caching */
	protected static class StringCache {
		public String canonicalString;
		public String hexString;
		public String hexStringPrefixed;
	}

	public AddressDivisionGrouping(AddressDivision divisions[]) {
		super(divisions);
	}
	
	public AddressDivisionGrouping(AddressDivision divisions[], boolean checkDivisions) {
		super(divisions, checkDivisions);
	}
	
	@Override
	public AddressDivision getDivision(int index) {
		return (AddressDivision) super.getDivision(index);
	}

	@Override
	protected byte[] getBytesImpl(boolean low) {
		byte bytes[] = new byte[(getBitCount() + 7) >> 3];
		int byteCount = bytes.length;
		int divCount = getDivisionCount();
		for(int k = divCount - 1, byteIndex = byteCount - 1, bitIndex = 8; k >= 0; k--) {
			AddressDivision div = getDivision(k);
			long segmentValue = low ? div.getDivisionValue() : div.getUpperDivisionValue();
			int divBits = div.getBitCount();
			//write out this entire segment
			while(divBits > 0) {
				bytes[byteIndex] |= segmentValue << (8 - bitIndex);
				segmentValue >>>= bitIndex;
				if(divBits < bitIndex) {
					bitIndex -= divBits;
					break;
				} else {
					divBits -= bitIndex;
					bitIndex = 8;
					byteIndex--;
				}
			}
		}
		return bytes;
	}

	protected static Integer cacheBits(int i) {
		return ParsedAddressGrouping.cache(i);
	}

	/**
	 * Returns whether the values of this division grouping contain the prefix block for the given prefix length
	 * 
	 * @param prefixLength
	 * @return
	 */
	@Override
	public boolean containsPrefixBlock(int prefixLength) {
		checkSubnet(this, prefixLength);
		int divisionCount = getDivisionCount();
		int prevBitCount = 0;
		for(int i = 0; i < divisionCount; i++) {
			AddressDivision division = getDivision(i);
			int bitCount = division.getBitCount();
			int totalBitCount = bitCount + prevBitCount;
			if(prefixLength < totalBitCount) {
				int divPrefixLen = Math.max(0, prefixLength - prevBitCount);
				if(!division.isPrefixBlock(division.getDivisionValue(), division.getUpperDivisionValue(), divPrefixLen)) {
					return false;
				}
				for(++i; i < divisionCount; i++) {
					division = getDivision(i);
					if(!division.isFullRange()) {
						return false;
					}
				}
				return true;
			}
			prevBitCount = totalBitCount;
		}
		return true;
	}
	
	/**
	 * Returns whether the values of this division grouping match the prefix block for the given prefix length
	 * @param prefixLength
	 * @return
	 */
	@Override
	public boolean containsSinglePrefixBlock(int prefixLength) {
		checkSubnet(this, prefixLength);
		int divisionCount = getDivisionCount();
		int prevBitCount = 0;
		for(int i = 0; i < divisionCount; i++) {
			AddressDivision division = getDivision(i);
			int bitCount = division.getBitCount();
			int totalBitCount = bitCount + prevBitCount;
			if(prefixLength >= totalBitCount) {
				if(division.isMultiple()) {
					return false;
				}
			} else {
				int divPrefixLen = Math.max(0, prefixLength - prevBitCount);
				if(!division.isSinglePrefixBlock(division.getDivisionValue(), division.getUpperDivisionValue(), divPrefixLen)) {
					return false;
				}
				for(++i; i < divisionCount; i++) {
					division = getDivision(i);
					if(!division.isFullRange()) {
						return false;
					}
				}
				return true;
			}
			prevBitCount = totalBitCount;
		}
		return true;
	}
	
	@Override
	public int hashCode() {
		int res = hashCode;
		if(res == 0) {
			res = 1;
			int count = getDivisionCount();
			for(int i = 0; i < count; i++) {
				AddressDivision combo = getDivision(i);
				res = adjustHashCode(res, combo.getDivisionValue(), combo.getUpperDivisionValue());
			}
			hashCode = res;
		}
		return res;
	}

	@Override
	protected boolean isSameGrouping(AddressDivisionGroupingBase other) {
		return other instanceof AddressDivisionGrouping && super.isSameGrouping(other);
	}

	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof AddressDivisionGrouping) {
			AddressDivisionGrouping other = (AddressDivisionGrouping) o;
			// we call isSameGrouping on the other object to defer to subclasses IPv4 and IPv6 which check for type IPv4AddressSection and IPv6AddressSection
			return other.isSameGrouping(this);
		}
		return false;
	}

	protected static Integer getPrefixedSegmentPrefixLength(int bitsPerSegment, int prefixLength, int segmentIndex) {
		return ParsedAddressGrouping.getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
	}
	
	protected static int getNetworkSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}

	protected static int getHostSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		return ParsedAddressGrouping.getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
	}
	
	protected static Integer getSegmentPrefixLength(int bitsPerSegment, Integer prefixLength, int segmentIndex) {
		return ParsedAddressGrouping.getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
	}
	
	protected static Integer getSegmentPrefixLength(int segmentBits, int segmentPrefixedBits) {
		return ParsedAddressGrouping.getSegmentPrefixLength(segmentBits, segmentPrefixedBits);
	}
	
	protected static int getNetworkPrefixLength(int bitsPerSegment, int prefixLength, int segmentIndex) {
		return ParsedAddressGrouping.getNetworkPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
	}

	protected int getAdjustedPrefix(boolean nextSegment, int bitsPerSegment, boolean skipBitCountPrefix) {
		Integer prefix = getPrefixLength();
		int bitCount = getBitCount();
		if(nextSegment) {
			if(prefix == null) {
				if(getMinPrefixLengthForBlock() == 0) {
					return 0;
				}
				return bitCount;
			}
			if(prefix == bitCount) {
				return bitCount;
			}
			int existingPrefixLength = prefix.intValue();
			int adjustment = existingPrefixLength % bitsPerSegment;
			return existingPrefixLength + bitsPerSegment - adjustment;
		} else {
			if(prefix == null) {
				if(getMinPrefixLengthForBlock() == 0) {
					return 0;
				}
				if(skipBitCountPrefix) {
					prefix = bitCount;
				} else {
					return bitCount;
				}
			} else if(prefix == 0) {
				return 0;
			}
			int existingPrefixLength = prefix.intValue();
			int adjustment = ((existingPrefixLength - 1) % bitsPerSegment) + 1;
			return existingPrefixLength - adjustment;
		}
	}
	
	protected int getAdjustedPrefix(int adjustment, boolean floor, boolean ceiling) {
		Integer prefix = getPrefixLength();
		if(prefix == null) {
			if(getMinPrefixLengthForBlock() == 0) {
				prefix = cacheBits(0);
			} else {
				prefix = cacheBits(getBitCount());
			}
		}
		int result = prefix + adjustment;
		if(ceiling) {
			result = Math.min(getBitCount(), result);
		}
		if(floor) {
			result = Math.max(0, result);
		}
		return result;
	}
	
	/**
	 * In the case where the prefix sits at a segment boundary, and the prefix sequence is null - null - 0, this changes to prefix sequence of null - x - 0, where x is segment bit length.
	 * 
	 * Note: We allow both [null, null, 0] and [null, x, 0] where x is segment length.  However, to avoid inconsistencies when doing segment replacements, 
	 * and when getting subsections, in the calling constructor we normalize [null, null, 0] to become [null, x, 0].
	 * We need to support [null, x, 0] so that we can create subsections and full addresses ending with [null, x] where x is bit length.
	 * So we defer to that when constructing addresses and sections.
	 * Also note that in our append/appendNetowrk/insert/replace we have special handling for cases like inserting [null] into [null, 8, 0] at index 2.
	 * The straight replace would give [null, 8, null, 0] which is wrong.
	 * In that code we end up with [null, null, 8, 0] by doing a special trick:
	 * We remove the end of [null, 8, 0] and do an append [null, 0] and we'd remove prefix from [null, 8] to get [null, null] and then we'd do another append to get [null, null, null, 0]
	 * The final step is this normalization here that gives [null, null, 8, 0]
	 * 
	 * However, when users construct AddressDivisionGrouping or IPAddressDivisionGrouping, either one is allowed: [null, null, 0] and [null, x, 0].  
	 * Since those objects cannot be further subdivided with getSection/getNetworkSection/getHostSection or grown with appended/inserted/replaced, 
	 * there are no inconsistencies introduced, we are simply more user-friendly.
	 * Also note that normalization of AddressDivisionGrouping or IPAddressDivisionGrouping is really not possible without the address creator objects we use for addresses and sections,
	 * that allow us to recreate new segments of the correct type.
	 * 
	 * @param sectionPrefixBits
	 * @param segments
	 * @param segmentBitCount
	 * @param segmentByteCount
	 * @param segProducer
	 */
	protected static <S extends IPAddressSegment> void normalizePrefixBoundary(
			int sectionPrefixBits,
			S segments[],
			int segmentBitCount,
			int segmentByteCount,
			BiFunction<S, Integer, S> segProducer) {
		//we've already verified segment prefixes in super constructor.  We simply need to check the case where the prefix is at a segment boundary,
		//whether the network side has the correct prefix
		int networkSegmentIndex = getNetworkSegmentIndex(sectionPrefixBits, segmentByteCount, segmentBitCount);
		if(networkSegmentIndex >= 0) {
			S segment = segments[networkSegmentIndex];
			if(!segment.isPrefixed()) {
				segments[networkSegmentIndex] = segProducer.apply(segment, segmentBitCount);
			}
		}
	}

	protected static <S extends AddressSegment> S[] setPrefixedSegments(
			AddressNetwork<?> network,
			int sectionPrefixBits,
			S segments[],
			int segmentBitCount,
			int segmentByteCount,
			AddressSegmentCreator<S> segmentCreator,
			BiFunction<S, Integer, S> segProducer) {
		boolean allPrefsSubnet = network.getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		for(int i = (sectionPrefixBits == 0) ? 0 : getNetworkSegmentIndex(sectionPrefixBits, segmentByteCount, segmentBitCount); i < segments.length; i++) {
			Integer pref = getPrefixedSegmentPrefixLength(segmentBitCount, sectionPrefixBits, i);
			if(pref != null) {
				segments[i] = segProducer.apply(segments[i], pref);
				if(allPrefsSubnet) {
					if(++i < segments.length) {
						S allSeg = segmentCreator.createSegment(0, 0);
						Arrays.fill(segments, i, segments.length, allSeg);
					}
				}
			}
		}
		return segments;
	}

	@FunctionalInterface
	protected interface SegPrefFunction<S> {
	    S apply(S s, Integer u, Integer v);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> S[] removePrefix(
			R original,
			S segments[],
			int segmentBitCount,
			SegPrefFunction<S> prefixSetter //this one takes both new and old prefix and both zeros out old pref and applies new one
			) {
		Integer oldPrefix = original.getPrefixLength();
		if(oldPrefix != null) {
			segments = segments.clone();
			for(int i = 0; i < segments.length; i++) {
				Integer oldPref = getPrefixedSegmentPrefixLength(segmentBitCount, oldPrefix, i);
				segments[i] = prefixSetter.apply(segments[i], oldPref, null);
			}
		}
		return segments;
	}

	protected static boolean prefixEquals(AddressSection first, AddressSection other, int otherIndex) {
		Integer prefixLength = first.getPrefixLength();
		int prefixedSection;
		if(prefixLength == null) {
			prefixedSection = first.getSegmentCount();
		} else {
			prefixedSection = getNetworkSegmentIndex(prefixLength, first.getBytesPerSegment(), first.getBitsPerSegment());
			if(prefixedSection >= 0) {
				AddressSegment one = first.getSegment(prefixedSection);
				AddressSegment two = other.getSegment(prefixedSection + otherIndex);
				if(!one.prefixEquals(two, prefixLength)) {
					return false;
				}
			}
		}
		while(--prefixedSection >= 0) {
			AddressSegment one = first.getSegment(prefixedSection);
			AddressSegment two = other.getSegment(prefixedSection + otherIndex);
			if(!one.equals(two)) {
				return false;
			}
		}
		return true;
	}
	
	protected static <S extends AddressSegment> S[] createSegments(
			S segments[],
			long highBytes,
			long lowBytes,
			int bitsPerSegment,
			AddressNetwork<S> network,
			Integer prefixLength) {
		AddressSegmentCreator<S> creator = network.getAddressCreator();
		int segmentMask = ~(~0 << bitsPerSegment);
		int lowIndex = Math.max(0, segments.length - (Long.SIZE / bitsPerSegment));
		int segmentIndex = segments.length - 1;
		long bytes = lowBytes;
		while(true) {
			while(true) {
				Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
				int value = segmentMask & (int) bytes;
				S seg = creator.createSegment(value, segmentPrefixLength);
				if(!network.equals(seg.getNetwork())) {
					throw new NetworkMismatchException(seg);
				}
				segments[segmentIndex] = seg;
				if(--segmentIndex < lowIndex) {
					break;
				}
				bytes >>>= bitsPerSegment;
			}
			if(lowIndex == 0) {
				break;
			}
			lowIndex = 0;
			bytes = highBytes;
		}
		return segments;
	}
	
	protected static <S extends AddressSegment> S[] createSegments(
			S segments[],
			SegmentValueProvider lowerValueProvider,
			SegmentValueProvider upperValueProvider,
			int bytesPerSegment,
			int bitsPerSegment,
			AddressNetwork<S> network,
			Integer prefixLength) {
		AddressSegmentCreator<S> creator = network.getAddressCreator();
		int segmentCount = segments.length;
		for(int segmentIndex = 0; segmentIndex < segmentCount; segmentIndex++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
			if(segmentPrefixLength != null && segmentPrefixLength == 0 && network.getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				S allSeg = creator.createSegment(0, 0);
				if(!network.equals(allSeg.getNetwork())) {
					throw new NetworkMismatchException(allSeg);
				}
				Arrays.fill(segments, segmentIndex, segmentCount, allSeg);
				break;
			}
			
			int value = 0, value2 = 0;
			if(lowerValueProvider == null) {
				value = upperValueProvider.getValue(segmentIndex);
			} else {
				value = lowerValueProvider.getValue(segmentIndex);
				if(upperValueProvider != null) {
					value2 = upperValueProvider.getValue(segmentIndex);
				}
			}
			S seg = (lowerValueProvider != null && upperValueProvider != null) ? 
					creator.createSegment(value, value2, segmentPrefixLength) : 
						creator.createSegment(value, segmentPrefixLength);
			if(!network.equals(seg.getNetwork())) {
				throw new NetworkMismatchException(seg);
			}
			segments[segmentIndex] = seg;
		}
		return segments;
	}

	protected static <S extends AddressSegment> S[] toSegments(
			S segments[],
			byte bytes[],
			int startIndex,
			int endIndex,
			int bytesPerSegment,
			int bitsPerSegment,
			AddressNetwork<S> network,
			Integer prefixLength) {
		if(endIndex < 0 || endIndex > bytes.length) {
			throw new AddressValueException(endIndex);
		}
		if(startIndex < 0 || startIndex > endIndex) {
			throw new AddressValueException(startIndex);
		}
		AddressSegmentCreator<S> creator = network.getAddressCreator();
		int segmentCount = segments.length;
		int expectedByteCount = segmentCount * bytesPerSegment;
		
		//We allow two formats of bytes:
		//1. two's complement: top bit indicates sign.  Ranging over all 16-byte lengths gives all addresses, from both positive and negative numbers
		//  Also, we allow sign extension to shorter and longer byte lengths.  For example, -1, -1, -2 is the same as just -2.  So if this were IPv4, we allow -1, -1, -1, -1, -2 and we allow -2.
		//  This is compatible with BigInteger.  If we have a positive number like 2, we allow 0, 0, 0, 0, 2 and we allow just 2.  
		//  But the top bit must be 0 for 0-sign extension. So if we have 255 as a positive number, we allow 0, 255 but not 255.  
		//  Just 255 is considered negative and equivalent to -1, and extends to -1, -1, -1, -1 or the address 255.255.255.255, not 0.0.0.255
		//
		//2. Unsigned values
		//  We interpret 0, -1, -1, -1, -1 as 255.255.255.255 even though this is not a sign extension of -1, -1, -1, -1.
		//  In this case, we also allow any 4 byte value to be considered a positive unsigned number, and thus we always allow leading zeros.
		//  In the case of extending byte array values that are shorter than the required length, 
		//  unsigned values must have a leading zero in cases where the top bit is 1, because the two's complement format takes precedence.
		//  So the single value 255 must have an additional 0 byte in front to be considered unsigned, as previously shown.
		//  The single value 255 is considered -1 and is extended to become the address 255.255.255.255, 
		//  but for the unsigned positive value 255 you must use the two bytes 0, 255 which become the address 0.0.0.255.
		//  Once again, this is compatible with BigInteger.
		
		int missingBytes = expectedByteCount + startIndex - endIndex;
		
		//First we handle the situation where we have too many bytes.  Extra bytes can be all zero-bits, or they can be the negative sign extension of all one-bits.
		if(missingBytes < 0) {
			int expectedStartIndex = endIndex - expectedByteCount;
			int higherStartIndex = expectedStartIndex - 1;
			byte expectedExtendedValue = bytes[higherStartIndex];
			if(expectedExtendedValue != 0) {
				int mostSignificantBit = bytes[expectedStartIndex] >>> 7;
				if(mostSignificantBit != 0) {
					if(expectedExtendedValue != -1) {//0xff
						throw new AddressValueException(expectedExtendedValue);
					}
				} else {
					throw new AddressValueException(expectedExtendedValue);
				}
			}
			while(startIndex < higherStartIndex) {
				if(bytes[--higherStartIndex] != expectedExtendedValue) {
					throw new AddressValueException(expectedExtendedValue);
				}
			}
			startIndex = expectedStartIndex;
			missingBytes = 0;
		}
		boolean allPrefixedAddressesAreSubnets = network.getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		for(int i = 0, segmentIndex = 0; i < expectedByteCount; segmentIndex++) {
			Integer segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
			if(allPrefixedAddressesAreSubnets && segmentPrefixLength != null && segmentPrefixLength == 0) {
				S allSeg = creator.createSegment(0, 0);
				if(!network.equals(allSeg.getNetwork())) {
					throw new NetworkMismatchException(allSeg);
				}
				Arrays.fill(segments, segmentIndex, segmentCount, allSeg);
				break;
			}

			int value = 0;
			int k = bytesPerSegment + i;
			int j = i;
			if(j < missingBytes) {
				int mostSignificantBit = bytes[startIndex] >>> 7;
				if(mostSignificantBit == 0) {//sign extension
					j = missingBytes;
				} else {//sign extension
					int upper = Math.min(missingBytes, k);
					for(; j < upper; j++) {
						value <<= 8;
						value |= 0xff;
					}
				}
			}
			for(; j < k; j++) {
				int byteValue = 0xff & bytes[startIndex + j - missingBytes];
				value <<= 8;
				value |= byteValue;
			}
			i = k;
			
			S seg = creator.createSegment(value, segmentPrefixLength);
			if(!network.equals(seg.getNetwork())) {
				throw new NetworkMismatchException(seg);
			}
			segments[segmentIndex] = seg;
		}
		return segments;
	}

	protected static <R extends AddressSection, S extends AddressSegment> S[] createSingle(
			R original,
			AddressSegmentCreator<S> segmentCreator,
			IntFunction<S> segProducer) {
		int segmentCount = original.getSegmentCount();
		S segs[] = segmentCreator.createSegmentArray(segmentCount);
		for(int i = 0; i < segmentCount; i++) {
			segs[i] = segProducer.apply(i);
		}
		return segs;
	}

	protected static <R extends AddressSegmentSeries> R getSingleLowestOrHighestSection(R section) {
		if(!section.isMultiple() && !(section.isPrefixed() && section.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets())) {
			return section;
		}
		return null;
	}

	protected static <R extends AddressSection, S extends AddressSegment> R reverseSegments(R section, AddressCreator<?, R, ?, S> creator, IntFunction<S> segProducer, boolean removePrefix) {
		int count = section.getSegmentCount();
		S newSegs[] = creator.createSegmentArray(count);
		int halfCount = count >>> 1;
		int i = 0;
		boolean isSame = !removePrefix || !section.isPrefixed();//when reversing, the prefix must go
		for(int j = count - 1; i < halfCount; i++, j--) {
			newSegs[j] = segProducer.apply(i);
			newSegs[i] = segProducer.apply(j);
			if(isSame && !(newSegs[i].equals(section.getSegment(i)) && newSegs[j].equals(section.getSegment(j)))) {
				isSame = false;
			}
		}
		if((count & 1) == 1) {//the count is odd, handle the middle one
			newSegs[i] = segProducer.apply(i);
			if(isSame && !newSegs[i].equals(section.getSegment(i))) {
				isSame = false;
			}
		}
		if(isSame) {
			return section;//We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
		}
		return creator.createSectionInternal(newSegs);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R reverseBits(
			boolean perByte, R section, AddressCreator<?, R, ?, S> creator, IntFunction<S> segBitReverser, boolean removePrefix) {
		if(perByte) {
			boolean isSame = !removePrefix || !section.isPrefixed();//when reversing, the prefix must go
			int count = section.getSegmentCount();
			S newSegs[] = creator.createSegmentArray(count);
			for(int i = 0; i < count; i++) {
				newSegs[i] = segBitReverser.apply(i);
				if(isSame && !newSegs[i].equals(section.getSegment(i))) {
					isSame = false;
				}
			}
			if(isSame) {
				return section;//We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
			}
			return creator.createSectionInternal(newSegs);
		}
		return reverseSegments(section, creator, segBitReverser, removePrefix);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R reverseBytes(
			boolean perSegment, R section, AddressCreator<?, R, ?, S> creator, IntFunction<S> segByteReverser, boolean removePrefix) {
		if(perSegment) {
			boolean isSame = !removePrefix || !section.isPrefixed();//when reversing, the prefix must go
			int count = section.getSegmentCount();
			S newSegs[] = creator.createSegmentArray(count);
			for(int i = 0; i < count; i++) {
				newSegs[i] = segByteReverser.apply(i);
				if(isSame && !newSegs[i].equals(section.getSegment(i))) {
					isSame = false;
				}
			}
			if(isSame) {
				return section;//We can do this because for ipv6 startIndex stays the same and for mac startIndex and extended stays the same
			}
			return creator.createSectionInternal(newSegs);
		}
		return reverseSegments(section, creator, segByteReverser, removePrefix);
	}

	protected static interface GroupingCreator<S extends AddressDivisionBase> {
		S createDivision(long value, long upperValue, int bitCount, int radix);
	}
	
	protected <S extends AddressDivisionBase> S[] createNewDivisions(int bitsPerDigit, GroupingCreator<S> groupingCreator, IntFunction<S[]> groupingArrayCreator) {
		return createNewPrefixedDivisions(bitsPerDigit, null, null,
				(value, upperValue, bitCount, radix, network, prefixLength) -> groupingCreator.createDivision(value, upperValue, bitCount, radix),
				groupingArrayCreator);
	}
	
	protected static interface PrefixedGroupingCreator<S extends AddressDivisionBase> {
		S createDivision(long value, long upperValue, int bitCount, int radix, IPAddressNetwork<?, ?, ?, ?, ?> network, Integer prefixLength);
	}
	
	/**
	 * 
	 * @param bitsPerDigit
	 * @param network can be null if networkPrefixLength is null
	 * @param networkPrefixLength
	 * @param groupingCreator
	 * @param groupingArrayCreator
	 * @throws AddressValueException if bitsPerDigit is larger than 32
	 * @return
	 */
	protected <S extends AddressDivisionBase> S[] createNewPrefixedDivisions(int bitsPerDigit, IPAddressNetwork<?, ?, ?, ?, ?> network, Integer networkPrefixLength, PrefixedGroupingCreator<S> groupingCreator, IntFunction<S[]> groupingArrayCreator) {
		if(bitsPerDigit >= Integer.SIZE) {
			//keep in mind once you hit 5 bits per digit, radix 32, you need 32 different digits, and there are only 26 alphabet characters and 10 digit chars, so 36
			//so once you get higher than that, you need a new character set.
			//AddressLargeDivision allows all the way up to base 85
			throw new AddressValueException(bitsPerDigit);
		}
		int bitCount = getBitCount();
		List<Integer> bitDivs = new ArrayList<Integer>(bitsPerDigit);
		//ipv6 octal:
		//seg bit counts: 63, 63, 2
		//ipv4 octal:
		//seg bit counts: 30, 2
		int largestBitCount = Long.SIZE - 1;
		largestBitCount -= largestBitCount % bitsPerDigit;
		do {
			if(bitCount <= largestBitCount) {
				int mod = bitCount % bitsPerDigit;
				int secondLast = bitCount - mod;
				if(secondLast > 0) {
					bitDivs.add(secondLast);
				}
				if(mod > 0) {
					bitDivs.add(mod);
				}
				break;
			} else {
				bitCount -= largestBitCount;
				bitDivs.add(largestBitCount);
			}
		} while(true);
		int bitDivSize = bitDivs.size();
		S divs[] = groupingArrayCreator.apply(bitDivSize);
		int currentSegmentIndex = 0;
		AddressDivision seg = getDivision(currentSegmentIndex);
		long segLowerVal = seg.getDivisionValue();
		long segUpperVal = seg.getUpperDivisionValue();
		int segBits = seg.getBitCount();
		int bitsSoFar = 0;
		int radix = AddressDivision.getRadixPower(BigInteger.valueOf(2), bitsPerDigit).intValue();
		//fill up our new divisions, one by one
		for(int i = bitDivSize - 1; i >= 0; i--) {
			int originalDivBitSize, divBitSize;
			originalDivBitSize = divBitSize = bitDivs.get(i);
			long divLowerValue, divUpperValue;
			divLowerValue = divUpperValue = 0;
			while(true) {
				if(segBits >= divBitSize) {
					int diff = segBits - divBitSize;
					divLowerValue |= segLowerVal >>> diff;
					int shift = ~(~0 << diff);
					segLowerVal &= shift;
					divUpperValue |= segUpperVal >>> diff;
					segUpperVal &= shift;
					segBits = diff;
					Integer segPrefixBits = networkPrefixLength == null ? null : getSegmentPrefixLength(originalDivBitSize, networkPrefixLength - bitsSoFar);
					S div = groupingCreator.createDivision(divLowerValue, divUpperValue, originalDivBitSize, radix, network, segPrefixBits);
					divs[bitDivSize - i - 1] = div;
					if(segBits == 0 && i > 0) {
						//get next seg
						seg = getDivision(++currentSegmentIndex);
						segLowerVal = seg.getDivisionValue();
						segUpperVal = seg.getUpperDivisionValue();
						segBits = seg.getBitCount();
					}
					break;
				} else {
					int diff = divBitSize - segBits;
					divLowerValue |= segLowerVal << diff;
					divUpperValue |= segUpperVal << diff;
					divBitSize = diff;
					
					//get next seg
					seg = getDivision(++currentSegmentIndex);
					segLowerVal = seg.getDivisionValue();
					segUpperVal = seg.getUpperDivisionValue();
					segBits = seg.getBitCount();
				}
			}
			bitsSoFar += originalDivBitSize;
		}
		return divs;
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> Iterator<R> iterator(
			boolean useOriginal,
			R original,
			AddressCreator<?, R, ?, S> creator,
			Iterator<S[]> iterator,
			Integer prefixLength) {
		if(useOriginal) {
			return new Iterator<R>() {
				R orig = original;

				@Override
				public R next() {
					if(orig == null) {
			    		throw new NoSuchElementException();
			    	}
					R result = orig;
			    	orig = null;
				    return result;
			    }

				@Override
				public boolean hasNext() {
					return orig != null;
				}

			    @Override
				public void remove() {
			    	throw new UnsupportedOperationException();
			    }
			};
		}
		return new Iterator<R>() {
			@Override
			public R next() {
				if(!iterator.hasNext()) {
		    		throw new NoSuchElementException();
		    	}
				S next[] = iterator.next();
				return createIteratedSection(next, creator, prefixLength);
			}

			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}

		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R createIteratedSection(
			S next[],
			AddressCreator<?, R, ?, S> creator,
			Integer prefixLength) {
		return creator.createPrefixedSectionInternal(next, prefixLength, true);
	}
	
	protected static <S extends AddressSegment> Iterator<S[]> iterator(
			int divCount,
			AddressSegmentCreator<S> segmentCreator,
			Supplier<S[]> segSupplier,
			IntFunction<Iterator<S>> segIteratorProducer,
			Predicate<S[]> excludeFunc) {
		return iterator(divCount, segmentCreator, segSupplier, segIteratorProducer, excludeFunc, divCount - 1, divCount, null);
	}
	
	/**
	 * Used to produce regular iterators with or without zero-host values, and prefix block iterators
	 * @param segmentCreator
	 * @param segSupplier
	 * @param segIteratorProducer
	 * @param excludeFunc
	 * @param networkSegmentIndex
	 * @param hostSegmentIndex
	 * @param prefixedSegIteratorProducer
	 * @return
	 */
	protected static <S extends AddressSegment> Iterator<S[]> iterator(
			int divCount,
			AddressSegmentCreator<S> segmentCreator,
			Supplier<S[]> segSupplier,//provides the original segments in an array for a single valued iterator
			IntFunction<Iterator<S>> segIteratorProducer,
			Predicate<S[]> excludeFunc,
			int networkSegmentIndex,
			int hostSegmentIndex,
			IntFunction<Iterator<S>> prefixedSegIteratorProducer) {
		if(segSupplier != null) {
			return new Iterator<S[]>() {
				S result[] = segSupplier.get(); {
					if(excludeFunc != null && excludeFunc.test(result)) {
						result = null;
					}
				}
				
				@Override
				public boolean hasNext() {
					return result != null;
				}

			    @Override
				public S[] next() {
			    	if(result == null) {
			    		throw new NoSuchElementException();
			    	}
			    	S res[] = result;
			    	result = null;
			    	return res;
			    }

			    @Override
				public void remove() {
			    	throw new UnsupportedOperationException();
			    }
			};
		}
		
		return new Iterator<S[]>() {
			private boolean done;
				
			@SuppressWarnings("unchecked")
			private final Iterator<S> variations[] = new Iterator[divCount];
			
			private S nextSet[] = segmentCreator.createSegmentArray(divCount);  {
				updateVariations(0);
				for(int i = networkSegmentIndex + 1; i < divCount; i++) {//for regular iterators (not prefix block), networkSegmentIndex is last segment (count - 1)
					variations[i] = prefixedSegIteratorProducer.apply(i);
					nextSet[i] = variations[i].next();
				}
				if(excludeFunc != null && excludeFunc.test(nextSet)) {
					increment();
				}
			}
			
			private void updateVariations(int start) {
				int i = start;
				for(; i < hostSegmentIndex; i++) {
					variations[i] = segIteratorProducer.apply(i);
					nextSet[i] = variations[i].next();
				}
				if(i == networkSegmentIndex) {
					variations[i] = prefixedSegIteratorProducer.apply(i);
					nextSet[i] = variations[i].next();
				}
			}
			
			@Override
			public boolean hasNext() {
				return !done;
			}
			
		    @Override
			public S[] next() {
		    	if(done) {
		    		throw new NoSuchElementException();
		    	}
		    	return increment();
		    }
		    
		    private S[] increment() {
		    	S previousSegs[] = null;
		    	for(int j = networkSegmentIndex; j >= 0; j--) {//for regular iterators (not prefix block), networkSegmentIndex is last segment (count - 1)
		    		while(variations[j].hasNext()) {
		    			if(previousSegs == null) {
		    				previousSegs = nextSet.clone();
		    			}
		    			nextSet[j] = variations[j].next();
		    			updateVariations(j + 1);
		    			if(excludeFunc != null && excludeFunc.test(nextSet)) {
		    				j = networkSegmentIndex;
						} else {
							return previousSegs;
						}
		    		}
		    	}
		    	done = true;
		    	return previousSegs == null ? nextSet : previousSegs;
		    }

		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}

	protected static <T extends Address, S extends AddressSegment> Iterator<T> iterator(
			T original,
			AddressCreator<T, ?, ?, S> creator,
			Iterator<S[]> iterator, /* unused if original not null */
			Integer prefixLength /* if the segments themselves do not have associated prefix length, one can be supplied here */) {
		if(original != null) {
			return new Iterator<T>() {
				T orig = original;

				@Override
				public boolean hasNext() {
					return orig != null;
				}

			    @Override
				public T next() {
			    	if(orig == null) {
			    		throw new NoSuchElementException();
			    	}
			    	T result = orig;
			    	orig = null;
			    	return result;
			    }
			
			    @Override
				public void remove() {
			    	throw new UnsupportedOperationException();
			    }
			};
		}
		return new Iterator<T>() {
			@Override
			public boolean hasNext() {
				return iterator.hasNext();
			}
		
		    @Override
			public T next() {
		    	if(!hasNext()) {
		    		throw new NoSuchElementException();
		    	}
		    	S[] next = iterator.next();
		    	return prefixLength != null ? creator.createAddressInternal(next, prefixLength, true) : creator.createAddressInternal(next); /* address creation */
		    }
		
		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	protected static void checkOverflow(
			long increment,
			long lowerValue,
			long upperValue,
			long count,
			LongSupplier maxValue
			) {
		if(increment < 0) {
			if(lowerValue < -increment) {
				throw new AddressValueException(increment);
			}
		} else {
			if(count > 1) {
				increment -= count - 1;
			}
			if(increment > maxValue.getAsLong() - upperValue) {
				throw new AddressValueException(increment);
			}
		}
	}
	
	protected static void checkOverflow(
			long increment,
			BigInteger bigIncrement,
			BigInteger lowerValue,
			BigInteger upperValue,
			BigInteger count,
			Supplier<BigInteger> maxValue
			) {
		boolean isMultiple = count.compareTo(BigInteger.ONE) > 0;
		if(increment < 0) {
			if(lowerValue.compareTo(bigIncrement.negate()) < 0) {
				throw new AddressValueException(increment);
			}
		} else {
			if(isMultiple) {
				bigIncrement = bigIncrement.subtract(count.subtract(BigInteger.ONE));
			}
			if(bigIncrement.compareTo(maxValue.get().subtract(upperValue)) > 0) {
				throw new AddressValueException(increment);
			}
		}
	}
	
	/**
	 * Handles the cases in which we can use longs rather than BigInteger
	 * 
	 * @param section
	 * @param increment
	 * @param addrCreator
	 * @param lowerProducer
	 * @param upperProducer
	 * @param prefixLength
	 * @return
	 */
	protected static <R extends AddressSection, S extends AddressSegment> R fastIncrement(
			R section,
			long increment,
			AddressCreator<?, R, ?, S> addrCreator, 
			Supplier<R> lowerProducer,
			Supplier<R> upperProducer,
			Integer prefixLength) {
		if(increment >= 0) {
			BigInteger count = section.getCount();
			if(count.compareTo(LONG_MAX) <= 0) {
				long longCount = count.longValue();
				if(longCount > increment) {
					if(longCount == increment + 1) {
						return upperProducer.get();
					}
					return incrementRange(section, increment, addrCreator, lowerProducer, prefixLength);
				}
				BigInteger value = section.getValue();
				BigInteger upperValue;
				if(value.compareTo(LONG_MAX) <= 0 && (upperValue = section.getUpperValue()).compareTo(LONG_MAX) <= 0) {
					return increment(
							section,
							increment,
							addrCreator,
							count.longValue(),
							value.longValue(),
							upperValue.longValue(),
							lowerProducer,
							upperProducer,
							prefixLength);
				}
			}
		} else {
			BigInteger value = section.getValue();
			if(value.compareTo(LONG_MAX) <= 0) {
				return add(lowerProducer.get(), value.longValue(), increment, addrCreator, prefixLength);
			}
		}
		return null;
	}

	//this does not handle overflow, overflow should be checked before calling this
	protected static <R extends AddressSection, S extends AddressSegment> R increment(
			R section,
			long increment,
			AddressCreator<?, R, ?, S> addrCreator, 
			long count,
			long lowerValue,
			long upperValue,
			Supplier<R> lowerProducer,
			Supplier<R> upperProducer,
			Integer prefixLength) {
		if(!section.isMultiple()) {
			return add(section, lowerValue, increment, addrCreator, prefixLength);
		}
		boolean isDecrement = increment <= 0;
		if(isDecrement) {
			//we know lowerValue + increment >= 0 because we already did an overflow check
			return add(lowerProducer.get(), lowerValue, increment, addrCreator, prefixLength);
		} 
		if(count > increment) {
			if(count == increment + 1) {
				return upperProducer.get();
			}
			return incrementRange(section, increment, addrCreator, lowerProducer, prefixLength);
		}
		if(increment <= Long.MAX_VALUE - upperValue) {
			return add(upperProducer.get(), upperValue, increment - (count - 1), addrCreator, prefixLength);
		}
		return add(upperProducer.get(), BigInteger.valueOf(increment - (count - 1)), addrCreator, prefixLength);
	}

	//this does not handle overflow, overflow should be checked before calling this
	protected static <R extends AddressSection, S extends AddressSegment> R increment(
			R section,
			long increment,
			BigInteger bigIncrement,
			AddressCreator<?, R, ?, S> addrCreator, 
			Supplier<R> lowerProducer,
			Supplier<R> upperProducer,
			Integer prefixLength) {
		if(!section.isMultiple()) {
			return add(section, bigIncrement, addrCreator, prefixLength);
		}
		boolean isDecrement = increment <= 0;
		if(isDecrement) {
			return add(lowerProducer.get(), bigIncrement, addrCreator, prefixLength);
		}
		BigInteger count = section.getCount();
		BigInteger incrementPlus1 = bigIncrement.add(BigInteger.ONE);
		int countCompare = count.compareTo(incrementPlus1);
		if(countCompare <= 0) {
			if(countCompare == 0) {
				return upperProducer.get();
			}
			return add(upperProducer.get(), incrementPlus1.subtract(count), addrCreator, prefixLength);
		}
		return incrementRange(section, increment, addrCreator, lowerProducer, prefixLength);
	}
	
	/**
	 * 
	 * @param section
	 * @param increment
	 * @param addrCreator
	 * @param rangeIncrement the positive value of the number of increments through the range (0 means take lower or upper value in range)
	 * @param isDecrement
	 * @param lowerProducer
	 * @param upperProducer
	 * @param prefixLength
	 * @return
	 */
	protected static <R extends AddressSection, S extends AddressSegment> R incrementRange(
			R section,
			long increment,
			AddressCreator<?, R, ?, S> addrCreator, 
			Supplier<R> lowerProducer,
			Integer prefixLength) {
		if(increment == 0) {
			return lowerProducer.get();
		}
		int segCount = section.getSegmentCount();
		S newSegments[] = addrCreator.createSegmentArray(segCount);
		for(int i = segCount - 1; i >= 0; i--) {
			AddressSegment seg = section.getSegment(i);
			int segRange = seg.getValueCount();
			long revolutions = increment / segRange;
			int remainder = (int) (increment % segRange);
			S newSegment = addrCreator.createSegment(seg.getSegmentValue() + remainder);
			newSegments[i] = newSegment;
			if(revolutions == 0) {
				for(i--; i >= 0; i--) {
					AddressSegment original = section.getSegment(i);
					newSegments[i] = addrCreator.createSegment(original.getSegmentValue());
				}
				break;
			} else {
				increment = revolutions;
			}
		}
		return createIteratedSection(newSegments, addrCreator, prefixLength);
	}
	
	//this does not handle overflow, overflow should be checked before calling this
	protected static <R extends AddressSection, S extends AddressSegment> R add(
			R section, BigInteger increment, AddressCreator<?, R, ?, S> addrCreator, Integer prefixLength) {
		if(section.isMultiple()) {
			throw new IllegalArgumentException();
		}
		int segCount = section.getSegmentCount();
		BigInteger fullValue = section.getValue();
		fullValue = fullValue.add(increment);
		byte bytes[] = fullValue.toByteArray();
		return addrCreator.createSectionInternal(bytes, segCount, prefixLength, true);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R add(
			R section, long fullValue, long increment, AddressCreator<?, R, ?, S> addrCreator, Integer prefixLength) {
		if(section.isMultiple()) {
			throw new IllegalArgumentException();
		}
		int segCount = section.getSegmentCount();
		S newSegs[] = addrCreator.createSegmentArray(segCount);
		createSegments(
					newSegs,
					0,
					fullValue + increment,
					section.getBitsPerSegment(),
					addrCreator.getNetwork(),
					prefixLength);
		return createIteratedSection(newSegs, addrCreator, prefixLength);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R getSection(
			int index,
			int endIndex,
			R section,
			AddressCreator<?, R, ?, S> creator) {
		if(index == 0 && endIndex == section.getSegmentCount()) {
			return section;
		}
		int segmentCount = endIndex - index;
		if(segmentCount < 0) {
			throw new IndexOutOfBoundsException();
		}
		S segs[] = creator.createSegmentArray(segmentCount);
		section.getSegments(index, endIndex, segs, 0);
		return creator.createSectionInternal(segs);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R append(
			R section,
			R other,
			AddressCreator<?, R, ?, S> creator) {
		int otherSegmentCount = other.getSegmentCount();
		int segmentCount = section.getSegmentCount();
		int totalSegmentCount = segmentCount + otherSegmentCount;
		S segs[] = creator.createSegmentArray(totalSegmentCount);
		section.getSegments(0, segmentCount, segs, 0);
		if(section.isPrefixed() && section.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			S allSegment = creator.createSegment(0, 0);
			Arrays.fill(segs, segmentCount, totalSegmentCount, allSegment);
		} else {
			other.getSegments(0, otherSegmentCount, segs, segmentCount);
		}
		return creator.createSectionInternal(segs);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R replace(
			R section,
			int index,
			int endIndex,
			R replacement,
			int replacementStartIndex,
			int replacementEndIndex,
			AddressCreator<?, R, ?, S> creator,
			boolean appendNetwork,
			boolean isMac) {
		int otherSegmentCount = replacementEndIndex  - replacementStartIndex;
		int segmentCount = section.getSegmentCount();
		int totalSegmentCount = segmentCount + otherSegmentCount - (endIndex - index);
		S segs[] = creator.createSegmentArray(totalSegmentCount);
		section.getSegments(0, index, segs, 0);
		if(index < totalSegmentCount) {
			if(section.isPrefixed() && section.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() &&
					(appendNetwork ?
							(getHostSegmentIndex(section.getPrefixLength(), section.getBytesPerSegment(), section.getBitsPerSegment()) < index) :
							(getNetworkSegmentIndex(section.getPrefixLength(), section.getBytesPerSegment(), section.getBitsPerSegment()) < index)) && 
					(isMac || index > 0)) { 
				S allSegment = creator.createSegment(0, 0);
				Arrays.fill(segs, index, totalSegmentCount, allSegment);
				return creator.createSectionInternal(segs);
			}
			replacement.getSegments(replacementStartIndex, replacementEndIndex, segs, index);
			if(index + otherSegmentCount < totalSegmentCount) {
				if(replacement.isPrefixed() && section.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && 
						getNetworkSegmentIndex(replacement.getPrefixLength(), replacement.getBytesPerSegment(), replacement.getBitsPerSegment()) < replacementEndIndex && 
						(isMac || otherSegmentCount > 0)) {
					S allSegment = creator.createSegment(0, 0);
					Arrays.fill(segs, index + otherSegmentCount, totalSegmentCount, allSegment);
				} else {
					section.getSegments(endIndex, segmentCount, segs, index + otherSegmentCount);
				}
			}
		}
		return creator.createSectionInternal(segs);
	}
	
	protected static <R extends AddressSection, S extends AddressSegment> R createSectionInternal(AddressCreator<?, R, ?, S> creator, S[] segments, int startIndex, boolean extended) {
		return creator.createSectionInternal(segments, startIndex, extended);
	}
	
	protected static AddressDivisionWriter getCachedParams(StringOptions opts) {
		return opts.cachedParams;
	}
	
	protected static void setCachedParams(StringOptions opts, AddressDivisionWriter cachedParams) {
		opts.cachedParams = cachedParams;
	}
	
	protected boolean isDualString() {
		int count = getDivisionCount();
		for(int i = 0; i < count; i++) {
			AddressDivision division = getDivision(i);
			if(division.isMultiple()) {
				//at this point we know we will return true, but we determine now if we must throw IncompatibleAddressException
				boolean isLastFull = true;
				AddressDivision lastDivision = null;
				for(int j = count - 1; j >= 0; j--) {
					division = getDivision(j);
					if(division.isMultiple()) {
						if(!isLastFull) {
							throw new IncompatibleAddressException(division, i, lastDivision, i + 1, "ipaddress.error.segmentMismatch");
						}
						isLastFull = division.isFullRange();
					} else {
						isLastFull = false;
					}
					lastDivision = division;
				}
				return true;
			}
		}
		return false;
	}

	protected static <T extends AddressStringDivisionSeries, E extends AddressStringDivisionSeries> String 
			toNormalizedStringRange(AddressStringParams<T> params, T lower, T upper, CharSequence zone) {
		int length = params.getStringLength(lower, zone) + params.getStringLength(upper, zone);
		StringBuilder builder;
		String separator = params.getWildcards().rangeSeparator;
		if(separator != null) {
			length += separator.length();
			builder = new StringBuilder(length);
			params.append(params.append(builder, lower, null).append(separator), upper, zone);
		} else {
			builder = new StringBuilder(length);
			params.append(params.append(builder, lower, null), upper, zone);
		}
		AddressStringParams.checkLengths(length, builder);
		return builder.toString();
	}
	
	protected static class AddressStringParams<T extends AddressStringDivisionSeries> implements AddressDivisionWriter, AddressSegmentParams, Cloneable {
		public static final Wildcards DEFAULT_WILDCARDS = new Wildcards();
		
		private Wildcards wildcards = DEFAULT_WILDCARDS;
		
		protected boolean expandSegments; //whether to expand 1 to 001 for IPv4 or 0001 for IPv6
		
		private String segmentStrPrefix = ""; //eg for inet_aton style there is 0x for hex, 0 for octal

		private int radix;
		
		//the segment separator and in the case of split digits, the digit separator
		protected Character separator;
				
		private boolean uppercase; //whether to print A or a
		
		//print the segments in reverse, and in the case of splitDigits, print the digits in reverse as well
		private boolean reverse;
				
		//in each segment, split the digits with the separator, so that 123.456.1.1 becomes 1.2.3.4.5.6.1.1
		private boolean splitDigits;
		
		private String addressLabel = "";
		
		private char zoneSeparator;
		
		public AddressStringParams(int radix, Character separator, boolean uppercase) {
			this(radix, separator, uppercase, (char) 0);
		}
		
		public AddressStringParams(int radix, Character separator, boolean uppercase, char zoneSeparator) {
			this.radix = radix;
			this.separator = separator;
			this.uppercase = uppercase;
			this.zoneSeparator  = zoneSeparator;
		}

		public void setZoneSeparator(char zoneSeparator) {
			this.zoneSeparator = zoneSeparator;
		}
		
		public String getAddressLabel() {
			return addressLabel;
		}
		
		public void setAddressLabel(String str) {
			this.addressLabel = str;
		}
		
		public Character getSeparator() {
			return separator;
		}
		
		public void setSeparator(Character separator) {
			this.separator = separator;
		}
		
		@Override
		public Wildcards getWildcards() {
			return wildcards;
		}
		
		public void setWildcards(Wildcards wc) {
			wildcards = wc;
		}
		
		@Override
		public boolean preferWildcards() {
			return true;
		}
		
		//returns -1 to expand
		@Override
		public int getLeadingZeros(int segmentIndex) {
			if(expandSegments) {
				return -1;
			}
			return 0;
		}
		
		@Override
		public String getSegmentStrPrefix() {
			return segmentStrPrefix;
		}
		
		public void setSegmentStrPrefix(String segmentStrPrefix) {
			if(segmentStrPrefix == null) {
				throw new NullPointerException();
			}
			this.segmentStrPrefix = segmentStrPrefix;
		}
		
		@Override
		public int getRadix() {
			return radix;
		}
		
		public void setRadix(int radix) {
			this.radix = radix;
		}
		
		public void setUppercase(boolean uppercase) {
			this.uppercase = uppercase;
		}
		
		@Override
		public boolean isUppercase() {
			return uppercase;
		}
		
		public void setSplitDigits(boolean split) {
			this.splitDigits = split;
		}
		
		@Override
		public boolean isSplitDigits() {
			return splitDigits;
		}
		
		@Override
		public Character getSplitDigitSeparator() {
			return separator;
		}
		
		@Override
		public boolean isReverseSplitDigits() {
			return reverse;
		}
		
		public void setReverse(boolean rev) {
			this.reverse = rev;
		}
		
		public boolean isReverse() {
			return reverse;
		}
		
		public void expandSegments(boolean expand) {
			expandSegments = expand;
		}
		
		public StringBuilder appendLabel(StringBuilder builder) {
			String str = getAddressLabel();
			if(str != null && str.length() > 0) {
				builder.append(str);
			}
			return builder;
		}
		
		public int getAddressLabelLength() {
			String str = getAddressLabel();
			if(str != null) {
				return str.length();
			}
			return 0;
		}
		
		public int getSegmentsStringLength(T part) {
			int count = 0;
			if(part.getDivisionCount() != 0) {
				int divCount = part.getDivisionCount();
				for(int i = 0; i < divCount; i++) {
					count += appendSegment(i, null, part);
				}
				Character separator = getSeparator();
				if(separator != null) {
					count += divCount - 1;
				}
			}
			return count;
		}

		public StringBuilder appendSegments(StringBuilder builder, T part) {
			int count = part.getDivisionCount();
			if(count != 0) {
				boolean reverse = isReverse();
				int i = 0;
				Character separator = getSeparator();
				while(true) {
					int segIndex = reverse ? (count - i - 1) : i;
					appendSegment(segIndex, builder, part);
					if(++i == count) {
						break;
					}
					if(separator != null) {
						builder.append(separator);
					}
				}
			}
			return builder;
		}
		
		public int appendSingleDivision(AddressStringDivision seg, StringBuilder builder) {
			if(builder == null) {
				return getAddressLabelLength() + seg.getStandardString(0, this, null);
			}
			appendLabel(builder);
			seg.getStandardString(0, this, builder);
			return 0;
		}
		
		protected int appendSegment(int segmentIndex, StringBuilder builder, T part) {
			AddressStringDivision seg = part.getDivision(segmentIndex);
			return seg.getStandardString(segmentIndex, this, builder);
		}
		
		public int getZoneLength(CharSequence zone) {
			if(zone != null && zone.length() > 0) {
				return zone.length() + 1; /* zone separator is one char */
			}
			return 0;
		}
		
		public int getStringLength(T addr, CharSequence zone) {
			int result = getStringLength(addr);
			if(zone != null) {
				result += getZoneLength(zone);
			}
			return result;
		}
		
		public int getStringLength(T addr) {
			return getAddressLabelLength() + getSegmentsStringLength(addr);
		}
		
		public StringBuilder appendZone(StringBuilder builder, CharSequence zone) {
			if(zone != null && zone.length() > 0) {
				builder.append(zoneSeparator).append(zone);
			}
			return builder;
		}

		public StringBuilder append(StringBuilder builder, T addr, CharSequence zone) {
			return appendZone(appendSegments(appendLabel(builder), addr), zone);
		}
		
		public StringBuilder append(StringBuilder builder, T addr) {
			return append(builder, addr, null);
		}
		
		@Override
		public int getDivisionStringLength(AddressStringDivision seg) {
			return appendSingleDivision(seg, null);
		}
		
		@Override
		public StringBuilder appendDivision(StringBuilder builder, AddressStringDivision seg) {
			appendSingleDivision(seg, builder);
			return builder;
		}

		public String toString(T addr, CharSequence zone) {	
			int length = getStringLength(addr, zone);
			StringBuilder builder = new StringBuilder(length);
			append(builder, addr, zone);
			checkLengths(length, builder);
			return builder.toString();
		}
		
		public String toString(T addr) {	
			return toString(addr, null);
		}
		
		public static void checkLengths(int length, StringBuilder builder) {
			//Note: re-enable this when doing development
//			boolean calcMatch = length == builder.length();
//			boolean capMatch = length == builder.capacity();
//			if(!calcMatch || !capMatch) {
//				//System.out.println(builder);//000a:0000:000c:000d:000e:000f:0001-1:0000/112 instead of 000a:0000:000c:000d:000e:000f:0001:0000/112
//				throw new IllegalStateException("length is " + builder.length() + ", capacity is " + builder.capacity() + ", expected length is " + length);
//			}
		}

		public static AddressStringParams<AddressStringDivisionSeries> toParams(StringOptions opts) {
			//since the params here are not dependent on the section, we could cache the params in the options 
			//this is not true on the IPv6 side where compression settings change based on the section
			@SuppressWarnings("unchecked")
			AddressStringParams<AddressStringDivisionSeries> result = (AddressStringParams<AddressStringDivisionSeries>) getCachedParams(opts);
			if(result == null) {
				result = new AddressStringParams<AddressStringDivisionSeries>(opts.base, opts.separator, opts.uppercase);
				result.expandSegments(opts.expandSegments);
				result.setWildcards(opts.wildcards);
				result.setSegmentStrPrefix(opts.segmentStrPrefix);
				result.setAddressLabel(opts.addrLabel);
				result.setReverse(opts.reverse);
				result.setSplitDigits(opts.splitDigits);
				setCachedParams(opts, result);
			}
			return result;
		}
		
		@Override
		public AddressStringParams<T> clone() {
			try {
				@SuppressWarnings("unchecked")
				AddressStringParams<T> parms = (AddressStringParams<T>) super.clone();
				return parms;
			} catch(CloneNotSupportedException e) {
				 return null;
			}
		}
	}
	
	
	
	/**
	 * Represents a clear way to create a specific type of string.
	 * 
	 * @author sfoley
	 */
	public static class StringOptions {
		
		public static class Wildcards {
			public final String rangeSeparator;//cannot be null
			public final String wildcard;//can be null
			public final String singleWildcard;//can be null
			
			public Wildcards() {
				this(Address.RANGE_SEPARATOR_STR, Address.SEGMENT_WILDCARD_STR, null);
			}
			
			public Wildcards(String wildcard, String singleWildcard) {
				this(Address.RANGE_SEPARATOR_STR, wildcard, singleWildcard);
			}
			
			public Wildcards(String rangeSeparator) {
				this(rangeSeparator, null, null);
			}
			
			public Wildcards(String rangeSeparator, String wildcard, String singleWildcard) {
				if(rangeSeparator == null) {
					rangeSeparator = Address.RANGE_SEPARATOR_STR;
				}
				this.rangeSeparator = rangeSeparator;
				this.wildcard = wildcard;
				this.singleWildcard = singleWildcard;
			}
			
			@Override
			public String toString() {
				return "range separator: " + rangeSeparator + "\nwildcard: " + wildcard + "\nsingle wildcard: " + singleWildcard;
			}
		}
		
		public final Wildcards wildcards;
		public final boolean expandSegments;
		public final int base;
		public final String segmentStrPrefix;
		public final Character separator;
		public final String addrLabel;
		public final boolean reverse;
		public final boolean splitDigits;
		public final boolean uppercase;
		
		//use this field if the options to params conversion is not dependent on the address part so it can be reused
		AddressDivisionWriter cachedParams; 
		
		protected StringOptions(
				int base,
				boolean expandSegments,
				Wildcards wildcards,
				String segmentStrPrefix,
				Character separator,
				String label,
				boolean reverse,
				boolean splitDigits,
				boolean uppercase) {
			this.expandSegments = expandSegments;
			this.wildcards = wildcards;
			this.base = base;
			if(segmentStrPrefix == null) {
				throw new NullPointerException("segment str");
			}
			this.segmentStrPrefix = segmentStrPrefix;
			this.separator = separator;
			if(label == null) {
				throw new NullPointerException("label");
			}
			this.addrLabel = label;
			this.reverse = reverse;
			this.splitDigits = splitDigits;
			this.uppercase = uppercase;
		}
		
		public static class Builder {
			
			public static final Wildcards DEFAULT_WILDCARDS = new Wildcards();
		
			protected Wildcards wildcards = DEFAULT_WILDCARDS;
			protected boolean expandSegments;
			protected int base;
			protected String segmentStrPrefix = "";
			protected Character separator;
			protected String addrLabel = "";
			protected boolean reverse;
			protected boolean splitDigits;
			protected boolean uppercase;
			
			protected Builder(int base, char separator) {
				this.base = base;
				this.separator = separator;
			}
			
			public Builder setWildcards(Wildcards wildcards) {
				this.wildcards = wildcards;
				return this;
			}
			
			public Builder setReverse(boolean reverse) {
				this.reverse = reverse;
				return this;
			}
			
			public Builder setUppercase(boolean uppercase) {
				this.uppercase = uppercase;
				return this;
			}
			public Builder setSplitDigits(boolean splitDigits) {
				this.splitDigits = splitDigits;
				return this;
			}
			
			public Builder setExpandedSegments(boolean expandSegments) {
				this.expandSegments = expandSegments;
				return this;
			}
			
			public Builder setRadix(int base) {
				this.base = base;
				return this;
			}
			
			/*
			 * separates the divisions of the address, typically ':' or '.', but also can be null for no separator
			 */
			public Builder setSeparator(Character separator) {
				this.separator = separator;
				return this;
			}
			
			public Builder setAddressLabel(String label) {
				this.addrLabel = label;
				return this;
			}
			
			public Builder setSegmentStrPrefix(String prefix) {
				this.segmentStrPrefix = prefix;
				return this;
			}
			
			public StringOptions toOptions() {
				return new StringOptions(base, expandSegments, wildcards, segmentStrPrefix, separator, addrLabel, reverse, splitDigits, uppercase);
			}
		}
	}
}
