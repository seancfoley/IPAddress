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

package inet.ipaddr;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.function.Supplier;
import java.util.stream.Stream;

import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork.IPAddressCreator;
import inet.ipaddr.IPAddressSection.IPStringCache;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.format.standard.AddressDivision;
import inet.ipaddr.format.standard.IPAddressDivision;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.format.util.IPAddressStringWriter;
import inet.ipaddr.format.validate.ParsedIPAddress.BitwiseOrer;
import inet.ipaddr.format.validate.ParsedIPAddress.Masker;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * This represents a single segment of an IP address.  For IPv4, segments are 1 byte.  For IPv6, they are two bytes.
 * 
 * IPAddressSegment objects are immutable and thus also thread-safe.
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressSegment extends IPAddressDivision implements AddressSegment {
	
	private static final long serialVersionUID = 4L;
	
	// These two values define the uniqueness of a segment with respect to equality and comparison, while the prefix is ignored as these values encapsulate the range of addresses created by the prefix.
	private final int value; // the lower value of the segment
	private final int upperValue; // the upper value of a CIDR or other type of range, if not a range it is the same as value
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address with the given value.
	 * 
	 * @param value the value of the segment
	 */
	protected IPAddressSegment(int value) {
		if(value < 0) {
			throw new AddressValueException(value);
		}
		this.value = this.upperValue = value;
	}
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address.
	 * 
	 * @param value the value of the segment.
	 * 		If the segmentPrefixLength is non-null, the network prefix of the value is used, and the segment represents all segment values with the same network prefix (all network or subnet segments, in other words).
	 * @param segmentPrefixLength the segment prefix bits, which can be null
	 */
	protected IPAddressSegment(int value, Integer segmentPrefixLength) {
		this(value, value, segmentPrefixLength);
	}
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address that represents a range of values.
	 * 
	 * @param segmentPrefixLength the segment prefix bits, which can be null.  If segmentPrefixLength is non-null, this segment represents a range of segment values with the given network prefix length.
	 * @param lower the lower value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the lower value becomes the smallest value with the same network prefix.
	 * @param upper the upper value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the upper value becomes the largest value with the same network prefix.
	 */
	protected IPAddressSegment(int lower, int upper, Integer segmentPrefixLength) {
		super(segmentPrefixLength);
		if(lower < 0 || upper < 0) {
			throw new AddressValueException(lower < 0 ? lower : upper);
		}
		if(lower > upper) {
			int tmp = lower;
			lower = upper;
			upper = tmp;
		}
		segmentPrefixLength = getSegmentPrefixLength();
		if(segmentPrefixLength == null || segmentPrefixLength >= getBitCount() || !getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			this.value = lower;
			this.upperValue = upper;
		} else {
			int mask = getSegmentNetworkMask(segmentPrefixLength);
			this.value = lower & mask;
			this.upperValue = upper | getSegmentHostMask(segmentPrefixLength);
		}
	}
	
	@Override
	public abstract IPAddressNetwork<?, ?, ?, ?, ?> getNetwork();
	
	public boolean isIPv4() {
		return false;
	}
	
	public boolean isIPv6() {
		return false;
	}
	
	public abstract IPVersion getIPVersion();

	protected static Integer getSplitSegmentPrefix(int bitsPerSegment, Integer networkPrefixLength, int segmentIndex) {
		return IPAddressSection.getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, segmentIndex);
	}
	
	@Override
	protected long getDivisionNetworkMask(int bits) {
		return getSegmentNetworkMask(bits);
	}
	
	@Override
	protected long getDivisionHostMask(int bits) {
		return getSegmentHostMask(bits);
	}
	
	protected abstract int getSegmentNetworkMask(int bits);
	
	protected abstract int getSegmentHostMask(int bits);
	
	@Override
	public int getMinPrefixLengthForBlock() {
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && isPrefixed() && getSegmentPrefixLength() == 0) {
			return 0;
		}
		return super.getMinPrefixLengthForBlock();
	}
	
	public static int getMaxSegmentValue(IPVersion version) {
		return version.isIPv4() ? IPv4Address.MAX_VALUE_PER_SEGMENT : IPv6Address.MAX_VALUE_PER_SEGMENT;
	}

	protected boolean isChangedByPrefix(Integer bits, boolean smallerOnly) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new PrefixLenException(this, bits);
		}
		if(smallerOnly) {
			if(isPrefixed()) {
				return hasBits && bits < getSegmentPrefixLength();
			}
		} else {
			if(isPrefixed()) {
				return !hasBits || bits != getSegmentPrefixLength().intValue();
			}
		}
		return hasBits;
	}

	protected <S extends IPAddressSegment> S toPrefixedSegment(Integer segmentPrefixLength, AddressSegmentCreator<S> creator) {
		int lower = getSegmentValue();
		int upper = getUpperSegmentValue();
		boolean hasBits = (segmentPrefixLength != null);
		if(lower != upper) {
			//note that the case where our segmentPrefix is less than the requested prefix bits has already been accounted for in isNetworkChangedByPrefix
			//so we are not handling that here
			if(!hasBits) {
				return creator.createSegment(lower, upper, null);
			}
			return creator.createSegment(lower, upper, segmentPrefixLength);
		}
		return hasBits ? creator.createSegment(lower, segmentPrefixLength) : creator.createSegment(lower);
	}

	@Override
	public boolean isPrefixBlock() {
		return (isPrefixed() && getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) || super.isPrefixBlock();
	}

	protected boolean isNetworkChangedByPrefix(Integer bits, boolean withPrefixLength) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new PrefixLenException(this, bits);
		}
		withPrefixLength &= hasBits;
		boolean thisHasPrefix = isPrefixed();
		if(withPrefixLength != thisHasPrefix) {
			return true;
		}
		if(!hasBits || bits != getDivisionPrefixLength()) {
			return true;
		}
		return
			//this call differs from the host side.  On the host side, we check that the network portion is 0
			//on the network side, we check that the host side is the full range, not 0.  
			//This means that any resulting network section is the same regardless of whether a prefix is used: we don't need a prefix.
			!containsPrefixBlock(bits);
	}
	
	protected boolean isNetworkChangedByPrefixNonNull(int prefixBitCount) {
		return !isPrefixed() || prefixBitCount != getDivisionPrefixLength() || !containsPrefixBlock(prefixBitCount);
	}
	
	/**
	 * used by constructors of IPAddressSection, see {@link IPAddress#getNetworkSection(int, boolean)}
	 */
	public IPAddressSegment toNetworkSegment(Integer segmentPrefixLength) {
		return toNetworkSegment(segmentPrefixLength, true);
	}
	
	/**
	 * used by getNetworkSection and by constructors of IPAddressSection, see {@link IPAddress#getNetworkSection(int, boolean)}
	 */
	public abstract IPAddressSegment toNetworkSegment(Integer segmentPrefixLength, boolean withPrefixLength);

	protected <S extends IPAddressSegment> S toNetworkSegment(Integer segmentPrefixLength, boolean withPrefixLength, AddressSegmentCreator<S> creator) {
		int newLower = getSegmentValue();
		int newUpper = getUpperSegmentValue();
		boolean hasPrefLen = segmentPrefixLength != null;
		if(hasPrefLen) {
			int mask = getSegmentNetworkMask(segmentPrefixLength);
			newLower &= mask;
			newUpper |= getSegmentHostMask(segmentPrefixLength);
		}
		withPrefixLength = withPrefixLength && hasPrefLen;
		if(newLower != newUpper) {
			//note that the case where our segmentPrefix is less than the requested prefix bits has already been accounted for in isNetworkChangedByPrefix
			//so we are not handling that here
			if(!withPrefixLength) {
				return creator.createSegment(newLower, newUpper, null);
			}
			return creator.createSegment(newLower, newUpper, segmentPrefixLength);
		}
		return withPrefixLength ? creator.createSegment(newLower, segmentPrefixLength) : creator.createSegment(newLower);
	}
	
	/**
	 * used by getHostSection, see {@link IPAddress#getHostSection(int)}
	 */
	public abstract IPAddressSegment toHostSegment(Integer segmentPrefixLength);
	
	protected <S extends IPAddressSegment> S toHostSegment(Integer segmentPrefixLength, AddressSegmentCreator<S> creator) {
		// We need to use Masker:
		// For example, ipv4 0-4, masking with prefix length 7, should become 0-1, not 0-0
		// So you cannot do a straight mask of 0 and 4.
		int mask = (segmentPrefixLength == null) ? 0 : getSegmentHostMask(segmentPrefixLength);
		int lower = getSegmentValue();
		int upper = getUpperSegmentValue();
		Masker masker = maskRange(lower, upper, mask, getMaxValue());
		int newLower = (int) masker.getMaskedLower(lower, mask);
		int newUpper = (int) masker.getMaskedUpper(upper, mask);
		if(newLower != newUpper) {
			return creator.createSegment(newLower, newUpper, null);
		}
		return creator.createSegment(newLower);
	}
	
	protected boolean isHostChangedByPrefix(Integer bits) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new PrefixLenException(this, bits);
		}
		//a host segment has no prefix, so if this remains unchanged it must have no prefix length
		if(isPrefixed()) {
			return true;
		}
		int mask = !hasBits ? 0 : getSegmentHostMask(bits);
		//additionally, the value must match the value for the given network prefix length
		int value = getSegmentValue();
		int upperValue = getUpperSegmentValue();
		return value != (value & mask) || upperValue != (upperValue & mask);
	}
	
	protected boolean isChangedBy(int newValue, int newUpperValue, Integer segmentPrefixLength) throws IncompatibleAddressException {
		int value = getSegmentValue();
		int upperValue = getUpperSegmentValue();
		return value != newValue ||
				upperValue != newUpperValue ||
						(isPrefixed() ? !getSegmentPrefixLength().equals(segmentPrefixLength) : (segmentPrefixLength != null));
	}
	
	protected static Masker maskRange(long value, long upperValue, long maskValue, long maxValue) {
		return AddressDivision.maskRange(value, upperValue, maskValue, maxValue);
	}
	
	public MaskResult maskRange(int maskValue) {
		int value = getSegmentValue();
		int upperValue = getUpperSegmentValue();
		Masker masker = AddressDivision.maskRange(value, upperValue, maskValue, getMaxSegmentValue());
		return new MaskResult(value, upperValue, maskValue, masker);
	}
	
	protected static BitwiseOrer bitwiseOrRange(long value, long upperValue, long maskValue, long maxValue) {
		return AddressDivision.bitwiseOrRange(value, upperValue, maskValue, maxValue);
	}

	public BitwiseOrResult bitwiseOrRange(int maskValue) {
		int value = getSegmentValue();
		int upperValue = getUpperSegmentValue();
		BitwiseOrer orer = AddressDivision.bitwiseOrRange(value, upperValue, maskValue, getMaxSegmentValue());
		return new BitwiseOrResult(value, upperValue, maskValue, orer);
	}
	
	/**
	 * If this segment represents a range of values, returns a segment representing just the lowest value in the range, otherwise returns this.
	 * @return
	 */
	@Override
	public abstract IPAddressSegment getLower();
	
	/**
	 * If this segment represents a range of values, returns a segment representing just the highest value in the range, otherwise returns this.
	 * @return
	 */
	@Override
	public abstract IPAddressSegment getUpper();
	
	protected static <S extends IPAddressSegment> S getLowestOrHighest(S original, AddressSegmentCreator<S> segmentCreator, boolean lowest) {
		boolean isAllSubnets = original.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		if(!original.isMultiple() && !(isAllSubnets && original.isPrefixed())) {
			return original;
		}
		return segmentCreator.createSegment(lowest ? original.getSegmentValue() : original.getUpperSegmentValue(), 
				isAllSubnets ? null : original.getSegmentPrefixLength());
	}

	@Override
	public abstract Iterable<? extends IPAddressSegment> getIterable();

	@Override
	public abstract Iterator<? extends IPAddressSegment> iterator();

	@Override
	public abstract AddressComponentSpliterator<? extends IPAddressSegment> spliterator();

	@Override
	public abstract Stream<? extends IPAddressSegment> stream();

	/**
	 * Iterates through the individual prefix blocks.
	 * <p>
	 * If the series has no prefix length, then this is equivalent to {@link #iterator()}
	 */
	public abstract Iterator<? extends IPAddressSegment> prefixBlockIterator();

	/**
	 * Partitions and traverses through the individual prefix blocks of this segment for its prefix length.
	 * 
	 * @return
	 */
	public abstract AddressComponentSpliterator<? extends IPAddressSegment> prefixBlockSpliterator();

	/**
	 * Returns a sequential stream of the individual prefix blocks of this segment.  For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @return
	 */
	public abstract Stream<? extends IPAddressSegment> prefixBlockStream();

	/**
	 * Iterates through the individual prefixes.
	 * <p>
	 * If the series has no prefix length, then this is equivalent to {@link #iterator()}
	 */
	public abstract Iterator<? extends IPAddressSegment> prefixIterator();

	/**
	 * Partitions and traverses through the individual prefixes of this segment for its prefix length.
	 * 
	 * @return
	 */
	public abstract AddressComponentSpliterator<? extends IPAddressSegment> prefixSpliterator();

	protected static <S extends IPAddressSegment> AddressComponentSpliterator<S> prefixSpliterator(
			S seg, int segPrefLength,
			IPAddressCreator<?, ?, ?, S, ?> creator,
			Supplier<Iterator<S>> iteratorProvider) {
		int bitCount = seg.getBitCount();
		int shiftAdjustment = bitCount - segPrefLength;
		int shiftMask, upperShiftMask;
		if(shiftAdjustment > 0) {
			shiftMask = ~0 << shiftAdjustment;
			upperShiftMask = ~shiftMask;
		} else {
			shiftMask = ~0;
			upperShiftMask = 0;
		}
		int originalValue = seg.getSegmentValue();
		int originalUpperValue = seg.getUpperSegmentValue();
		int originalValuePrefix = originalValue >>> shiftAdjustment;
		int originalUpperValuePrefix = originalUpperValue >>> shiftAdjustment;
		Integer segPrefixLength = IPAddressSection.cacheBits(segPrefLength);
		IntBinaryIteratorProvider<S> subIteratorProvider = (isLowest, isHighest, value, upperValue) -> {
			if(isLowest || isHighest) {
				value = isLowest ? originalValue : value << shiftAdjustment;
				upperValue = isHighest ?  originalUpperValue : ((upperValue << shiftAdjustment) | upperShiftMask);
				return iterator(null, value, upperValue, bitCount, creator, segPrefixLength, true, false);
			}
			return iterator(null, value << shiftAdjustment, upperValue << shiftAdjustment, bitCount, creator, segPrefixLength, true, true);
		};
		return createSegmentSpliterator(
				seg,
				originalValuePrefix,
				originalUpperValuePrefix,
				iteratorProvider,
				subIteratorProvider,
				(value, upperValue) -> {
					value = (value == originalValuePrefix) ? originalValue : value << shiftAdjustment;
					upperValue = (upperValue == originalUpperValuePrefix) ? 
							originalUpperValue : ((upperValue << shiftAdjustment) | upperShiftMask);
					return creator.createSegment(value, upperValue, segPrefLength);
				});
	}

	/**
	 * Returns a sequential stream of the individual prefixes of this segment.  For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @return
	 */
	public abstract Stream<? extends IPAddressSegment> prefixStream();

	/**
	 * Iterates through the individual prefix blocks according to the given segment prefix length.
	 * Any existing prefix length is disregarded.
	 */
	public abstract Iterator<? extends IPAddressSegment> prefixBlockIterator(int prefixLength);
	
	protected static <S extends IPAddressSegment> AddressComponentSpliterator<S> prefixBlockSpliterator(
			S seg, int segPrefLength,
			IPAddressCreator<?, ?, ?, S, ?> creator,
			Supplier<Iterator<S>> iteratorProvider) {
		int bitCount = seg.getBitCount();
		int shiftAdjustment = bitCount - segPrefLength;
		int shiftMask, upperShiftMask;
		if(shiftAdjustment > 0) {
			shiftMask = ~0 << shiftAdjustment;
			upperShiftMask = ~shiftMask;
		} else {
			shiftMask = ~0;
			upperShiftMask = 0;
		}
		Integer segmentPrefixLength = IPAddressSection.cacheBits(segPrefLength);
		return createSegmentSpliterator(
				seg,
				seg.getSegmentValue() >>> shiftAdjustment,
				seg.getUpperSegmentValue() >>> shiftAdjustment,
				iteratorProvider,
				(isLowest, isHighest, value, upperValue) -> iterator(
							null,
							value << shiftAdjustment,
							(upperValue << shiftAdjustment) | upperShiftMask,
							bitCount,
							creator,
							segmentPrefixLength,
							true,
							true),
				(value, upperValue) -> creator.createSegment(
						value << shiftAdjustment,
						(upperValue << shiftAdjustment) | upperShiftMask,
						segmentPrefixLength));
	}

	/**
	 * Partitions and traverses through the individual prefix blocks for the given prefix length.
	 * 
	 * @return
	 */
	public abstract AddressComponentSpliterator<? extends IPAddressSegment> prefixBlockSpliterator(int prefixLength);

	/**
	 * Returns a sequential stream of the individual prefix blocks for the given prefix length.  For a parallel stream, call {@link Stream#parallel()} on the returned stream.
	 * 
	 * @return
	 */
	public abstract Stream<? extends IPAddressSegment> prefixBlockStream(int prefixLength);

	public static int getBitCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BITS_PER_SEGMENT : IPv6Address.BITS_PER_SEGMENT;
	}

	public static int getByteCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BYTES_PER_SEGMENT : IPv6Address.BYTES_PER_SEGMENT;
	}

	public static int getDefaultTextualRadix(IPVersion version) {
		return version.isIPv4() ? IPv4Address.DEFAULT_TEXTUAL_RADIX : IPv6Address.DEFAULT_TEXTUAL_RADIX;
	}

	@Override
	public boolean matches(int value) {
		return super.matches(value);
	}
	
	public boolean matchesWithPrefixMask(int value, Integer segmentPrefixLength) {
		return super.matchesWithPrefixMask(value, segmentPrefixLength);
	}
	
	@Override
	public boolean matchesWithMask(int value, int mask) {
		return super.matchesWithMask(value, mask);
	}
	
	@Override
	public boolean matchesWithMask(int lowerValue, int upperValue, int mask) {
		return super.matchesWithMask(lowerValue, upperValue, mask);
	}
	
	/**
	 * @return the same value as {@link #getCount()} as an integer
	 */
	@Override
	public int getValueCount() {
		return getUpperSegmentValue() - getSegmentValue() + 1;
	}
	
	/**
	 * Counts the number of prefixes in this address segment.
	 * <p>
	 * If this segment has no prefix length, this is equivalent to {@link #getValueCount()}
	 * 
	 * @return
	 */
	public int getPrefixValueCount() {
		Integer prefixLength = getSegmentPrefixLength();
		if(prefixLength == null) {
			return (int) getValueCount();
		}
		return getPrefixValueCount(this, prefixLength);
	}
	
	@Override
	public BigInteger getCount() {
		return BigInteger.valueOf(getValueCount());
	}
	
	@Override
	public BigInteger getPrefixCount(int segmentPrefixLength) {
		return BigInteger.valueOf(getPrefixValueCount(segmentPrefixLength));
	}
	
	@Override
	public int getPrefixValueCount(int segmentPrefixLength) {
		if(segmentPrefixLength < 0) {
			throw new PrefixLenException(this, segmentPrefixLength);
		}
		int bitCount = getBitCount();
		if(bitCount <= segmentPrefixLength) {
			return getValueCount();
		}
		int shiftAdjustment = bitCount - segmentPrefixLength;
		return (getUpperSegmentValue() >>> shiftAdjustment) - (getSegmentValue() >>> shiftAdjustment) + 1;
	}

	protected int highByte() {
		return highByte(getSegmentValue());
	}
	
	protected int lowByte() {
		return lowByte(getSegmentValue());
	}
	
	protected static int highByte(int value) {
		return value >> 8;
	}
	
	protected static int lowByte(int value) {
		return value & 0xff;
	}
	
	@Override
	public long getMaxValue() {
		return getMaxSegmentValue();
	}

	@Override
	public boolean isMultiple() {
		return getSegmentValue() != getUpperSegmentValue();
	}
	
	/**
	 * returns the lower value
	 */
	@Override
	public int getSegmentValue() {
		return value;
	}
	
	/**
	 * returns the upper value
	 */
	@Override
	public int getUpperSegmentValue() {
		return upperValue;
	}
	
	/**
	 * returns the lower value as a long, although for individual segments {@link #getSegmentValue()} provides the same value as an int
	 */
	@Override
	public long getDivisionValue() {
		return getSegmentValue();
	}
	
	/**
	 * returns the lower upper value as a long, although for individual segments {@link #getUpperSegmentValue()} provides the same value as an int
	 */
	@Override
	public long getUpperDivisionValue() {
		return getUpperSegmentValue();
	}
	
	@Override
	public abstract IPAddressSegment reverseBits(boolean perByte);
	
	@Override
	public abstract IPAddressSegment reverseBytes();

	/**
	 * @deprecated use {@link #withoutPrefixLength()} and {@link #toZeroHost()}
	 * @return
	 */
	@Deprecated
	public abstract IPAddressSegment removePrefixLength();

	/**
	 * Returns a segment with the same network bits as this segment, 
	 * but with the host bits changed to 0.
	 * <p>
	 * If there is no prefix length associated with this segment, returns an all-zero segment.
	 * <p>
	 * This is nearly equivalent to doing the mask (see {@link #maskRange(int)}) of this segment
	 * with the network mask for the given prefix length,
	 * but when applying a mask to a range of values you can have a non-sequential result.
	 * <p>
	 * With this method, if the resulting series has a range of values, 
	 * then the resulting series range boundaries will have host values of 0, 
	 * but not necessarily all the intervening values.
	 * <p>
	 * For instance, the 1-byte segment range 4-7 with prefix length 6, 
	 * when masked with 252 (the network mask) results in just the single value 4, matching the result of this method.
	 * The 1-byte segment range 4-8 with prefix length 6, 
	 * when masked with 252 results in the two non-sequential values, 4 and 8, 
	 * but the result of this method with prefix length 6 results in the range 4-8, the same as the original segment.
	 * <p>
	 * The default behaviour is that the resultant series will have the same prefix length.
	 * The resultant series will not have a prefix length if {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()} is {@link inet.ipaddr.AddressNetwork.PrefixConfiguration#ALL_PREFIXED_ADDRESSES_ARE_SUBNETS}. 
	 *
	 * @return
	 */
	public abstract IPAddressSegment toZeroHost();

	/**
	 * @deprecated use {@link #toZeroHost()} and {@link #withoutPrefixLength()}
	 * @param zeroed
	 * @return
	 */
	@Deprecated
	public abstract IPAddressSegment removePrefixLength(boolean zeroed);

	/**
	 * Returns a segment with the same values but without a prefix length.
	 * 
	 * @return
	 */
	public abstract IPAddressSegment withoutPrefixLength();
	
	protected static <S extends IPAddressSegment> S toZeroHost(S original, AddressSegmentCreator<S> creator) {
		if(original.isPrefixed()) {
			int lower = original.getSegmentValue();
			int upper = original.getUpperSegmentValue();
			Integer segmentPrefixLength = original.getSegmentPrefixLength();
			int mask = original.getSegmentNetworkMask(segmentPrefixLength);
			int newLower = lower & mask;
			int newUpper = upper & mask;
			boolean allPrefsSubnets = original.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
			if(allPrefsSubnets) {
				return creator.createSegment(newLower, newUpper, null);
			}
			if(newLower == lower && newUpper == upper) {
				return original;
			}
			return creator.createSegment(newLower, newUpper, segmentPrefixLength);
		} else if(original.isZero()) {
			return original;
		}
		return creator.createSegment(0, null);
	}
	
	protected static <S extends IPAddressSegment> S removePrefix(S original, boolean zeroed, AddressSegmentCreator<S> creator) {
		if(original.isPrefixed()) {
			int lower = original.getSegmentValue();
			int upper = original.getUpperSegmentValue();
			if(zeroed) {
				int maskBits = original.getSegmentNetworkMask(original.getSegmentPrefixLength());
				long value = original.getDivisionValue();
				long upperValue = original.getUpperDivisionValue();
				long maxValue = original.getMaxValue();
				Masker masker = maskRange(value, upperValue, maskBits, maxValue);
				if(!masker.isSequential()) {
					throw new IncompatibleAddressException(original, maskBits, "ipaddress.error.maskMismatch");
				}
				return creator.createSegment((int) masker.getMaskedLower(lower, maskBits), (int) masker.getMaskedUpper(upper, maskBits), null);
			}
			return creator.createSegment(lower, upper, null);
		}
		return original;
	}
	
	@Override
	public boolean isBoundedBy(int value) {
		return getUpperSegmentValue() < value;
	}
	
	public Integer getSegmentPrefixLength() {
		return getDivisionPrefixLength();
	}
	
	@Override
	public int hashCode() {
		return hash(getSegmentValue(), getUpperSegmentValue(), getBitCount());
	}
	
	static int hash(int lower, int upper, int bitCount) {
		return lower | (upper << bitCount);
	}

	protected boolean isSameValues(AddressSegment otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return getSegmentValue() == otherSegment.getSegmentValue() && getUpperSegmentValue() == otherSegment.getUpperSegmentValue();
	}

	public boolean prefixEquals(IPAddressSegment other) {
		Integer prefLength = getSegmentPrefixLength();
		if(prefLength == null) {
			return equals(other);
		}
		return prefixEquals(other, prefLength);
	}
	
	@Override
	public boolean prefixEquals(AddressSegment other, int prefixLength) {
		if(prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
		int shift = getBitCount() - prefixLength;
		if(shift <= 0) {
			return isSameValues(other);
		}
		return (other.getSegmentValue() >>> shift) == (getSegmentValue() >>> shift) && 
				(other.getUpperSegmentValue() >>> shift) == (getUpperSegmentValue() >>> shift);
	}
	
	/**
	 * Using the prefix length of this segment, or the whole segment if it has no prefix length,
	 * returns whether the prefix bit value ranges contain the same bits of the given segment.
	 * 
	 * 
	 * @param other
	 * @return
	 */
	public boolean prefixContains(IPAddressSegment other) {
		Integer prefLength = getSegmentPrefixLength();
		if(prefLength == null) {
			return equals(other);
		}
		return prefixContains(other, prefLength);
	}
	
	/**
	 * Returns whether the given prefix bit value ranges contain the same bits of the given segment.
	 * 
	 * @param other
	 * @param prefixLength
	 * @return
	 */
	public boolean prefixContains(IPAddressSegment other, int prefixLength) {
		if(prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
		int shift = getBitCount() - prefixLength;
		if(shift <= 0) {
			return contains(other);
		}
		return (other.getSegmentValue() >>> shift) >= (getSegmentValue() >>> shift) && 
				(other.getUpperSegmentValue() >>> shift) <= (getUpperSegmentValue() >>> shift);
	}

	/**
	 * 
	 * @param other
	 * @return whether this subnet segment contains the given address segment
	 */
	protected boolean containsSeg(AddressSegment other) {
		return other.getSegmentValue() >= getSegmentValue() && other.getUpperSegmentValue() <= getUpperSegmentValue();
	}

	@Override
	public boolean includesZero() {
		return getSegmentValue() == 0;
	}
	
	@Override
	public boolean includesMax() {
		return getUpperSegmentValue() == getMaxSegmentValue();
	}
	
	boolean containsPrefixBlock(int lowerVal, int upperVal, int divisionPrefixLen) {
		return isPrefixBlock(lowerVal, upperVal, divisionPrefixLen);
	}
	
	boolean containsSinglePrefixBlock(int lowerVal, int upperVal, int divisionPrefixLen) {
		return isSinglePrefixBlock(lowerVal, upperVal, divisionPrefixLen);
	}

	@Override
	protected String getDefaultSegmentWildcardString() {
		return Address.SEGMENT_WILDCARD_STR;
	}

	@Override
	public String toHexString(boolean with0xPrefix) {
		return toNormalizedString(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams);
	}

	@Override
	public String toNormalizedString() {
		return toNormalizedString(IPStringCache.canonicalSegmentParams);
	}

	public String toNormalizedString(IPStringOptions options) {
		IPAddressStringWriter<IPAddressStringDivisionSeries> params =  IPAddressSection.toIPParams(options);
		StringBuilder builder = new StringBuilder(params.getDivisionStringLength(this));
		return params.appendDivision(builder, this).toString();
	}
	
	protected static int toUnsignedStringLength(int value, int radix) {
		return AddressDivision.toUnsignedStringLength(value, radix);
	}
	
	protected static StringBuilder toUnsignedString(int value, int radix, StringBuilder appendable) {
		return toUnsignedStringCased(value, radix, 0, false, appendable);
	}

	void setStandardString(
			CharSequence addressStr, 
			boolean isStandardString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int originalLowerValue) {
		if(cachedString == null && isStandardString && originalLowerValue == getDivisionValue()) {
			cachedString = addressStr.subSequence(lowerStringStartIndex, lowerStringEndIndex).toString();
		}
	}

	void setWildcardString(
			CharSequence addressStr, 
			boolean isStandardString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int lowerValue) {
		if(cachedWildcardString == null && isStandardString && lowerValue == getDivisionValue() && lowerValue == getUpperDivisionValue()) {
			cachedWildcardString = addressStr.subSequence(lowerStringStartIndex, lowerStringEndIndex).toString();
		}
	}
	
	void setStandardString(
			CharSequence addressStr, 
			boolean isStandardString,
			boolean isStandardRangeString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int upperStringEndIndex,
			int rangeLower,
			int rangeUpper) {
		if(cachedString == null) {
			if(isSinglePrefixBlock()) {
				if(isStandardString && rangeLower == getDivisionValue()) {
					cachedString = addressStr.subSequence(lowerStringStartIndex, lowerStringEndIndex).toString();
				}
			} else if(isFullRange()) {
				cachedString = IPAddress.SEGMENT_WILDCARD_STR;
			} else if(isStandardRangeString && rangeLower == getDivisionValue()) {
				long upper = getUpperDivisionValue();
				if(isPrefixed()) {
					upper &= getDivisionNetworkMask(getDivisionPrefixLength());
				}
				if(rangeUpper == upper) {
					cachedString = addressStr.subSequence(lowerStringStartIndex, upperStringEndIndex).toString();
				}
			}
		}
	}
	
	void setWildcardString(
			CharSequence addressStr, 
			boolean isStandardRangeString,
			int lowerStringStartIndex,
			int upperStringEndIndex,
			int rangeLower,
			int rangeUpper) {
		if(cachedWildcardString == null) {
			if(isFullRange()) {
				cachedWildcardString = IPAddress.SEGMENT_WILDCARD_STR;
			} else if(isStandardRangeString && rangeLower == getDivisionValue() && rangeUpper == getUpperDivisionValue()) {
				cachedWildcardString = addressStr.subSequence(lowerStringStartIndex, upperStringEndIndex).toString();
			}
		}
	}
}
