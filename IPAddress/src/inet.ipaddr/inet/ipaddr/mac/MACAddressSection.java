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

package inet.ipaddr.mac;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import inet.ipaddr.Address;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressPositionException;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.AddressDivisionGroupingBase;
import inet.ipaddr.format.standard.AddressBitsDivision;
import inet.ipaddr.format.standard.AddressDivision;
import inet.ipaddr.format.standard.AddressDivisionGrouping;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.string.AddressStringDivisionSeries;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;

public class MACAddressSection extends AddressDivisionGrouping implements AddressSection, Iterable<MACAddressSection> {

	private static final long serialVersionUID = 4L;
	
	private static final long MAX_VALUES_LONG[] = new long[] {
			0,
			MACAddress.MAX_VALUE_PER_SEGMENT,
			0xffff,
			0xffffff,
			0xffffffffL,
			0xffffffffffL,
			0xffffffffffffL,
			0xffffffffffffffL};

	private static final BigInteger MAX_VALUES[] = new BigInteger[] {
			BigInteger.ZERO,
			BigInteger.valueOf(MAX_VALUES_LONG[1]),
			BigInteger.valueOf(MAX_VALUES_LONG[2]),
			BigInteger.valueOf(MAX_VALUES_LONG[3]),
			BigInteger.valueOf(MAX_VALUES_LONG[4]),
			BigInteger.valueOf(MAX_VALUES_LONG[5]),
			BigInteger.valueOf(MAX_VALUES_LONG[6]),
			BigInteger.valueOf(MAX_VALUES_LONG[7]),
			BigInteger.valueOf(1).shiftLeft(64).subtract(BigInteger.ONE),
	};

	/* the various string representations - these fields are for caching */
	protected static class MACStringCache extends StringCache {
		static final StringOptions hexParams;
		static final StringOptions hexPrefixedParams;
		static final StringOptions canonicalParams;//uses the '-' as separator and '|' as range indicator
		static final StringOptions compressedParams;
		static final StringOptions normalizedParams;//uses the ':' as separator
		static final StringOptions dottedParams;
		static final StringOptions spaceDelimitedParams;
		
		static {
			hexParams = new MACStringOptions.Builder().setSeparator(null).setExpandedSegments(true).setRadix(16).toOptions();
			hexPrefixedParams = new MACStringOptions.Builder().setSeparator(null).setExpandedSegments(true).setRadix(16).setAddressLabel(MACAddress.HEX_PREFIX).toOptions();
			normalizedParams = new MACStringOptions.Builder().setSeparator(MACAddress.COLON_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toOptions();
			canonicalParams = new MACStringOptions.Builder().setSeparator(MACAddress.DASH_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).setWildcards(new Wildcards(MACAddress.DASHED_SEGMENT_RANGE_SEPARATOR_STR, Address.SEGMENT_WILDCARD_STR, null)).toOptions();
			compressedParams = new MACStringOptions.Builder().setSeparator(MACAddress.COLON_SEGMENT_SEPARATOR).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toOptions();
			dottedParams = new MACStringOptions.Builder().setSeparator(MACAddress.DOTTED_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toOptions();
			spaceDelimitedParams = new MACStringOptions.Builder().setSeparator(MACAddress.SPACE_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toOptions();
		}
		
		public String compressedString;
		public String normalizedString;
		public String dottedString;
		public String spaceDelimitedString;
	}
	
	static class AddressCache extends SectionCache<MACAddress> {}
	
	private static MACAddressCreator creators[][] = new MACAddressCreator[2][MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT];
	
	private transient MACStringCache stringCache;
	
	private transient SectionCache<MACAddressSection> sectionCache;
	
	/*
	 * Indicates the index of the first segment where this section would be located in a full address.  0 for oui sections or full addresses
	 */
	public final int addressSegmentIndex;

	/*
	 * Indicates whether this is part of an extended address.  An extended address is 64 bits, otherwise it is 48 bits.
	 */
	public final boolean extended;	

	/**
	 * Constructs a single segment section, the segment being the leading segment.
	 * 
	 * @param segment
	 */
	public MACAddressSection(MACAddressSegment segment) {
		super(new MACAddressSegment[] {segment});
		this.addressSegmentIndex = 0;
		this.extended = false;
	}
	
	/**
	 * Constructs a single segment section with the segment at the given index in the address.
	 * 
	 * @param segment
	 */
	public MACAddressSection(MACAddressSegment segment, int startIndex, boolean extended) {
		this(false, new MACAddressSegment[] {segment}, startIndex, extended);
	}
	
	/**
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(MACAddressSegment segments[]) {
		this(segments, 0, segments.length > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT);
	}
	
	public MACAddressSection(MACAddressSegment segments[], int startIndex, boolean extended) {
		this(true, segments, startIndex, extended);
	}

	protected MACAddressSection(boolean cloneSegments, MACAddressSegment segments[], int startIndex, boolean extended) {
		super(cloneSegments ? segments.clone() : segments);
		addressSegmentIndex = startIndex;
		this.extended = extended;
		if(startIndex < 0 || startIndex > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressPositionException(startIndex);
		} else if(startIndex + segments.length > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressValueException(segments.length);
		}
	}

	public MACAddressSection(SegmentValueProvider valueProvider) {
		this(valueProvider, valueProvider, 0, false);
	}
	
	public MACAddressSection(SegmentValueProvider valueProvider, int startIndex, boolean extended) {
		this(valueProvider, valueProvider, startIndex, extended);
	}
	
	public MACAddressSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, int startIndex, boolean extended) {
		super(new MACAddressSegment[Math.max(0, (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT) - startIndex)], false);
		createSegments(
				getSegmentsInternal(),
				lowerValueProvider,
				upperValueProvider,
				MACAddress.BYTES_PER_SEGMENT,
				MACAddress.BITS_PER_SEGMENT,
				getNetwork(),
				null);
		if(startIndex < 0 || startIndex > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressPositionException(startIndex);
		}
		this.addressSegmentIndex = startIndex;
		this.extended = extended;
	}

	protected MACAddressSection(byte bytes[], int segmentCount, int startIndex, boolean extended, boolean cloneBytes) {
		this(bytes, 0, bytes.length, segmentCount, startIndex, extended, cloneBytes);
	}

	protected MACAddressSection(byte bytes[], int byteStartIndex, int byteEndIndex, int segmentCount, int startIndex, boolean extended, boolean cloneBytes) {
		super(new MACAddressSegment[segmentCount >= 0 ? segmentCount : Math.max(0, byteEndIndex - byteStartIndex)], false);
		MACAddressSegment segs[] = getSegmentsInternal();
		toSegments(
				segs,
				bytes,
				byteStartIndex,
				byteEndIndex,
				MACAddress.BYTES_PER_SEGMENT,
				MACAddress.BITS_PER_SEGMENT,
				getNetwork(),
				null);
		if(startIndex < 0 || startIndex > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressPositionException(startIndex);
		}
		this.addressSegmentIndex = startIndex;
		this.extended = extended;
		if(bytes.length == segs.length) {
			setBytes(cloneBytes ? bytes.clone() : bytes);
		}
	}
	
	/*
	 * Use this constructor for any section that is part of a 64-bit EUI address,
	 * or for any section that you wish to start in the middle of a MAC address.
	 */
	public MACAddressSection(byte bytes[], int startIndex, boolean extended) {
		this(bytes, 0, bytes.length, -1, startIndex, extended, true);
	}
	
	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(byte bytes[]) {
		this(bytes, 0, bytes.length >  MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT);
	}

	public MACAddressSection(long value, int startIndex, boolean extended) {
		super(new MACAddressSegment[extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT], false);
		if(startIndex < 0 || startIndex > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressPositionException(startIndex);
		} else if(!extended && (value > 0xffffffffffffL || value < 0L)) {
			throw new AddressValueException(value);
		}
		createSegments(
				getSegmentsInternal(),
				0,
				value,
				MACAddress.BITS_PER_SEGMENT,
				getNetwork(),
				null);
		this.addressSegmentIndex = startIndex;
		this.extended = extended;
	}

	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(long value) {
		this(value, 0, false);
	}
	
	@Override
	public MACAddressNetwork getNetwork() {
		return MACAddress.defaultMACNetwork();
	}
	
	public IPv6AddressNetwork getIPv6Network() {
		return MACAddress.defaultIpv6Network();
	}
	
	protected MACAddressCreator getAddressCreator(int startIndex, boolean extended) {
		MACAddressCreator creator = null;
		boolean useCached = startIndex < MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT;
		int ext = 0;
		if(useCached) {
			if(extended) {
				ext = 1;
			}
			creator = creators[ext][startIndex];
		}
		if(creator != null) {
			useCached |= creator.getNetwork().equals(getNetwork());
			if(useCached) {
				return creator;
			}
		}
		creator = new MACAddressCreator(getNetwork()) {
			private static final long serialVersionUID = 4L;

			@Override
			protected MACAddressSection createSectionInternal(MACAddressSegment segments[]) {
				return getNetwork().getAddressCreator().createSectionInternal(segments, startIndex, extended);
			}
			
		};
		if(useCached) {
			creators[ext][startIndex] = creator;
		}
		return creator;
	}
	
	MACAddressCreator getAddressCreator() {
		return getAddressCreator(addressSegmentIndex, extended);
	}

	private AddressSegmentCreator<MACAddressSegment> getSegmentCreator() {
		return getAddressCreator(0, false);
	}
	
	@Override
	protected boolean isSameGrouping(AddressDivisionGroupingBase other) {
		return other instanceof MACAddressSection && super.isSameGrouping(other);
	}

	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof MACAddressSection) {
			MACAddressSection other = (MACAddressSection) o;
			return addressSegmentIndex == other.addressSegmentIndex && isExtended() == other.isExtended() && other.isSameGrouping(this);
		}
		return false;
	}
	
	protected MACStringCache getStringCache() {
		return (MACStringCache) stringCache;
	}

	@Override
	public MACAddressSegment[] getSegments() {
		return (MACAddressSegment[]) getDivisionsInternal().clone();
	}
	
	@Override
	public void getSegments(AddressSegment segs[]) {
		getSegments(0, getDivisionCount(), segs, 0);
	}
	
	protected MACAddressSegment[] getSegmentsInternal() {
		return (MACAddressSegment[]) super.getDivisionsInternal();
	}
	
	@Override
	public void getSegments(int start, int end, AddressSegment segs[], int destIndex) {
		System.arraycopy(getSegmentsInternal(), start, segs, destIndex, end - start);
	}
	
	/**
	 * @return whether this section is part of a larger EUI-64 address.
	 */
	public boolean isExtended() {
		return extended;
	}
	
	@Override
	public int getSegmentCount() {
		return getDivisionCount();
	}
	
	public boolean isEntireAddress(boolean extended) {
		return getSegmentCount() == (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT);
	}
	
	@Override
	public MACAddressSegment getDivision(int index) {
		return (MACAddressSegment) super.getDivision(index);
	}
	
	@Override
	public MACAddressSegment getSegment(int index) {
		return (MACAddressSegment) super.getDivision(index);
	}

	public void getSegments(Collection<? super MACAddressSegment> segs) {
		getSegments(0, getSegmentCount(), segs);
	}

	public void getSegments(int start, int end, Collection<? super MACAddressSegment> segs) {
		for(int i = start; i < end; i++) {
			segs.add(getSegment(i));
		}
	}

	@Override
	public int getMaxSegmentValue() {
		return MACAddress.MAX_VALUE_PER_SEGMENT;
	}
	
	@Override
	public int getBitsPerSegment() {
		return MACAddress.BITS_PER_SEGMENT;
	}
	
	@Override
	public int getBytesPerSegment() {
		return MACAddress.BYTES_PER_SEGMENT;
	}
	
	@Override
	public int getByteCount() {
		return getSegmentCount(); //MACAddress.BYTES_PER_SEGMENT is 1
	}
	
	@Override
	public int getBitCount() {
		return getSegmentCount() << 3;//MACAddress.BITS_PER_SEGMENT is 8
	}
	
	@Override
	protected byte[] getBytesImpl(boolean low) {
		int segmentCount = getSegmentCount();
		byte bytes[] = new byte[segmentCount];
		for(int i = 0; i < segmentCount; i++) {
			MACAddressSegment seg = getSegment(i);
			int val = low ? seg.getSegmentValue() : seg.getUpperSegmentValue();
			bytes[i] = (byte) val;
		}
		return bytes;
	}
	
	@Override
	protected BigInteger getCountImpl() {
		return getCountImpl(getSegmentCount());
	}
	
	private BigInteger getCountImpl(int segCount) {
		if(!isMultiple()) {
			return BigInteger.ONE;
		}
		long result = getSegment(0).getValueCount();
		int limit = Math.min(segCount, 7);
		for(int i = 1; i < limit; i++) {
			result *= getSegment(i).getValueCount();
		}
		if(segCount == 8) {
			long lastValue = getSegment(7).getValueCount();
			if(lastValue != 1) {
				if(result <= 0x7fffffffffffffL) {
					result *= lastValue;
				} else {
					return BigInteger.valueOf(result).multiply(BigInteger.valueOf(lastValue));
				}
			}
		}
		return BigInteger.valueOf(result);
	}
	
	@Override
	public BigInteger getBlockCount(int segmentCount) {
		if(segmentCount < 0) {
			throw new IllegalArgumentException();
		}
		int segCount = getSegmentCount();
		if(segmentCount > segCount) {
			segmentCount = segCount;
		}
		return getCountImpl(segmentCount);
	}
	
	@Override
	public BigInteger getPrefixCount(int prefixLength) {
		checkSubnet(this, prefixLength);
		if(isMultiple()) {
			long result = 1;
			int networkSegmentIndex = getNetworkSegmentIndex(prefixLength, MACAddress.BYTES_PER_SEGMENT, MACAddress.BITS_PER_SEGMENT);
			int hostSegmentIndex = getHostSegmentIndex(prefixLength, MACAddress.BYTES_PER_SEGMENT, MACAddress.BITS_PER_SEGMENT);
			int i = 0;
			for(; i < hostSegmentIndex; i++) {//note we know there is at least one host segment as we checked prefix length above
				result *= getSegment(i).getValueCount();
			}
			if(i == networkSegmentIndex) {
				long lastValue = getSegment(i).getPrefixValueCount(getSegmentPrefixLength(MACAddress.BITS_PER_SEGMENT, prefixLength, i));
				if(lastValue != 1) {
					if(result <= 0x7fffffffffffffL) {
						result *= lastValue;
					} else {
						return BigInteger.valueOf(result).multiply(BigInteger.valueOf(lastValue));
					}
				}
			}
			return BigInteger.valueOf(result);
		}
		return BigInteger.ONE;
	}
	
	@Override
	protected BigInteger getPrefixCountImpl() {
		Integer prefixLength = getPrefixLength();
		if(prefixLength == null || prefixLength >= getBitCount()) {
			return getCount();
		}
		return getPrefixCount(prefixLength);
	}
	
	/**
	 * Indicates if the address represents all devices with the same OUI segments.
	 * 
	 * @return true if all the ODI segments are full-range, covering all devices
	 */
	@Override
	public boolean isPrefixed() {
		return getPrefixLength() != null;
	}
	
	public int getOUISegmentCount() {
		return Math.max(0, MACAddress.ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT - addressSegmentIndex);
	}
	
	public int getODISegmentCount() {
		return getSegmentCount() - getOUISegmentCount();
	}

	/**
	 * @return the number of bits in the prefix.  
	 * 
	 * The prefix is the smallest bit length x for which all possible values with the same first x bits are included in this range of sections,
	 * unless that value x matches the bit count of this section, in which case the prefix is null.
	 * 
	 * If the prefix is the OUI bit length (24) then the ODI segments cover all possibly values.
	 */
	@Override
	public Integer getPrefixLength() {
		Integer ret = cachedPrefixLength;
		if(ret == null) {
			int prefix = getMinPrefixLengthForBlock();
			if(prefix == getBitCount()) {
				cachedPrefixLength = NO_PREFIX_LENGTH;
				return null;
			}
			return cachedPrefixLength = prefix;
		}
		if(ret.intValue() == NO_PREFIX_LENGTH.intValue()) {
			return null;
		}
		return ret;
	}
	
	protected void assignPrefixLength(Integer prefixLength) {
		if(prefixLength == null) {
			cachedPrefixLength = NO_PREFIX_LENGTH;
			return;
		}
		if(prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
		int max = getBitCount();
		if(prefixLength > max) {
			int maxPrefixLength = extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_BIT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_BIT_COUNT;
			if(prefixLength > maxPrefixLength) {
				throw new PrefixLenException(prefixLength);
			}
			prefixLength = max;
		}
		cachedPrefixLength = prefixLength;
	}

	@Override
	public MACAddressSection getSection() {
		return this;
	}

	@Override
	public MACAddressSection getSection(int index) {
		return getSection(index, getSegmentCount());
	}

	@Override
	public MACAddressSection getSection(int index, int endIndex) {
		MACAddressSection result = getSection(index, endIndex, this, getAddressCreator(addressSegmentIndex + index, extended));
		Integer prefix = getPrefixLength();
		if(prefix != null) {
			if(index > 0) {
				prefix = Math.max(0,  prefix - (index << 3));
			}
			if(prefix > ((endIndex - index) << 3)) {
				prefix = null;
			}
		}
		result.assignPrefixLength(prefix);
		return result;
	}

	public MACAddressSection getOUISection() {
		int segmentCount = getOUISegmentCount();
		MACAddressSection result = getSection(0, segmentCount, this, getAddressCreator());
		Integer prefix = getPrefixLength();
		if(prefix != null) {
			if(prefix > (segmentCount << 3)) {
				prefix = null;
			}
		}
		result.assignPrefixLength(prefix);
		return result;
	}

	public MACAddressSection getODISection() {
		int segmentCount = getOUISegmentCount();
		MACAddressSection result = getSection(segmentCount, getSegmentCount(), this, getAddressCreator(addressSegmentIndex + segmentCount, extended));
		Integer prefix = getPrefixLength();
		if(prefix != null && segmentCount > 0) {
			prefix = Math.max(0,  prefix - (segmentCount << 3));
		}
		result.assignPrefixLength(prefix);
		return result;
	}
	
	/**
	 * Returns a section in which the range of values match the block for the OUI (organizationally unique identifier) bytes
	 * 
	 * @return
	 */
	public MACAddressSection toOUIPrefixBlock() {
		int ouiSegmentCount = getOUISegmentCount();
		int segmentCount = getSegmentCount();
		Integer currentPref = getPrefixLength();
		int newPref = ouiSegmentCount << 3;//ouiSegmentCount * MACAddress.BITS_PER_SEGMENT
		boolean createNew;
		if(!(createNew = (currentPref == null || currentPref > newPref))) {
			newPref = currentPref;
			for(int i = ouiSegmentCount; i < segmentCount; i++) {
				MACAddressSegment segment = getSegment(i);
				if(!segment.isFullRange()) {
					createNew = true;
					break;
				}
			}
		}
		if(createNew) {
			MACAddressCreator creator = getAddressCreator();
			MACAddressSegment allRangeSegment = creator.createRangeSegment(0, MACAddress.MAX_VALUE_PER_SEGMENT);
			MACAddressSegment newSegments[] = setPrefixedSegments(
					getNetwork(),
					newPref,
					getSegments(), //this clones
					MACAddress.BITS_PER_SEGMENT,
					MACAddress.BYTES_PER_SEGMENT,
					creator, 
					(seg, prefixLength) -> (prefixLength == 0) ? allRangeSegment : seg);			
			MACAddressSection result = creator.createSectionInternal(newSegments);
			result.assignPrefixLength(newPref);
			return result;
		}
		return this;
	}
	
	/**
	 * Converts to Ipv6.  Any MAC prefix length is ignored.  Other elements of this address section are incorporated into the conversion.
	 * 
	 * @return
	 */
	public IPv6AddressSection toEUI64IPv6() {
		return getIPv6Network().getAddressCreator().createSection(this);
	}

	/**
	 * Equivalent to isEUI64(asMAC, false)
	 * 
	 * @return
	 */
	public boolean isEUI64(boolean asMAC) {
		return isEUI64(asMAC, false);
	}

	/**
	 * Whether this section is consistent with an EUI64 section,
	 * which means it came from an extended 8 byte address,
	 * and the corresponding segments in the middle match 0xff and 0xff/fe for MAC/not-MAC
	 * 
	 * @param partial whether missing segments are considered a match (this only has an effect if this section came from an extended 8 byte address),
	 * 	or in other words, we don't consider 6 byte addresses to be "missing" the bytes that would make it 8 byte.
	 * @param asMAC whether to search for the ffff or fffe pattern
	 * @return
	 */
	public boolean isEUI64(boolean asMAC, boolean partial) {
		if(isExtended()) {
			int segmentCount = getSegmentCount();
			int endIndex = addressSegmentIndex + segmentCount;
			if(addressSegmentIndex <= 3) {
				if(endIndex > 4) {
					int index3 = 3 - addressSegmentIndex;
					MACAddressSegment seg3 = getSegment(index3);
					MACAddressSegment seg4 = getSegment(index3 + 1);
					return seg4.matches(asMAC ? 0xff : 0xfe) && seg3.matches(0xff);
				} else if(partial && endIndex == 4) {
					MACAddressSegment seg3 = getSegment(3 - addressSegmentIndex);
					return seg3.matches(0xff);
				}
			} else if(partial && addressSegmentIndex == 4 && endIndex > 4) {
				MACAddressSegment seg4 = getSegment(4 - addressSegmentIndex);
				return seg4.matches(asMAC ? 0xff : 0xfe);
			}
			return partial;
		}
		return false;
	}

	/**
	 * If this section is part of a shorter 48 bit MAC or EUI-48 address see {@link #isExtended()},
	 * then the required sections are inserted (FF-FF for MAC, FF-FE for EUI-48) to extend it to EUI-64.
	 * 
	 * However, if the section does not encompass the parts of the address where 
	 * the new sections should be placed, then the section is unchanged.
	 * 
	 * If the section is already part of an EUI-64 address, then it is checked
	 * to see if it has the segments that identify it as extended to EUI-64 (FF-FF for MAC, FF-FE for EUI-48), 
	 * and if not, {@link IncompatibleAddressException} is thrown.
	 * 
	 * @param asMAC
	 * @return
	 */
	public MACAddressSection toEUI64(boolean asMAC) {
		int originalSegmentCount = getSegmentCount();
		if(!isExtended()) {
			MACAddressCreator creator = getAddressCreator(addressSegmentIndex, true);
			if(addressSegmentIndex + originalSegmentCount < 3 || addressSegmentIndex > 3) {
				return this;
			}
			//we are in a situation where we are including segments at index 3 and 4 in an address, which are the ff:fe or ff:ff segments
			MACAddressSegment segs[] = creator.createSegmentArray(originalSegmentCount + 2);
			int frontCount;
			if(addressSegmentIndex < 3) {
				frontCount = 3 - addressSegmentIndex;
				getSegments(0, frontCount, segs, 0);
			} else {
				frontCount = 0;
			}
			MACAddressSegment ffSegment = creator.createSegment(0xff);
			segs[frontCount] = ffSegment;
			segs[frontCount + 1] = asMAC ? ffSegment : creator.createSegment(0xfe);
			Integer prefLength = getPrefixLength();
			if(originalSegmentCount > frontCount) {
				getSegments(frontCount, originalSegmentCount, segs, frontCount + 2);
				//If the prefLength is exactly at the end of the initial segments before ff:fe or ff:ff, we could put it either before or after the ff:fe or ff:ff
				//Since the ff:fe or ff:ff is not part of any OUI, we put it before
				//This is also consistent with what we do with IP address inserts, where inserting at 3rd segment of 1.2.4/16 results in 1.2.3.4/16
				if(prefLength != null && prefLength > frontCount << 3) {
					prefLength += MACAddress.BITS_PER_SEGMENT << 1; //2 segments
				}
			}
			MACAddressSection result = creator.createSectionInternal(segs, addressSegmentIndex, true);
			result.assignPrefixLength(prefLength);
			return result;
		}
		int endIndex = addressSegmentIndex + originalSegmentCount;
		if(addressSegmentIndex <= 3) {
			if(endIndex > 4) {
				int index3 = 3 - addressSegmentIndex;
				MACAddressSegment seg3 = getSegment(index3);
				MACAddressSegment seg4 = getSegment(index3 + 1);
				if(!seg4.matches(asMAC ? 0xff : 0xfe) || !seg3.matches(0xff)) {
					throw new IncompatibleAddressException(this, "ipaddress.mac.error.not.eui.convertible");
				}
			} else if(endIndex == 4) {
				MACAddressSegment seg3 = getSegment(3 - addressSegmentIndex);
				if(!seg3.matches(0xff)) {
					throw new IncompatibleAddressException(this, "ipaddress.mac.error.not.eui.convertible");
				}
			}
		} else if(addressSegmentIndex == 4) {
			if(endIndex > 4) {
				MACAddressSegment seg4 = getSegment(4 - addressSegmentIndex);
				if(!seg4.matches(asMAC ? 0xff : 0xfe)) {
					throw new IncompatibleAddressException(this, "ipaddress.mac.error.not.eui.convertible");
				}
			}
		}
		return this;
	}

	public MACAddressSection append(MACAddressSection other) {
		int count = getSegmentCount();
		return replace(count, count, other, 0, other.getSegmentCount());
	}
	
	public MACAddressSection appendToPrefix(MACAddressSection other) {
		Integer prefixLength = getPrefixLength();
		if(prefixLength == null) {
			return append(other);
		}
		MACAddressSection thizz = this;
		int bitsPerSegment = getBitsPerSegment();
		int adjustment = prefixLength % bitsPerSegment;
		if(adjustment != 0) {
			prefixLength += bitsPerSegment - adjustment;
			thizz = setPrefixLength(prefixLength, false, false);
		}
		int index = prefixLength >>> 3;
		if(other.isPrefixed() && other.getPrefixLength() == 0) {
			//replacement is all host, cannot make it part of network
			return insert(index, other); //return append(other);
		}
		return thizz.replace(index, index, other, 0, other.getSegmentCount(), true);
	}
	
	public MACAddressSection insert(int index, MACAddressSection other) {
		return replace(index, index, other, 0, other.getSegmentCount());
	}
	
	/**
	 * Replace the segments of this section starting at the given index with the given replacement segments
	 * 
	 * @param index
	 * @param replacement
	 * @return
	 */
	public MACAddressSection replace(int index, MACAddressSection replacement) {
		return replace(index, index + replacement.getSegmentCount(), replacement, 0, replacement.getSegmentCount());
	}

	/**
	 * Replaces segments starting from startIndex and ending before endIndex with the segments starting at replacementStartIndex and 
	 * ending before replacementEndIndex from the replacement section
	 * @param startIndex
	 * @param endIndex
	 * @param replacement
	 * @param replacementStartIndex
	 * @param replacementEndIndex
	 * @throws IndexOutOfBoundsException
	 * @throws AddressValueException if the resulting section would exceed the maximum segment count for this address type and version
	 * @return
	 */
	public MACAddressSection replace(int startIndex, int endIndex, MACAddressSection replacement, int replacementStartIndex, int replacementEndIndex) {
		return replace(startIndex, endIndex, replacement, replacementStartIndex, replacementEndIndex, false);
	}
	
	private MACAddressSection replace(int startIndex, int endIndex, MACAddressSection replacement, int replacementStartIndex, int replacementEndIndex, boolean appendNetwork) {
		int segmentCount = getSegmentCount();
		int replacedCount = endIndex - startIndex;
		int replacementCount = replacementEndIndex - replacementStartIndex;
		if(replacedCount < 0 || replacementCount < 0 || startIndex < 0 || replacementStartIndex < 0 || replacementEndIndex > replacement.getSegmentCount() || endIndex > segmentCount) {
			throw new IndexOutOfBoundsException();
		}
		int diff = replacementCount - replacedCount;
		int totalSegmentCount = segmentCount + diff;
		if(addressSegmentIndex + totalSegmentCount > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			throw new AddressValueException(this, replacement, addressSegmentIndex + totalSegmentCount);
		}
		//if only one is prefixed, then that prefix prevails
		//if neither prefixed, the result not prefixed
		//if both prefixed, then the front prefix matters
		else if(replacementCount == 0) {
			if(isPrefixed()) {
				if(replacement.isPrefixed() && replacement.getPrefixLength() <= replacementEndIndex << 3) {
					if(getPrefixLength() <= startIndex << 3) {
						return this;
					}
				} else {
					return this;
				}
			} else if(!replacement.isPrefixed()) {
				return this;
			}
		}
		if(segmentCount == replacedCount && addressSegmentIndex == replacement.addressSegmentIndex && extended == replacement.extended) {
			if(!isPrefixed() || (replacement.isPrefixed() && replacement.getPrefixLength() == 0)) {
				return replacement;
			}
		}
		MACAddressSection result = replace(this, startIndex, endIndex, replacement, replacementStartIndex, replacementEndIndex, getAddressCreator(), appendNetwork, true);//will use same start index and extended flag as this
		if(isPrefixed()) {
			Integer prefLength = getPrefixLength();
			int startBits = startIndex << 3;
			if(!appendNetwork && prefLength <= startBits) {
				result.assignPrefixLength(prefLength);
			} else if(replacement.isPrefixed() && replacement.getPrefixLength() <= replacementEndIndex << 3) {
				result.assignPrefixLength(Math.max(0, (replacement.getPrefixLength() - (replacementStartIndex << 3))) + startBits);
			} else if(prefLength <= endIndex << 3) {
				result.assignPrefixLength(startBits + (replacementCount << 3));
			} else {
				result.assignPrefixLength(prefLength + (diff << 3));
			}
		} else if(replacement.isPrefixed() && replacement.getPrefixLength() <= replacementEndIndex << 3) {
			result.assignPrefixLength(Math.max(0, (replacement.getPrefixLength() - (replacementStartIndex << 3))) + (startIndex << 3));
		} else {
			result.assignPrefixLength(null);
		}
		return result;
	}

	private MACAddressSection getLowestOrHighestSection(boolean lowest) {
		MACAddressSection result = getSingleLowestOrHighestSection(this);
		if(result == null) {
			if(sectionCache == null || (result = lowest ? sectionCache.lower : sectionCache.upper) == null) {
				synchronized(this) {
					boolean create = (sectionCache == null);
					if(create) {
						sectionCache = new SectionCache<MACAddressSection>();
					} else {
						if(lowest) {
							create = (result = sectionCache.lower) == null;
						} else {
							create = (result = sectionCache.upper) == null;
						}
					}
					if(create) {
						MACAddressCreator creator = getAddressCreator();
						MACAddressSegment segs[] = createSingle(this, creator, i -> lowest ? getSegment(i).getLower() : getSegment(i).getUpper());
						Integer prefLength;
						result = (getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() || (prefLength = getPrefixLength()) == null) ? 
							creator.createSectionInternal(segs) :
							creator.createPrefixedSectionInternal(segs, prefLength, true);
						if(lowest) {
							sectionCache.lower = result;
						} else {
							sectionCache.upper = result;
						}
					}
				}
			}
		}
		return result;
	}

	MACAddress getLowestOrHighest(MACAddress addr, boolean lowest) {
		MACAddressSection sectionResult = getLowestOrHighestSection(lowest);
		if(sectionResult == this) {
			return addr;
		}
		
		MACAddress result = null;
		AddressCache cache = addr.sectionCache;
		if(cache == null || (result = lowest ? cache.lower : cache.upper) == null) {
			synchronized(this) {
				cache = addr.sectionCache;
				boolean create = (cache == null);
				if(create) {
					cache = addr.sectionCache = new AddressCache();
				} else {
					if(lowest) {
						create = (result = cache.lower) == null;
					} else {
						create = (result = cache.upper) == null;
					}
				}
				if(create) {
					result = getAddressCreator().createAddress(sectionResult);
					if(lowest) {
						cache.lower = result;
					} else {
						cache.upper = result;
					}
				}
			}
		}
		return result;
	}

	@Override
	public MACAddressSection getLower() {
		return getLowestOrHighestSection(true);
	}

	@Override
	public MACAddressSection getUpper() {
		return getLowestOrHighestSection(false);
	}

	public long longValue() {
		return getLongValue(true);
	}

	public long upperLongValue() {
		return getLongValue(false);
	}
	
	private long getLongValue(boolean lower) {
		int segCount = getSegmentCount();
		long result = 0;
		for(int i = 0; i < segCount; i++) {
			MACAddressSegment seg = getSegment(i);
			result = (result << MACAddress.BITS_PER_SEGMENT) | (lower ? seg.getSegmentValue() : seg.getUpperSegmentValue());
		}
		return result;
	}

	@Override
	public MACAddressSection reverseBits(boolean perByte) {
		MACAddressSection result =  reverseBits(perByte, this, getAddressCreator(), i -> getSegment(i).reverseBits(perByte), false);
		result.assignPrefixLength(null);
		return result;
	}
	
	@Override
	public MACAddressSection reverseBytes() {
		return reverseSegments();
	}
	
	@Override
	public MACAddressSection reverseBytesPerSegment() {
		return this;
	}
	
	@Override
	public MACAddressSection reverseSegments() {
		if(getSegmentCount() <= 1) {
			return this;
		}
		MACAddressSection result = reverseSegments(this, getAddressCreator(), this::getSegment, false);
		result.assignPrefixLength(null);
		return result;
	}
	
	@Override
	public MACAddressSection removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public MACAddressSection withoutPrefixLength() {
		return removePrefixLength(false);
	}
	
	@Override  @Deprecated
	public MACAddressSection removePrefixLength(boolean zeroed) {
		if(getPrefixLength() == null) {
			return this;
		}
		MACAddressSegment oldSegs[] = getSegmentsInternal();
		MACAddressSegment newSegs[] = removePrefix(//when we increase the prefix length, we zero out the bits between old and new, and in this case we are always doing that as we go from having one to having none
				this,
				oldSegs,
				MACAddress.BITS_PER_SEGMENT,
				(seg, oldPrefLength, newPrefLength) -> seg.setPrefixedSegment(oldPrefLength, newPrefLength, zeroed)); 
		MACAddressSection result = getAddressCreator().createSectionInternal(newSegs);
		result.assignPrefixLength(null);
		return result;
	}
	
	@Override
	public MACAddressSection adjustPrefixBySegment(boolean nextSegment) {
		return adjustPrefixBySegment(nextSegment, true);
	}
	
	@Override
	public MACAddressSection adjustPrefixBySegment(boolean nextSegment, boolean zeroed) {
		Integer existing = getPrefixLength();
		if(existing == null && nextSegment) {
			return this;
		}
		int prefix = getAdjustedPrefix(nextSegment, getBitsPerSegment(), true);
		return setPrefixLength(prefix, zeroed);
	}

	@Override
	public MACAddressSection adjustPrefixLength(int adjustment) {
		return adjustPrefixLength(adjustment, true);
	}

	@Override
	public MACAddressSection adjustPrefixLength(int adjustment, boolean zeroed) {
		if(adjustment == 0) {
			return this;
		}
		int prefix = getAdjustedPrefix(adjustment, true, true);
		return setPrefixLength(prefix, zeroed);
	}

	@Override
	public MACAddressSection applyPrefixLength(int prefixLength) {
		return setPrefixLength(prefixLength, true, true);
	}

	@Override
	public MACAddressSection setPrefixLength(int prefixLength) {
		return setPrefixLength(prefixLength, true, false);
	}
	
	@Override
	public MACAddressSection setPrefixLength(int prefixLength, boolean zeroed) {
		return setPrefixLength(prefixLength, zeroed, false);
	}

	private MACAddressSection setPrefixLength(int prefixLength, boolean zeroed, boolean noShrink) {
		if(prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
		int max = getBitCount();
		if(prefixLength > max) {
			if(prefixLength > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_BIT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_BIT_COUNT)) {
				throw new PrefixLenException(prefixLength);
			}
			prefixLength = max;
		}
		Integer oldPrefix = getPrefixLength();
		boolean prefixShrinking = oldPrefix == null || oldPrefix > prefixLength;
		boolean prefixGrowing;
		boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		if(prefixShrinking) {
			prefixGrowing = false;
		} else {
			prefixGrowing = !noShrink && oldPrefix < prefixLength;
			if(!prefixGrowing && !isAllSubnets) {//no shrinking and no growing, nothing happening
				return this;
			}
		}
		MACAddressCreator creator = getAddressCreator();
		MACAddressSegment oldSegs[] = getSegmentsInternal();
		MACAddressSegment newSegs[];
		int segmentBitCount = MACAddress.BITS_PER_SEGMENT;
		int segmentByteCount = MACAddress.BYTES_PER_SEGMENT;
		if(isAllSubnets) {
			if(prefixShrinking) {
				newSegs = setPrefixedSegments(getNetwork(), prefixLength, oldSegs.clone(), 
						segmentBitCount, segmentByteCount, creator, MACAddressSegment::toPrefixBlockSegment);
				MACAddressSection result = creator.createSectionInternal(newSegs);
				result.assignPrefixLength(prefixLength);
				return result;
			} else if(!prefixGrowing) {
				//neither growing nor shrinking
				return toPrefixBlock();
			}
		}
		newSegs = oldSegs.clone();
		for(int i = 0; i < newSegs.length; i++) {
			Integer newPref = getPrefixedSegmentPrefixLength(MACAddress.BITS_PER_SEGMENT, prefixLength, i);
			Integer oldPref = oldPrefix == null ? null : getPrefixedSegmentPrefixLength(MACAddress.BITS_PER_SEGMENT, oldPrefix, i);
			newSegs[i] = newSegs[i].setPrefixedSegment(oldPref, newPref, zeroed);
			if(isAllSubnets && newPref != null) {
				if(++i < newSegs.length) {
					MACAddressSegment zeroSeg = creator.createRangeSegment(0, MACAddress.MAX_VALUE_PER_SEGMENT);
					Arrays.fill(newSegs, i, newSegs.length, zeroSeg);
					break;
				}
			}
		}
		MACAddressSection result = creator.createSectionInternal(newSegs);
		result.assignPrefixLength(prefixLength);
		return result;
	}

	@Override
	public MACAddressSection toPrefixBlock() {
		Integer prefixLength = getPrefixLength();
		if(prefixLength != null) {
			int segmentBitCount = MACAddress.BITS_PER_SEGMENT;
			int segmentByteCount = MACAddress.BYTES_PER_SEGMENT;
			MACAddressSegment oldSegs[] = getSegmentsInternal();
			for(int i = getHostSegmentIndex(prefixLength, segmentByteCount, segmentBitCount); i < oldSegs.length; i++) {
				Integer pref = getPrefixedSegmentPrefixLength(segmentBitCount, prefixLength, i);
				MACAddressSegment seg = oldSegs[i];
				if(pref != null && !seg.isPrefixBlock(pref)) {
					MACAddressCreator creator = getAddressCreator();
					MACAddressSegment newSegs[] = setPrefixedSegments(getNetwork(), prefixLength, oldSegs.clone(),
							segmentBitCount, segmentByteCount, creator, MACAddressSegment::toPrefixBlockSegment);
					MACAddressSection result = creator.createSectionInternal(newSegs);
					result.assignPrefixLength(prefixLength);
					return result;
				}
			}
		}
		return this;
	}

	@Override
	public Iterable<MACAddressSection> getIterable() {
		return this;
	}
	
	@Override
	public Iterator<MACAddressSection> iterator() {
		MACAddressCreator creator = getAddressCreator();
		boolean isSingle = !isMultiple();
		return iterator(
				isSingle,
				this,
				creator,
				isSingle ? null : segmentsIterator(),
				getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength()); 
	}

	@Override
	public Iterator<MACAddressSection> prefixIterator() {
		return prefixIterator(false);
	}
	
	@Override
	public Iterator<MACAddressSection> prefixBlockIterator() {
		return prefixIterator(true);
	}
	
	private Iterator<MACAddressSection> prefixIterator(boolean isBlockIterator) {
		Integer prefLength = getPrefixLength();
		if(prefLength == null || prefLength > getBitCount()) {
			return iterator();
		}
		MACAddressCreator creator = getAddressCreator();
		boolean useOriginal = isBlockIterator ? isSinglePrefixBlock() : getPrefixCount().equals(BigInteger.ONE);
		return iterator(
				useOriginal,
				this,
				creator,
				useOriginal ?
						null :
						iterator(
							getSegmentCount(),
							creator,
							null, //when no prefix we defer to other iterator, when there is one we use the whole original section in the encompassing iterator and not just the original segments
							index -> getSegment(index).iterator(),
							null, 
							getNetworkSegmentIndex(prefLength, MACAddress.BYTES_PER_SEGMENT, MACAddress.BITS_PER_SEGMENT), 
							getHostSegmentIndex(prefLength, MACAddress.BYTES_PER_SEGMENT, MACAddress.BITS_PER_SEGMENT), 
							isBlockIterator ? 
									index -> getSegment(index).prefixBlockIterator(getSegmentPrefixLength(MACAddress.BITS_PER_SEGMENT, prefLength, index)) :
									index -> getSegment(index).prefixIterator(getSegmentPrefixLength(MACAddress.BITS_PER_SEGMENT, prefLength, index))
						),
				prefLength);
	}
	
	@Override
	public Iterator<MACAddressSegment[]> segmentsIterator() {
		return iterator(getSegmentCount(), getSegmentCreator(), isMultiple() ? null : () -> getLower().getSegments(), index -> getSegment(index).iterator(), null);
	}
	
	//these are the iterators used by MACAddress
	protected Iterator<MACAddress> iterator(MACAddress original) {
		MACAddressCreator creator = getAddressCreator();
		boolean isSingle = !isMultiple();
		return iterator(
				isSingle ? original : null, 
				creator,//using a lambda for this one results in a big performance hit
				isSingle ? null : segmentsIterator(),
				getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength());
	}
	
	Iterator<MACAddress> prefixIterator(MACAddress original, boolean isBlockIterator) {
		Integer prefLength = getPrefixLength();
		if(prefLength == null || prefLength > getBitCount()) {
			return iterator(original);
		}
		MACAddressCreator creator = getAddressCreator();
		boolean useOriginal = isSinglePrefixBlock();
		return iterator(
				useOriginal ? original : null,
				creator,//using a lambda for this one results in a big performance hit
				useOriginal ? null :
					iterator(
							getSegmentCount(),
							creator,
							null, //when no prefix we defer to other iterator, when there is one we use the whole original address in the encompassing iterator and not just the original segments
							index -> getSegment(index).iterator(),
							null, 
							getNetworkSegmentIndex(prefLength, MACAddress.BYTES_PER_SEGMENT, MACAddress.BITS_PER_SEGMENT), 
							getHostSegmentIndex(prefLength, MACAddress.BYTES_PER_SEGMENT, MACAddress.BITS_PER_SEGMENT), 
							isBlockIterator ? 
									index -> getSegment(index).prefixBlockIterator(getSegmentPrefixLength(MACAddress.BITS_PER_SEGMENT, prefLength, index)) :
									index -> getSegment(index).prefixIterator(getSegmentPrefixLength(MACAddress.BITS_PER_SEGMENT, prefLength, index))
							),
				prefLength);
	}

	private static long getMaxValueLong(int segmentCount) {
		return MAX_VALUES_LONG[segmentCount];
	}
	
	private static BigInteger getMaxValue(int segmentCount) {
		return MAX_VALUES[segmentCount];
	}
	
	@Override
	public MACAddressSection incrementBoundary(long increment) {
		if(increment <= 0) {
			if(increment == 0) {
				return this;
			}
			return getLower().increment(increment);
		}
		return getUpper().increment(increment);
	}
	
	@Override
	public MACAddressSection increment(long increment) {
		if(increment == 0 && !isMultiple()) {
			return this;
		}
		if(!isExtended() || getSegmentCount() < 8) {
			long lowerValue = longValue();
			long upperValue = upperLongValue();
			long count = getCount().longValue();
			checkOverflow(increment, lowerValue, upperValue, count, () -> getMaxValueLong(getSegmentCount()));
			return increment(
					this,
					increment,
					//null,
					getAddressCreator(),
					getCount().longValue(),
					longValue(),
					upperLongValue(),
					this::getLower,
					this::getUpper,
					getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength());
		}
		BigInteger lowerValue = getValue();
		BigInteger upperValue = getUpperValue();
		BigInteger count = getCount();
		BigInteger bigIncrement = BigInteger.valueOf(increment);
		checkOverflow(increment, bigIncrement, lowerValue, upperValue, count, () -> getMaxValue(getSegmentCount()));
		Integer prefixLength = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength();
		MACAddressSection result = fastIncrement(
				this,
				increment,
				getAddressCreator(),
				this::getLower,
				this::getUpper,
				prefixLength);
		if(result != null) {
			return result;
		}
		return increment(
				this,
				increment,
				bigIncrement,
				getAddressCreator(), 
				this::getLower,
				this::getUpper,
				getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : getPrefixLength());
	}

	protected boolean hasNoStringCache() {
		if(stringCache == null) {
			synchronized(this) {
				if(stringCache == null) {
					stringCache = new MACStringCache();
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Writes this address as a single hexadecimal value with always the exact same number of characters, with or without a preceding 0x prefix.
	 * 
	 */
	@Override
	public String toHexString(boolean with0xPrefix) {  
		String result;
		if(hasNoStringCache() || (result = (with0xPrefix ? stringCache.hexStringPrefixed : stringCache.hexString)) == null) {
			result = toHexString(with0xPrefix, null);
			if(with0xPrefix) {
				stringCache.hexStringPrefixed = result;
			} else {
				stringCache.hexString = result;
			}
		}
		return result;
	}
	
	protected String toHexString(boolean with0xPrefix, CharSequence zone) {
		if(isDualString()) {
			return toNormalizedStringRange(AddressStringParams.toParams(with0xPrefix ? MACStringCache.hexPrefixedParams : MACStringCache.hexParams), getLower(), getUpper(), null);
		}
		return toNormalizedString(with0xPrefix ? MACStringCache.hexPrefixedParams : MACStringCache.hexParams);
	}
	
	public String toNormalizedString(StringOptions stringOptions) {
		return toNormalizedString(stringOptions, this);
	}

	public static String toNormalizedString(StringOptions opts, AddressDivisionGrouping section) {
		return toParams(opts).toString(section);
	}

	/**
	 * The normalized string returned by this method is the most common representation of MAC addresses: xx:xx:xx:xx:xx:xx
	 */
	@Override
	public String toNormalizedString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().normalizedString) == null) {
			getStringCache().normalizedString = result = toNormalizedString(MACStringCache.normalizedParams);
		}
		return result;
	}

	/**
	 * This produces a canonical string using the canonical standardized IEEE 802 MAC address representation of xx-xx-xx-xx-xx-xx
	 * For range segments, '..' is used: 11-22-33..44-55-66
	 */
	@Override
	public String toCanonicalString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().canonicalString) == null) {
			getStringCache().canonicalString = result = toNormalizedString(MACStringCache.canonicalParams);
		}
		return result;
	}

	/**
	 * This produces a shorter string for the address that uses the canonical representation but not using leading zeroes.
	 * 
	 * Each address has a unique compressed string.
	 */
	@Override
	public String toCompressedString() {
		String result;
		if(hasNoStringCache() || (result = getStringCache().compressedString) == null) {
			getStringCache().compressedString = result = toNormalizedString(MACStringCache.compressedParams);
		}
		return result;
	}
	
	/**
	 * This produces the dotted hexadecimal format aaaa.bbbb.cccc
	 */
	public String toDottedString() {
		String result = null;
		if(hasNoStringCache() || (result = getStringCache().dottedString) == null) {
			AddressDivisionGrouping dottedGrouping = getDottedGrouping();
			getStringCache().dottedString = result = toNormalizedString(MACStringCache.dottedParams, dottedGrouping);
		}
		return result;
	}
	
	/**
	 * This produces a string delimited by spaces: aa bb cc dd ee ff
	 */
	public String toSpaceDelimitedString() {
		String result = null;
		if(hasNoStringCache() || (result = getStringCache().spaceDelimitedString) == null) {
			getStringCache().spaceDelimitedString = result = toNormalizedString(MACStringCache.spaceDelimitedParams);
		}
		return result;
	}

	public String toDashedString() {
		return toCanonicalString();
	}

	public String toColonDelimitedString() {
		return toNormalizedString();
	}

	@Override
	public String toString() {
		return toNormalizedString();
	}
	
	@Override
	public String[] getSegmentStrings() {
		return getDivisionStrings();
	}
	
	@SuppressWarnings("serial")
	public AddressDivisionGrouping getDottedGrouping() {
		int start = addressSegmentIndex;
		int segmentCount = getSegmentCount();
		AddressDivision newSegs[];
		int newSegmentBitCount = MACAddress.BITS_PER_SEGMENT << 1;
		int segIndex, newSegIndex;
		if((start & 1) == 0) {
			int newSegmentCount = (segmentCount + 1) >>> 1;
			newSegs = new AddressDivision[newSegmentCount];
			newSegIndex = segIndex = 0;
		} else {
			int newSegmentCount = (segmentCount >>> 1) + 1;
			newSegs = new AddressDivision[newSegmentCount];
			MACAddressSegment segment = getSegment(0);
			newSegs[0] = new AddressBitsDivision(segment.getSegmentValue(), segment.getUpperSegmentValue(), newSegmentBitCount, MACAddress.DEFAULT_TEXTUAL_RADIX);
			newSegIndex = segIndex = 1;
		}
		while(segIndex + 1 < segmentCount) {
			MACAddressSegment segment1 = getSegment(segIndex++);
			MACAddressSegment segment2 = getSegment(segIndex++);
			if(segment1.isMultiple() && !segment2.isFullRange()) {
				throw new IncompatibleAddressException(segment1, segIndex - 2, segment2, segIndex - 1, "ipaddress.error.invalid.joined.ranges");
			}
			AddressDivision newSeg = new AddressBitsDivision(
					(segment1.getSegmentValue() << MACAddress.BITS_PER_SEGMENT) | segment2.getSegmentValue(), 
					(segment1.getUpperSegmentValue() << MACAddress.BITS_PER_SEGMENT) | segment2.getUpperSegmentValue(), 
					newSegmentBitCount,
					MACAddress.DEFAULT_TEXTUAL_RADIX);
			newSegs[newSegIndex++] = newSeg;
		}
		if(segIndex < segmentCount) {
			MACAddressSegment segment = getSegment(segIndex);
			newSegs[newSegIndex] = new AddressBitsDivision(
					segment.getSegmentValue() << MACAddress.BITS_PER_SEGMENT,
					segment.getUpperSegmentValue() << MACAddress.BITS_PER_SEGMENT,
					newSegmentBitCount,
					MACAddress.DEFAULT_TEXTUAL_RADIX);
		}
		AddressDivisionGrouping dottedGrouping;
		if(cachedPrefixLength == null) {
			dottedGrouping = new AddressDivisionGrouping(newSegs);
		} else {
			Integer prefLength = cachedPrefixLength;
			dottedGrouping = new AddressDivisionGrouping(newSegs) {{
				cachedPrefixLength = prefLength;
			}};
		}
		return dottedGrouping;
	}
	
	static String toNormalizedString(IPStringOptions opts, AddressStringDivisionSeries section) {
		return toParams(opts).toString(section);
	}

	@Override
	public boolean contains(AddressSection other) {
		return other instanceof MACAddressSection && contains((MACAddressSection) other);
	}
	
	/**
	 * @param other
	 * @return whether this section contains the given address section
	 */
	public boolean contains(MACAddressSection other) {
		//check if they are comparable first
		if(addressSegmentIndex != other.addressSegmentIndex || isExtended() != other.isExtended() || getSegmentCount() != other.getSegmentCount()) {
			return false;
		}
		for(int i = 0; i < getSegmentCount(); i++) {
			if(!getSegment(i).contains(other.getSegment(i))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean prefixEquals(AddressSection o) {
		if(o instanceof MACAddressSection) {
			MACAddressSection other = (MACAddressSection) o;
			if(addressSegmentIndex >= other.addressSegmentIndex) {
				return prefixEquals(this, other, addressSegmentIndex - other.addressSegmentIndex);
			}
		}
		return false;
	}
	
	protected static AddressStringParams<AddressStringDivisionSeries> toParams(StringOptions opts) {
		return AddressStringParams.toParams(opts);
	}
	
	/**
	 * Represents a clear way to create a specific type of string.
	 * 
	 * @author sfoley
	 */
	public static class MACStringOptions extends StringOptions {
		
		protected MACStringOptions(
				int base,
				boolean expandSegments,
				Wildcards wildcards,
				String segmentStrPrefix,
				Character separator,
				String label,
				boolean reverse,
				boolean splitDigits,
				boolean uppercase) {
			super(base, expandSegments, wildcards, segmentStrPrefix, separator, label, reverse, splitDigits, uppercase);
		}
		
		public static class Builder extends StringOptions.Builder {

			public Builder() {
				this(MACAddress.DEFAULT_TEXTUAL_RADIX, MACAddress.COLON_SEGMENT_SEPARATOR);
			}
			
			protected Builder(int base, char separator) {
				super(base, separator);
			}

			@Override
			public MACStringOptions toOptions() {
				return new MACStringOptions(base, expandSegments, wildcards, segmentStrPrefix, separator, addrLabel, reverse, splitDigits, uppercase);
			}
		}
	}
}
