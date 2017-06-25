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

package inet.ipaddr.mac;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Iterator;
import java.util.function.IntFunction;

import inet.ipaddr.Address;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSection;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressTypeException;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.format.AddressBitsDivision;
import inet.ipaddr.format.AddressDivision;
import inet.ipaddr.format.AddressDivisionGrouping;
import inet.ipaddr.format.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.AddressStringDivisionSeries;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;

public class MACAddressSection extends AddressDivisionGrouping implements AddressSection, Iterable<MACAddressSection> {

	private static final long serialVersionUID = 3L;

	/* the various string representations - these fields are for caching */
	protected static class MACStringCache extends StringCache {
		public static final StringOptions hexParams;
		public static final StringOptions hexPrefixedParams;
		public static final StringOptions canonicalParams;//uses the '-' as separator and '|' as range indicator
		public static final StringOptions compressedParams;
		public static final StringOptions normalizedParams;//uses the ':' as separator
		public static final StringOptions dottedParams;
		public static final StringOptions spaceDelimitedParams;
		
		static {
			hexParams = new MACStringOptions.Builder().setSeparator(null).setExpandedSegments(true).setRadix(16).toParams();
			hexPrefixedParams = new MACStringOptions.Builder().setSeparator(null).setExpandedSegments(true).setRadix(16).setAddressLabel(MACAddress.HEX_PREFIX).toParams();
			normalizedParams = new MACStringOptions.Builder().setSeparator(MACAddress.COLON_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toParams();
			canonicalParams = new MACStringOptions.Builder().setSeparator(MACAddress.DASH_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).setWildcards(new Wildcards(MACAddress.DASHED_SEGMENT_RANGE_SEPARATOR_STR, Address.SEGMENT_WILDCARD_STR, null)).toParams();
			compressedParams = new MACStringOptions.Builder().setSeparator(MACAddress.COLON_SEGMENT_SEPARATOR).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toParams();
			dottedParams = new MACStringOptions.Builder().setSeparator(MACAddress.DOTTED_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toParams();
			spaceDelimitedParams = new MACStringOptions.Builder().setSeparator(MACAddress.SPACE_SEGMENT_SEPARATOR).setExpandedSegments(true).setRadix(MACAddress.DEFAULT_TEXTUAL_RADIX).toParams();
		}
		
		public String compressedString;
		public String normalizedString;
		public String dottedString;
		public String spaceDelimitedString;
	}
	
	static class AddressCache extends SectionCache<MACAddress> {}
	
	private static MACAddressCreator creators[][] = new MACAddressCreator[MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT + 1][2];
	
	private transient MACStringCache stringCache;
	
	private transient SectionCache<MACAddressSection> sectionCache;
	
	/*
	 * Indicates the index of the first segment where this section would be located in a full address.  0 for oui sections or full addresses
	 */
	public final int startIndex;
	public final boolean extended;	

	/**
	 * Constructs a single segment section, the segment being the leading segment.
	 * 
	 * @param segment
	 */
	public MACAddressSection(MACAddressSegment segment) {
		super(new MACAddressSegment[] {segment});
		this.startIndex = 0;
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

	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(MACAddressSegment segments[], Integer prefixLength) {
		this(segments, 0, segments.length > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT, prefixLength);
	}
	
	public MACAddressSection(MACAddressSegment segments[], int startIndex, boolean extended, Integer prefixLength) {
		this(false,
			toPrefixedSegments(
				prefixLength,
				segments,
				MACAddress.BITS_PER_SEGMENT,
				getSegmentCreator(), 
				(seg, prefLength) -> seg.toPrefixedSegment(prefLength), true),
			startIndex,
			extended);
	}
	
	MACAddressSection(boolean cloneSegments, MACAddressSegment segments[], int startIndex, boolean extended) {
		super(cloneSegments ? segments.clone() : segments);
		if(startIndex < 0) {
			throw new IllegalArgumentException();
		}
		if(startIndex + segments.length > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new IllegalArgumentException(MACAddress.getMessage("ipaddress.error.exceeds.size") + ' ' + segments.length);
		}
		this.startIndex = startIndex;
		this.extended = extended;
	}
		
	MACAddressSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, int startIndex, boolean extended, Integer prefixLength) {
		super(AddressDivisionGrouping.toSegments(
				lowerValueProvider,
				upperValueProvider,
				extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT,
				MACAddress.BYTES_PER_SEGMENT,
				MACAddress.BITS_PER_SEGMENT,
				MACAddress.MAX_VALUE_PER_SEGMENT,
				getSegmentCreator(),
				prefixLength));
		if(startIndex < 0) {
			throw new IllegalArgumentException();
		}
		this.startIndex = startIndex;
		this.extended = extended;
	}
	
	MACAddressSection(byte bytes[], int startIndex, boolean extended, Integer prefixLength, boolean cloneBytes) {
		super(AddressDivisionGrouping.toSegments(
				bytes,
				bytes.length,
				MACAddress.BYTES_PER_SEGMENT,
				MACAddress.BITS_PER_SEGMENT,
				MACAddress.MAX_VALUE_PER_SEGMENT,
				getSegmentCreator(),
				prefixLength));
		if(startIndex < 0) {
			throw new IllegalArgumentException();
		}
		if(startIndex + bytes.length > (extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new IllegalArgumentException(MACAddress.getMessage("ipaddress.error.exceeds.size") + ' ' + bytes.length);
		}
		this.startIndex = startIndex;
		this.extended = extended;
		setBytes(cloneBytes ? bytes.clone() : bytes);
	}
	
	public MACAddressSection(byte bytes[], int startIndex, boolean extended, Integer prefixLength) {
		this(bytes, startIndex, extended, prefixLength, true);
	}

	/*
	 * Use this constructor for any section that is part of a 64-bit EUI address,
	 * or for any section that you wish to start in the middle of a MAC address.
	 */
	public MACAddressSection(byte bytes[], int startIndex, boolean extended) {
		this(bytes, startIndex, extended, null, true);
	}
	
	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(byte bytes[], Integer prefixLength) {
		this(bytes, 0, bytes.length >  MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT, null, true);
	}
	
	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(byte bytes[]) {
		this(bytes, null);
	}

	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(long value, int startIndex, boolean extended, Integer prefixLength) {
		super(toPrefixedSegments(
			value,
			extended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT,
			MACAddress.BYTES_PER_SEGMENT,
			MACAddress.BITS_PER_SEGMENT,
			MACAddress.MAX_VALUE_PER_SEGMENT,
			getSegmentCreator(),
			prefixLength));
		if(startIndex < 0) {
			throw new IllegalArgumentException();
		}
		if(!extended && (value > 0xffffffffffffL || value < 0L)) {
			throw new IllegalArgumentException(MACAddress.getMessage("ipaddress.error.exceeds.size") + ' ' + value);
		}
		this.startIndex = startIndex;
		this.extended = extended;
	}
	
	public MACAddressSection(long value, int startIndex, boolean extended) {
		this(value, startIndex, extended, null);
	}

	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(long value, Integer prefixLength) {
		this(value, 0, false, prefixLength);
	}

	/*
	 * Use this constructor for any address section that includes the leading segment of a MAC address
	 */
	public MACAddressSection(long value) {
		this(value, 0, false, null);
	}

	protected static MACAddressSegment[] toPrefixedSegments(long value, int segmentCount, int bytesPerSegment, int bitsPerSegment, int maxValuePerSegment, AddressSegmentCreator<MACAddressSegment> creator, Integer prefixLength) {
		return AddressDivisionGrouping.toSegments(value, segmentCount, segmentCount, bytesPerSegment, bitsPerSegment, maxValuePerSegment, creator, prefixLength);
	}

	private static MACAddressCreator getAddressCreator(int startIndex, boolean extended) {
		int extendedIndex = extended ? 1 : 0;
		MACAddressCreator result = creators[startIndex][extendedIndex];
		if(result == null) {
			creators[startIndex][extendedIndex] = result = new MACAddressCreator() {
				@Override
				protected MACAddressSection createSectionInternal(MACAddressSegment segments[]) {
					return MACAddress.network().getAddressCreator().createSectionInternal(segments, startIndex, extended);
				}
			};
		}
		return result;
	}

	MACAddressCreator getAddressCreator() {
		return getAddressCreator(startIndex, extended);
	}
	
	private static AddressSegmentCreator<MACAddressSegment> getSegmentCreator() {
		return getAddressCreator(0, false);
	}
	
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof MACAddressSection) {
			MACAddressSection other = (MACAddressSection) o;
			return startIndex == other.startIndex && isExtended() == other.isExtended() && other.isSameGrouping(this);
		}
		return false;
	}
	
	protected MACStringCache getStringCache() {
		return (MACStringCache) stringCache;
	}

	@Override
	protected boolean isSameGrouping(AddressDivisionGrouping other) {
		return other instanceof MACAddressSection && super.isSameGrouping(other);
	}

	@Override
	public MACAddressSegment[] getSegments() {
		return (MACAddressSegment[]) divisions.clone();
	}
	
	@Override
	public void getSegments(AddressSegment segs[]) {
		getSegments(0, getDivisionCount(), segs, 0);
	}
	
	@Override
	public void getSegments(int start, int end, AddressSegment segs[], int destIndex) {
		System.arraycopy(divisions, start, segs, destIndex, end - start);
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
	public int getByteCount() {
		return getSegmentCount(); //MACAddress.BYTES_PER_SEGMENT is 1
	}
	
	@Override
	public int getBitCount() {
		return getSegmentCount() << 3;//MACAddress.BITS_PER_SEGMENT is 8
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
	protected byte[] getBytesImpl(boolean low) {
		byte bytes[] = new byte[getByteCount()];
		int segmentCount = getSegmentCount();
		for(int i = 0; i < segmentCount; i++) {
			MACAddressSegment seg = getSegment(i);
			int val = low ? seg.getLowerSegmentValue() : seg.getUpperSegmentValue();
			bytes[i] = (byte) val;
		}
		return bytes;
	}
	
	@Override
	protected BigInteger getCountImpl() {
		int segCount = getSegmentCount();
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
		return Math.max(0, MACAddress.ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT - startIndex);
	}
	
	public int getODISegmentCount() {
		return getSegmentCount() - Math.max(0, MACAddress.ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT - startIndex);
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
		Integer ret = cachedPrefix;
		if(ret == null) {
			int prefix = getMinPrefix();
			if(prefix == getBitCount()) {
				cachedPrefix = -1;
				return null;
			}
			return cachedPrefix = prefix;
		}
		if(cachedPrefix < 0) {
			return null;
		}
		return ret;
	}

	@Override
	public boolean isMultipleByPrefix() {
		return isPrefixed();
	}

	@Override
	public MACAddressSection getSection(int index) {
		return getSection(index, getSegmentCount());
	}

	@Override
	public MACAddressSection getSection(int index, int endIndex) {
		return getSection(index, endIndex, this, getAddressCreator(startIndex + index, extended));
	}

	public MACAddressSection getOUISection() {
		int segmentCount = getOUISegmentCount();
		return getSection(0, segmentCount, this, getAddressCreator());
	}

	public MACAddressSection getODISection() {
		int segmentCount = getOUISegmentCount();
		return getSection(segmentCount, getSegmentCount(), this, getAddressCreator(startIndex + segmentCount, extended));
	}
	
	public MACAddressSection toOUIPrefixed() {
		int ouiSegmentCount = getOUISegmentCount();
		int segmentCount = getSegmentCount();
		for(int i = ouiSegmentCount; i < segmentCount; i++) {
			MACAddressSegment segment = getSegment(i);
			if(!segment.isFullRange()) {
				MACAddressCreator creator = getAddressCreator();
				MACAddressSegment newSegments[] = toPrefixedSegments(
						ouiSegmentCount * MACAddress.BITS_PER_SEGMENT,
						getSegments(),
						MACAddress.BITS_PER_SEGMENT,
						creator, 
						(seg, prefixLength) -> (prefixLength == 0) ? MACAddressSegment.ALL_RANGE_SEGMENT : seg,
						false);
				return creator.createSectionInternal(newSegments);
			}
		}
		return this;
	}
	
	public IPv6AddressSection toEUI64IPv6() {
		return IPv6Address.network().getAddressCreator().createSection(this);
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
			int endIndex = startIndex + segmentCount;
			if(startIndex <= 3) {
				if(endIndex > 4) {
					int index3 = 3 - startIndex;
					MACAddressSegment seg3 = getSegment(index3);
					MACAddressSegment seg4 = getSegment(index3 + 1);
					return seg4.matches(asMAC ? 0xff : 0xfe) && seg3.matches(0xff);
				} else if(partial && endIndex == 4) {
					MACAddressSegment seg3 = getSegment(3 - startIndex);
					return seg3.matches(0xff);
				}
			} else if(partial && startIndex == 4 && endIndex > 4) {
				MACAddressSegment seg4 = getSegment(4 - startIndex);
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
	 * and if not, AddressTypeException is thrown.
	 * 
	 * @param asMAC
	 * @return
	 */
	public MACAddressSection toEUI64(boolean asMAC) {
		int originalSegmentCount = getSegmentCount();
		if(!isExtended()) {
			MACAddressCreator creator = getAddressCreator(startIndex, true);
			if(startIndex + originalSegmentCount < 3 || startIndex > 3) {
				return this;
			}
			MACAddressSegment segs[] = creator.createSegmentArray(originalSegmentCount + 2);
			int frontCount;
			if(startIndex < 3) {
				frontCount = 3 - startIndex;
				getSegments(0, frontCount, segs, 0);
			} else {
				frontCount = 0;
			}
			segs[frontCount] = MACAddressSegment.FF_SEGMENT;
			segs[frontCount + 1] = asMAC ? MACAddressSegment.FF_SEGMENT : MACAddressSegment.FE_SEGMENT;
			if(originalSegmentCount > frontCount) {
				getSegments(frontCount, originalSegmentCount, segs, frontCount + 2);
			}
			return creator.createSectionInternal(segs, startIndex, true);
		}
		int endIndex = startIndex + originalSegmentCount;
		if(startIndex <= 3) {
			if(endIndex > 4) {
				int index3 = 3 - startIndex;
				MACAddressSegment seg3 = getSegment(index3);
				MACAddressSegment seg4 = getSegment(index3 + 1);
				if(!seg4.matches(asMAC ? 0xff : 0xfe) || !seg3.matches(0xff)) {
					throw new AddressTypeException(this, "ipaddress.mac.error.not.eui.convertible");
				}
			} else if(endIndex == 4) {
				MACAddressSegment seg3 = getSegment(3 - startIndex);
				if(!seg3.matches(0xff)) {
					throw new AddressTypeException(this, "ipaddress.mac.error.not.eui.convertible");
				}
			}
		} else if(startIndex == 4) {
			if(endIndex > 4) {
				MACAddressSegment seg4 = getSegment(4 - startIndex);
				if(!seg4.matches(asMAC ? 0xff : 0xfe)) {
					throw new AddressTypeException(this, "ipaddress.mac.error.not.eui.convertible");
				}
			}
		}
		return this;
	}
	
	public MACAddressSection replace(MACAddressSection other, int index) {
		return replace(this, other, getAddressCreator(), index, false);
	}
	
	public MACAddressSection prepend(MACAddressSection other) {
		int otherSegmentCount = other.getSegmentCount();
		int newStartIndex = startIndex - otherSegmentCount;
		if(newStartIndex < 0) {
			throw new AddressTypeException(this, other, "ipaddress.error.exceeds.size");
		}
		if(otherSegmentCount == 0) {
			return this;
		}
		int segmentCount = getSegmentCount();
		if(startIndex == other.startIndex + otherSegmentCount && extended == other.extended && segmentCount == 0) {
			return other;
		}
		return append(other, this, getAddressCreator(newStartIndex, extended), false);
	}
	
	public MACAddressSection append(MACAddressSection other) {
		int otherSegmentCount = other.getSegmentCount();
		int segmentCount = getSegmentCount();
		int totalSegmentCount = segmentCount + otherSegmentCount;
		if(startIndex + totalSegmentCount > IPv6Address.SEGMENT_COUNT) {
			throw new AddressTypeException(this, other, "ipaddress.error.exceeds.size");
		}
		if(otherSegmentCount == 0) {
			return this;
		}
		if(startIndex == other.startIndex && extended == other.extended && segmentCount == 0) {
			return other;
		}
		return append(this, other, getAddressCreator(), false);//will use same start index and extended flag as this
	}

	/**
	 * @param other
	 * @return whether this section contains the given address section
	 */
	public boolean contains(MACAddressSection other) {
		//check if they are comparable first
		if(startIndex != other.startIndex || isExtended() != other.isExtended() || getSegmentCount() != other.getSegmentCount()) {
			return false;
		}
		for(int i=0; i < getSegmentCount(); i++) {
			if(!getSegment(i).contains(other.getSegment(i))) {
				return false;
			}
		}
		return true;
	}
	
	private MACAddressSection getLowestOrHighestSection(boolean lowest) {
		return getLowestOrHighestSection(
			this,
			getAddressCreator(),
			lowest,
			i -> lowest ? getSegment(i).getLower() : getSegment(i).getUpper(),
			() -> getSectionCache(this, () -> sectionCache, () -> sectionCache = new SectionCache<MACAddressSection>()));
	}

	MACAddress getLowestOrHighest(MACAddress addr, boolean lowest) {
		return getLowestOrHighestAddress(
				addr,
				getAddressCreator(),
				lowest,
				() -> getLowestOrHighestSection(lowest),
				() -> getSectionCache(addr, () -> addr.sectionCache, () -> addr.sectionCache = new AddressCache()));
	}

	@Override
	public MACAddressSection getLower() {
		return getLowestOrHighestSection(true);
	}
	
	@Override
	public MACAddressSection getUpper() {
		return getLowestOrHighestSection(false);
	}

	@Override
	public MACAddressSection reverseBits(boolean perByte) {
		return reverseBits(perByte, this, getAddressCreator(), i -> getSegment(i).reverseBits(perByte), false);
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
		return reverseSegments(this, getAddressCreator(), this::getSegment, false);
	}
	
	@Override
	public MACAddressSection removePrefixLength() {
		MACAddressSegment oldSegs[] = (MACAddressSegment[]) divisions;
		MACAddressSegment newSegs[] = removePrefix(
				this,
				//prefixLength,
				oldSegs,
				MACAddress.BITS_PER_SEGMENT,
				//noShrink,
				//creator,
				//(seg, prefLength) -> seg.toPrefixedSegment(prefLength), 
				(seg, oldPrefLength, newPrefLength) -> seg.setPrefixedSegment(oldPrefLength, newPrefLength));
		if(newSegs == oldSegs) {
			return this;
		}
		return getAddressCreator().createSectionInternal(newSegs, startIndex, extended);
	}
	
	@Override
	public MACAddressSection adjustPrefixBySegment(boolean nextSegment) {
		Integer existing = getPrefixLength();
		if(existing == null && nextSegment) {
			return this;
		}
		int prefix = getAdjustedPrefix(nextSegment, getBitsPerSegment(), true);
		return setPrefixLength(prefix);
	}
	
	@Override
	public MACAddressSection adjustPrefixLength(int adjustment) {
		if(adjustment == 0) {
			return this;
		}
		int prefix = getAdjustedPrefix(adjustment, true, true);
		return setPrefixLength(prefix);
	}
	
	@Override
	public MACAddressSection applyPrefixLength(int prefixLength) {
		return setPrefixLength(prefixLength, true);
	}
	
	@Override
	public MACAddressSection setPrefixLength(int networkPrefixLength) {
		return setPrefixLength(networkPrefixLength, false);
	}
	
	private MACAddressSection setPrefixLength(int prefixLength, boolean noShrink) {
		MACAddressCreator creator = getAddressCreator();
		MACAddressSegment oldSegs[] = (MACAddressSegment[]) divisions;
		MACAddressSegment newSegs[] = setPrefixed(
				this,
				prefixLength,
				oldSegs,
				MACAddress.BITS_PER_SEGMENT,
				noShrink,
				creator,
				(seg, prefLength) -> seg.toPrefixedSegment(prefLength), 
				(seg, oldPrefLength, newPrefLength) -> seg.setPrefixedSegment(oldPrefLength, newPrefLength));
		if(newSegs == oldSegs) {
			return this;
		}
		return creator.createSectionInternal(newSegs, startIndex, extended);
	}
	
	@Override
	public Iterable<MACAddressSection> getIterable() {
		return this;
	}
	
	@Override
	public Iterator<MACAddressSection> iterator() {
		boolean useOriginal = !isMultiple();
		return iterator(useOriginal, this, getAddressCreator(), useOriginal ? null : segmentsIterator());
	}
	
	@Override
	public Iterator<MACAddressSegment[]> segmentsIterator() {
		return super.iterator(getSegmentCreator(), () -> getLower().getSegments(), index -> getSegment(index).iterator());
	}
	
	protected Iterator<MACAddress> iterator(MACAddress original) {
		MACAddressCreator creator = getAddressCreator();
		boolean useOriginal = !isMultiple();
		return iterator(
				original, 
				creator,//using a lambda for this one results in a big performance hit
				useOriginal,
				useOriginal ? null : iterator(creator, () -> (MACAddressSegment[]) getLower().divisions, index -> getSegment(index).iterator()));
	}
	
	protected static <R extends MACAddressSection, S extends MACAddressSegment> S[] createSingle(R original, AddressSegmentCreator<S> segmentCreator, IntFunction<S> segProducer) {
		return AddressDivisionGrouping.createSingle(original, segmentCreator, segProducer);
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
	
	@SuppressWarnings("serial")
	public AddressDivisionGrouping getDottedGrouping() {
		int start = startIndex;
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
			newSegs[0] = new AddressBitsDivision(segment.getLowerSegmentValue(), segment.getUpperSegmentValue(), newSegmentBitCount, MACAddress.DEFAULT_TEXTUAL_RADIX);
			newSegIndex = segIndex = 1;
		}
		while(segIndex + 1 < segmentCount) {
			MACAddressSegment segment1 = getSegment(segIndex++);
			MACAddressSegment segment2 = getSegment(segIndex++);
			if(segment1.isMultiple() && !segment2.isFullRange()) {
				throw new AddressTypeException(segment1, segIndex - 2, segment2, segIndex - 1, "ipaddress.error.invalid.joined.ranges");
			}
			AddressDivision newSeg = new AddressBitsDivision(
					(segment1.getLowerSegmentValue() << MACAddress.BITS_PER_SEGMENT) | segment2.getLowerSegmentValue(), 
					(segment1.getUpperSegmentValue() << MACAddress.BITS_PER_SEGMENT) | segment2.getUpperSegmentValue(), 
					newSegmentBitCount,
					MACAddress.DEFAULT_TEXTUAL_RADIX);
			newSegs[newSegIndex++] = newSeg;
		}
		if(segIndex < segmentCount) {
			MACAddressSegment segment = getSegment(segIndex);
			newSegs[newSegIndex] = new AddressBitsDivision(
					segment.getLowerSegmentValue() << MACAddress.BITS_PER_SEGMENT,
					segment.getUpperSegmentValue() << MACAddress.BITS_PER_SEGMENT,
					newSegmentBitCount,
					MACAddress.DEFAULT_TEXTUAL_RADIX);
		}
		AddressDivisionGrouping dottedGrouping;
		if(cachedPrefix == null) {
			dottedGrouping = new AddressDivisionGrouping(newSegs);
		} else {
			Integer prefLength = getPrefixLength();
			dottedGrouping = new AddressDivisionGrouping(newSegs) {{
					cachedPrefix = prefLength;
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
			public MACStringOptions toParams() {
				return new MACStringOptions(base, expandSegments, wildcards, segmentStrPrefix, separator, addrLabel, reverse, splitDigits, uppercase);
			}
		}
	}
}
