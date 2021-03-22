package ipaddr

import "strings"

// An object for writing an address part string in a specific format.
type addressDivisionWriter interface {
	appendDivision(builder *strings.Builder, div AddressStringDivision) *strings.Builder

	getDivisionStringLength(div AddressStringDivision) int
}

// An object for writing an IP address part string in a specific format.
type ipAddressStringWriter interface {
	addressDivisionWriter

	// returns the number of segment separators in the string produced by these params
	getTrailingSeparatorCount(addr IPAddressStringDivisionSeries) int

	getTrailingSegmentSeparator() byte

	//returns the string produced by these params
	toString(addr IPAddressStringDivisionSeries) string

	//returns the string produced by these params
	toZonedString(addr IPAddressStringDivisionSeries, zone string) string
}

// TODO resinstate when you start work on the string building
//func ToNormalizedString(opts IPStringOptions, section IPAddressStringDivisionSeries) {
//	return toIPParams(opts).toString(section)
//}

//protected static IPAddressStringParams<IPAddressStringDivisionSeries> toIPParams(IPStringOptions opts) {
func toIPParams(opts IPStringOptions) (res *ipAddressStringParams) {
	//since the params here are not dependent on the section, we could cache the params in the options
	//this is not true on the IPv6 side where compression settings change based on the section
	options, hasCache := opts.(*ipStringOptions)
	if hasCache {
		res = options.cachedIPAddr
	}
	if res == nil {
		res = &ipAddressStringParams{
			addressStringParams: addressStringParams{
				radix:            opts.GetRadix(),
				separator:        opts.GetSeparator(),
				uppercase:        opts.IsUppercase(),
				expandSegments:   opts.IsExpandedSegments(),
				wildcards:        opts.GetWildcards(),
				segmentStrPrefix: opts.GetSegmentStrPrefix(),
				reverse:          opts.IsReverse(),
				splitDigits:      opts.IsSplitDigits(),
				addressLabel:     opts.GetAddressLabel(),
				zoneSeparator:    opts.GetZoneSeparator(),
			},
			wildcardOption: opts.GetWildcardOption(),
			addressSuffix:  opts.GetAddressSuffix(),
		}
		if hasCache {
			options.cachedIPAddr = res
		}
	}
	return
}

//public static AddressStringParams<AddressStringDivisionSeries> toParams(StringOptions opts) {
func toParams(opts StringOptions) (res *addressStringParams) {
	//since the params here are not dependent on the section, we could cache the params in the options
	//this is not true on the IPv6 side where compression settings change based on the section
	options, hasCache := opts.(*stringOptions)
	if hasCache {
		res = options.cached
	}
	if res == nil {
		res = &addressStringParams{
			radix:            opts.GetRadix(),
			separator:        opts.GetSeparator(),
			uppercase:        opts.IsUppercase(),
			expandSegments:   opts.IsExpandedSegments(),
			wildcards:        opts.GetWildcards(),
			segmentStrPrefix: opts.GetSegmentStrPrefix(),
			addressLabel:     opts.GetAddressLabel(),
			reverse:          opts.IsReverse(),
			splitDigits:      opts.IsSplitDigits(),
		}
		if hasCache {
			options.cached = res
		}
	}
	return
}

//	protected static AddressStringParams<IPAddressStringDivisionSeries> toParams(IPStringOptions opts) {
func toParamsFromIPOptions(opts IPStringOptions) (res *addressStringParams) {
	//since the params here are not dependent on the section, we could cache the params in the options
	//this is not true on the IPv6 side where compression settings change based on the section
	options, hasCache := opts.(*ipStringOptions)
	if hasCache {
		res = options.cachedAddr
	}
	if res == nil {
		res = &addressStringParams{
			radix:            opts.GetRadix(),
			separator:        opts.GetSeparator(),
			uppercase:        opts.IsUppercase(),
			expandSegments:   opts.IsExpandedSegments(),
			wildcards:        opts.GetWildcards(),
			segmentStrPrefix: opts.GetSegmentStrPrefix(),
			addressLabel:     opts.GetAddressLabel(),
			reverse:          opts.IsReverse(),
			splitDigits:      opts.IsSplitDigits(),
			zoneSeparator:    opts.GetZoneSeparator(),
		}
		if hasCache {
			options.cachedAddr = res
		}
	}
	return
}

func (opts *ipv6StringOptions) from(addr *IPv6AddressSection) (res *ipv6StringParams) {
	res = &ipv6StringParams{
		ipAddressStringParams: ipAddressStringParams{
			addressStringParams: addressStringParams{
				radix:            opts.GetRadix(),
				separator:        opts.GetSeparator(),
				uppercase:        opts.IsUppercase(),
				expandSegments:   opts.IsExpandedSegments(),
				wildcards:        opts.GetWildcards(),
				segmentStrPrefix: opts.GetSegmentStrPrefix(),
				reverse:          opts.IsReverse(),
				splitDigits:      opts.IsSplitDigits(),
				addressLabel:     opts.GetAddressLabel(),
				zoneSeparator:    opts.GetZoneSeparator(),
			},
			wildcardOption: opts.GetWildcardOption(),
			addressSuffix:  opts.GetAddressSuffix(),
		},
	}
	if opts.compressOptions != nil {
		makeMixed := opts.makeMixed()
		//vals := addr.getCompressIndexAndCount(opts.GetCompressOptions(), makeMixed)
		//if len(vals) > 0 {
		//	maxIndex := vals[0]
		//	maxCount := vals[1];
		compressOptions := opts.GetCompressOptions()
		maxIndex, maxCount := addr.GetCompressIndexAndCount(compressOptions, makeMixed)
		if maxCount > 0 {
			res.firstCompressedSegmentIndex = maxIndex
			res.nextUncompressedIndex = maxIndex + maxCount
			res.hostCompressed = compressOptions.GetCompressionChoiceOptions().compressHost() &&
				addr.IsPrefixed() &&
				(res.nextUncompressedIndex >
					getHostSegmentIndex(*addr.GetNetworkPrefixLength(), IPv6BytesPerSegment, IPv6BitsPerSegment))
		}
	}
	return res
}

// Each segment params has settings to write exactly one type of IP address part string segment.
type addressSegmentParams interface {
	getWildcards() Wildcards

	preferWildcards() bool

	// returns -1 for as many leading zeros as needed to write the max number of characters per segment,
	// or 0, 1, 2, 3 to indicate the number of leading zeros
	getLeadingZeros(segmentIndex int) int

	getSegmentStrPrefix() string

	getRadix() int

	isUppercase() bool

	isSplitDigits() bool

	getSplitDigitSeparator() byte

	isReverseSplitDigits() bool
}

type addressStringParams struct {
	//protected static class AddressStringParams<T extends AddressStringDivisionSeries> implements AddressDivisionWriter, AddressSegmentParams, Cloneable {

	wildcards      Wildcards
	expandSegments bool //whether to expand 1 to 001 for IPv4 or 0001 for IPv6

	segmentStrPrefix string //eg for inet_aton style there is 0x for hex, 0 for octal

	radix int

	//the segment separator and in the case of split digits, the digit separator
	separator byte
	uppercase bool //whether to print A or a

	//print the segments in reverse, and in the case of splitDigits, print the digits in reverse as well
	reverse bool

	//in each segment, split the digits with the separator, so that 123.456.1.1 becomes 1.2.3.4.5.6.1.1
	splitDigits   bool
	addressLabel  string
	zoneSeparator byte
}

//TODO NEXT next you are trying to do the params conversion from StringOptions to StringParams
// first do the addressStringParams type hierarchy, just the data part, not the string building part
// then do the multiple toIPParams(opts) functions, there are four commented out above
// then onto the string building part (we do have toUnsignedString done already, which is nice

//TODO just assign these fields directly when converting from StringOPtions to stringParams instead of using constructors
//public AddressStringParams(int radix, Character separator, boolean uppercase) {
//	this(radix, separator, uppercase, (char) 0);
//}
//
//public AddressStringParams(int radix, Character separator, boolean uppercase, char zoneSeparator) {
//	this.radix = radix;
//	this.separator = separator;
//	this.uppercase = uppercase;
//	this.zoneSeparator  = zoneSeparator;
//}

//public void setZoneSeparator(char zoneSeparator) {
//	this.zoneSeparator = zoneSeparator;
//}
//
//public String getAddressLabel() {
//	return addressLabel;
//}
//
//public void setAddressLabel(String str) {
//	this.addressLabel = str;
//}
//
//public Character getSeparator() {
//	return separator;
//}
//
//public void setSeparator(Character separator) {
//	this.separator = separator;
//}

func (params *addressStringParams) getWildcards() Wildcards {
	return params.wildcards
}

//public void setWildcards(Wildcards wc) {
//	wildcards = wc;
//}

func (params *addressStringParams) preferWildcards() bool {
	return true
}

//returns -1 to expand
func (params *addressStringParams) getLeadingZeros(segmentIndex int) int {
	if params.expandSegments {
		return -1
	}
	return 0
}

func (params *addressStringParams) getSegmentStrPrefix() string {
	return params.segmentStrPrefix
}

//public void setSegmentStrPrefix(String segmentStrPrefix) {
//	if(segmentStrPrefix == null) {
//		throw new NullPointerException();
//	}
//	this.segmentStrPrefix = segmentStrPrefix;
//}

func (params *addressStringParams) getRadix() int {
	return params.radix
}

//public void setRadix(int radix) {
//	this.radix = radix;
//}
//
//public void setUppercase(boolean uppercase) {
//	this.uppercase = uppercase;
//}

func (params *addressStringParams) isUppercase() bool {
	return params.uppercase
}

//public void setSplitDigits(boolean split) {
//	this.splitDigits = split;
//}

func (params *addressStringParams) isSplitDigits() bool {
	return params.splitDigits
}

func (params *addressStringParams) getSplitDigitSeparator() byte {
	return params.separator
}

func (params *addressStringParams) isReverseSplitDigits() bool {
	return params.reverse
}

//public void setReverse(boolean rev) {
//	this.reverse = rev;
//}
//
//public boolean isReverse() {
//	return reverse;
//}

//public void expandSegments(boolean expand) {
//	expandSegments = expand;
//}

//TODO here we have the machinery to build a string, which calls into the division
// which is passed in, in fact the whole address passed in
// The IPv6 version of this stuff needs to stay in that class, it is aware tht
// it is dealing with a more complicated beast, just gotta be sure
// control does not pass into here from there
// eg call to getSegmentsStringLength calls appendSegment
// if we override appendSegment we must also override getSegmentsStringLength
//		public StringBuilder appendLabel(StringBuilder builder) {
//			String str = getAddressLabel();
//			if(str != null && str.length() > 0) {
//				builder.append(str);
//			}
//			return builder;
//		}
//
//		public int getAddressLabelLength() {
//			String str = getAddressLabel();
//			if(str != null) {
//				return str.length();
//			}
//			return 0;
//		}
//
//		public int getSegmentsStringLength(T part) {
//			int count = 0;
//			if(part.getDivisionCount() != 0) {
//				int divCount = part.getDivisionCount();
//				for(int i = 0; i < divCount; i++) {
//					count += appendSegment(i, null, part);
//				}
//				Character separator = getSeparator();
//				if(separator != null) {
//					count += divCount - 1;
//				}
//			}
//			return count;
//		}
//
//		public StringBuilder appendSegments(StringBuilder builder, T part) {
//			int count = part.getDivisionCount();
//			if(count != 0) {
//				boolean reverse = isReverse();
//				int i = 0;
//				Character separator = getSeparator();
//				while(true) {
//					int segIndex = reverse ? (count - i - 1) : i;
//					appendSegment(segIndex, builder, part);
//					if(++i == count) {
//						break;
//					}
//					if(separator != null) {
//						builder.append(separator);
//					}
//				}
//			}
//			return builder;
//		}
//
//		public int appendSingleDivision(AddressStringDivision seg, StringBuilder builder) {
//			if(builder == null) {
//				return getAddressLabelLength() + seg.getStandardString(0, this, null);
//			}
//			appendLabel(builder);
//			seg.getStandardString(0, this, builder);
//			return 0;
//		}
//
//		protected int appendSegment(int segmentIndex, StringBuilder builder, T part) {
//			AddressStringDivision seg = part.getDivision(segmentIndex);
//			return seg.getStandardString(segmentIndex, this, builder);
//		}
//
//		public int getZoneLength(CharSequence zone) {
//			if(zone != null && zone.length() > 0) {
//				return zone.length() + 1; /* zone separator is one char */
//			}
//			return 0;
//		}
//
//		public int getStringLength(T addr, CharSequence zone) {
//			int result = getStringLength(addr);
//			if(zone != null) {
//				result += getZoneLength(zone);
//			}
//			return result;
//		}
//
//		public int getStringLength(T addr) {
//			return getAddressLabelLength() + getSegmentsStringLength(addr);
//		}
//
//		public StringBuilder appendZone(StringBuilder builder, CharSequence zone) {
//			if(zone != null && zone.length() > 0) {
//				builder.append(zoneSeparator).append(zone);
//			}
//			return builder;
//		}
//
//		public StringBuilder append(StringBuilder builder, T addr, CharSequence zone) {
//			return appendZone(appendSegments(appendLabel(builder), addr), zone);
//		}
//
//		public StringBuilder append(StringBuilder builder, T addr) {
//			return append(builder, addr, null);
//		}
//
//		@Override
//		public int getDivisionStringLength(AddressStringDivision seg) {
//			return appendSingleDivision(seg, null);
//		}
//
//		@Override
//		public StringBuilder appendDivision(StringBuilder builder, AddressStringDivision seg) {
//			appendSingleDivision(seg, builder);
//			return builder;
//		}
//
//		public String toZonedString(T addr, CharSequence zone) {
//			int length = getStringLength(addr, zone);
//			StringBuilder builder = new StringBuilder(length);
//			append(builder, addr, zone);
//			checkLengths(length, builder);
//			return builder.toString();
//		}
//
//		public String toString(T addr) {
//			return toString(addr, null);
//		}
//
//		public static void checkLengths(int length, StringBuilder builder) {
//			//Note: re-enable this when doing development
////				boolean calcMatch = length == builder.length();
////				boolean capMatch = length == builder.capacity();
////				if(!calcMatch || !capMatch) {
////					throw new IllegalStateException("length is " + builder.length() + ", capacity is " + builder.capacity() + ", expected length is " + length);
////				}
//		}

func (params *addressStringParams) clone() *addressStringParams {
	result := *params
	return &result
}

//var _ addressDivisionWriter = &addressStringParams{} TODO reinstate when string building done
var _ addressSegmentParams = &addressStringParams{}

// Each StringParams has settings to write exactly one type of IP address part string.
//protected static class IPAddressStringParams<T extends IPAddressStringDivisionSeries> extends AddressStringParams<T> implements IPAddressStringWriter<T> {
type ipAddressStringParams struct {
	addressStringParams

	//public static final WildcardOption DEFAULT_WILDCARD_OPTION = WildcardOption.NETWORK_ONLY;
	//protected static final int EXTRA_SPACE = 16;

	wildcardOption WildcardOption
	expandSeg      []int //the same as expandSegments but for each segment
	addressSuffix  string
}

//public IPAddressStringParams(int radix, Character separator, boolean uppercase) {
//	this(radix, separator, uppercase, (char) 0);
//}
//
//public IPAddressStringParams(int radix, Character separator, boolean uppercase, char zoneSeparator) {
//	super(radix, separator, uppercase, zoneSeparator);
//}

//public String getAddressSuffix() {
//	return addressSuffix;
//}
//
//public void setAddressSuffix(String suffix) {
//	this.addressSuffix = suffix;
//}

func (params *ipAddressStringParams) preferWildcards() bool {
	return params.wildcardOption == WILDCARDS_ALL
}

//public void setWildcardOption(WildcardOption option) {
//	wildcardOption = option;
//}

func (params *ipAddressStringParams) getExpandedSegmentLength(segmentIndex int) int {
	expandSegment := params.expandSeg
	if expandSegment == nil || len(expandSegment) <= segmentIndex {
		return 0
	}
	return expandSegment[segmentIndex]
}

func (params *ipAddressStringParams) expandSegment(index, expansionLength, segmentCount int) {
	expandSegment := params.expandSeg
	if expandSegment == nil {
		expandSegment = make([]int, segmentCount)
		params.expandSeg = expandSegment
	}
	expandSegment[index] = expansionLength
}

//returns -1 for MAX, or 0, 1, 2, 3 to indicate the string prefix length
func (params *ipAddressStringParams) getLeadingZeros(segmentIndex int) int {
	expandSegment := params.expandSeg
	if params.expandSegments {
		return -1
	} else if expandSegment != nil && len(expandSegment) > segmentIndex {
		return expandSegment[segmentIndex]
	}
	return 0
}

func (params *ipAddressStringParams) getTrailingSegmentSeparator() byte {
	return params.separator
}

//public StringBuilder appendSuffix(StringBuilder builder) {
//	String suffix = getAddressSuffix();
//	if(suffix != null) {
//		builder.append(suffix);
//	}
//	return builder;
//}
//
//public int getAddressSuffixLength() {
//	String suffix = getAddressSuffix();
//	if(suffix != null) {
//		return suffix.length();
//	}
//	return 0;
//}
//@Override
//		public int getTrailingSeparatorCount(T addr) {
//			int count = addr.getDivisionCount();
//			if(count > 0) {
//				return count - 1;
//			}
//			return 0;
//		}
//
//		public static int getPrefixIndicatorStringLength(IPAddressStringDivisionSeries addr) {
//			if(addr.isPrefixed()) {
//				return AddressDivisionBase.toUnsignedStringLengthFast(addr.getPrefixLength(), 10) + 1;
//			}
//			return 0;
//		}
//
//		@Override
//		public int getStringLength(T addr) {
//			int count = getSegmentsStringLength(addr);
//			if(!isReverse() && !preferWildcards()) {
//				count += getPrefixIndicatorStringLength(addr);
//			}
//			return count + getAddressSuffixLength() + getAddressLabelLength();
//		}
//
//		public void appendPrefixIndicator(StringBuilder builder, IPAddressStringDivisionSeries addr) {
//			if(addr.isPrefixed()) {
//				builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(addr.getPrefixLength());
//			}
//		}
//
//		@Override
//		public StringBuilder append(StringBuilder builder, T addr, CharSequence zone) {
//			/*
//			 * Our order is label, then segments, then zone, then suffix, then prefix length.
//			 * This is documented in more detail in IPv6AddressSection for the IPv6-only case.
//			 */
//			appendSuffix(appendZone(appendSegments(appendLabel(builder), addr), zone));
//			if(!isReverse() && !preferWildcards()) {
//				appendPrefixIndicator(builder, addr);
//			}
//			return builder;
//		}
//
//		@Override
//		protected int appendSegment(int segmentIndex, StringBuilder builder, T part) {
//			IPAddressStringDivision seg = part.getDivision(segmentIndex);
//			PrefixConfiguration config = part.getNetwork().getPrefixConfiguration();
//			//consider all the cases in which we need not account for prefix length
//			Integer prefix;
//			if(config.prefixedSubnetsAreExplicit() || preferWildcards()
//					|| (prefix = seg.getDivisionPrefixLength()) == null  || prefix >= seg.getBitCount()
//					|| (config.zeroHostsAreSubnets() && !part.isPrefixBlock())
//					|| isSplitDigits()) {
//				return seg.getStandardString(segmentIndex, this, builder);
//			}
//			//prefix length will have an impact on the string - either we need not print the range at all
//			//because it is equivalent to the prefix length, or we need to adjust the upper value of the
//			//range so that the host is zero when printing the string
//			if(seg.isSinglePrefixBlock()) {
//				return seg.getLowerStandardString(segmentIndex, this, builder);
//			}
//			return seg.getPrefixAdjustedRangeString(segmentIndex, this, builder);
//		}
//public String toZonedString(T addr, CharSequence zone) {
//			int length = getStringLength(addr, zone);
//			StringBuilder builder = new StringBuilder(length);
//			append(builder, addr, zone);
//			checkLengths(length, builder);
//			return builder.toString();
//		}
//
//		public String toString(T addr) {
//			return toString(addr, null);
//		}

func (params *ipAddressStringParams) clone() *ipAddressStringParams {
	result := *params
	expandSegment := params.expandSeg
	if expandSegment != nil {
		result.expandSeg = cloneInts(expandSegment)
	}
	return &result
}

//var _ ipAddressStringWriter = &ipAddressStringParams{} TODO reinstate when string building done

//IPv4StringParams(int radix) {
//	super(radix, IPv4Address.SEGMENT_SEPARATOR, false);
//}

// Each IPv6StringParams has settings to write exactly one IPv6 address section string
//static class IPv6StringParams extends IPAddressStringParams<IPv6AddressSection> {
type ipv6StringParams struct {
	ipAddressStringParams

	firstCompressedSegmentIndex, nextUncompressedIndex int //the start and end of any compressed section

	hostCompressed bool //whether the host was compressed, which with some prefix configurations means we must print the network prefix to indicate that the host is full range
}

//IPv6StringParams() {
//	this(-1, 0);
//}
//
//IPv6StringParams(int firstCompressedSegmentIndex, int compressedCount) {
//	this(false, firstCompressedSegmentIndex, compressedCount, false, IPv6Address.SEGMENT_SEPARATOR, IPv6Address.ZONE_SEPARATOR);
//}

//private IPv6StringParams(
//		boolean expandSegments,
//		int firstCompressedSegmentIndex,
//		int compressedCount,
//		boolean uppercase,
//		char separator,
//		char zoneSeparator) {
//	super(IPv6Address.DEFAULT_TEXTUAL_RADIX, separator, uppercase, zoneSeparator);
//	this.expandSegments(expandSegments);
//	this.firstCompressedSegmentIndex = firstCompressedSegmentIndex;
//	this.nextUncompressedIndex = firstCompressedSegmentIndex + compressedCount;
//}

func (params *ipv6StringParams) endIsCompressed(addr IPAddressStringDivisionSeries) bool {
	return params.nextUncompressedIndex >= addr.GetDivisionCount()
}

func (params *ipv6StringParams) isCompressed(addr IPAddressStringDivisionSeries) bool {
	return params.firstCompressedSegmentIndex >= 0
}

func (params *ipv6StringParams) getTrailingSeparatorCount(addr *IPv6AddressSection) int {
	return params.getTrailingSepCount(addr)
}

func (params *ipv6StringParams) getTrailingSepCount(addr IPAddressStringDivisionSeries) int {
	divisionCount := addr.GetDivisionCount()
	if divisionCount == 0 {
		return 0
	}
	count := divisionCount - 1 //separators with no compression
	if params.isCompressed(addr) {
		firstCompressedSegmentIndex := params.firstCompressedSegmentIndex
		nextUncompressedIndex := params.nextUncompressedIndex
		count -= (nextUncompressedIndex - firstCompressedSegmentIndex) - 1 //missing seps
		if firstCompressedSegmentIndex == 0 /* additional separator at front */ ||
			nextUncompressedIndex >= divisionCount /* additional separator at end */ {
			count++
		}
	}
	return count
}

//@Override
//public int getStringLength(IPv6AddressSection addr) {
//	int count = getSegmentsStringLength(addr);
//	if(!isReverse() && (!preferWildcards() || hostCompressed)) {
//		count += getPrefixIndicatorStringLength(addr);
//	}
//	count += getAddressSuffixLength();
//	count += getAddressLabelLength();
//	return count;
//}
//
//@Override
//public StringBuilder append(StringBuilder builder, IPv6AddressSection addr, CharSequence zone) {
//	/*
//	 * Our order is label, then segments, then zone, then suffix, then prefix length.
//	 */
//	appendSuffix(appendZone(appendSegments(appendLabel(builder), addr), zone));
//	if(!isReverse() && (!preferWildcards() || hostCompressed)) {
//		appendPrefixIndicator(builder, addr);
//	}
//	return builder;
//}
//
// /**
// * @see inet.ipaddr.format.util.IPAddressPartStringCollection.IPAddressStringParams#appendSegments(java.lang.StringBuilder, inet.ipaddr.format.string.IPAddressStringDivisionSeries)
// */
//@Override
//public StringBuilder appendSegments(StringBuilder builder, IPv6AddressSection addr) {
//	int divisionCount = addr.getDivisionCount();
//	if(divisionCount <= 0) {
//		return builder;
//	}
//	int lastIndex = divisionCount - 1;
//	Character separator = getSeparator();
//	boolean reverse = isReverse();
//	int i = 0;
//	while(true) {
//		int segIndex = reverse ? lastIndex - i : i;
//		if(segIndex < firstCompressedSegmentIndex || segIndex >= nextUncompressedIndex) {
//			appendSegment(segIndex, builder, addr);
//			if(++i > lastIndex) {
//				break;
//			}
//			if(separator != null) {
//				builder.append(separator);
//			}
//		} else {
//			if(segIndex == (reverse ? nextUncompressedIndex - 1 :  firstCompressedSegmentIndex) && separator != null) { //the segment is compressed
//				builder.append(separator);
//				if(i == 0) {//when compressing the front we use two separators
//					builder.append(separator);
//				}
//			} //else we are in the middle of a compressed set of segments, so nothing to write
//			if(++i > lastIndex) {
//				break;
//			}
//		}
//	}
//	return builder;
//}
//
//@Override
//public int getSegmentsStringLength(IPv6AddressSection part) {
//	int count = 0;
//	int divCount = part.getDivisionCount();
//	if(divCount != 0) {
//		Character separator = getSeparator();
//		int i = 0;
//		while(true) {
//			if(i < firstCompressedSegmentIndex || i >= nextUncompressedIndex) {
//				count += appendSegment(i, null, part);
//				if(++i >= divCount) {
//					break;
//				}
//				if(separator != null) {
//					count++;
//				}
//			} else {
//				if(i == firstCompressedSegmentIndex && separator != null) { //the segment is compressed
//					count++;
//					if(i == 0) {//when compressing the front we use two separators
//						count++;
//					}
//				} //else we are in the middle of a compressed set of segments, so nothing to write
//				if(++i >= divCount) {
//					break;
//				}
//			}
//		}
//	}
//	return count;
//}

func (params *ipv6StringParams) clone() *ipv6StringParams {
	res := *params
	res.ipAddressStringParams = *res.ipAddressStringParams.clone()
	return &res
}
