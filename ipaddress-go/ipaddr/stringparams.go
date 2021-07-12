package ipaddr

import (
	"strings"
	"sync/atomic"
	"unsafe"
)

// An object for writing an address part string in a specific format.
//type addressDivisionWriter interface {
//	appendDivision(builder *strings.Builder, div AddressStringDivision) *strings.Builder
//
//	getDivisionStringLength(div AddressStringDivision) int
//}
//
//// An object for writing an IP address part string in a specific format.
//type ipAddressStringWriter interface {
//	addressDivisionWriter
//
//	// returns the number of segment separators in the string produced by these params
//	getTrailingSeparatorCount(addr IPAddressStringDivisionSeries) int
//
//	getTrailingSegmentSeparator() byte
//
//	//returns the string produced by these params
//	toString(addr IPAddressStringDivisionSeries) string
//
//	//returns the string produced by these params
//	toZonedString(addr IPAddressStringDivisionSeries, zone string) string
//}

func toNormalizedIPZonedString(opts IPStringOptions, section AddressDivisionSeries, zone Zone) string {
	return toIPParams(opts).toZonedString(section, zone)
}

func toNormalizedIPString(opts IPStringOptions, section AddressDivisionSeries) string {
	return toIPParams(opts).toString(section)
}

func toNormalizedString(opts StringOptions, section AddressDivisionSeries) string {
	return toParams(opts).toString(section)
}

//protected static IPAddressStringParams<IPAddressStringDivisionSeries> toIPParams(IPStringOptions opts) {
func toIPParams(opts IPStringOptions) (res *ipAddressStringParams) {
	//since the params here are not dependent on the section, we could cache the params in the options
	//this is not true on the IPv6 side where compression settings change based on the section
	options, hasCache := opts.(*ipStringOptions)
	if hasCache {
		res = options.cachedIPAddr
	}
	if res == nil {
		radix, wildcards, separator, zoneSeparator := getDefaults(opts.GetRadix(), opts.GetWildcards(), opts.GetSeparator(), opts.GetZoneSeparator())
		res = &ipAddressStringParams{
			addressStringParams: addressStringParams{
				radix:            radix,
				separator:        separator,
				hasSep:           opts.HasSeparator(),
				uppercase:        opts.IsUppercase(),
				expandSegments:   opts.IsExpandedSegments(),
				wildcards:        wildcards,
				segmentStrPrefix: opts.GetSegmentStrPrefix(),
				reverse:          opts.IsReverse(),
				splitDigits:      opts.IsSplitDigits(),
				addressLabel:     opts.GetAddressLabel(),
				zoneSeparator:    zoneSeparator,
			},
			wildcardOption: opts.GetWildcardOption(),
			addressSuffix:  opts.GetAddressSuffix(),
		}
		if hasCache {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&options.cachedIPAddr))
			atomic.StorePointer(dataLoc, unsafe.Pointer(res))
		}
	}
	return
}

func getDefaults(radix int, wildcards Wildcards, separator, zoneSeparator byte) (int, Wildcards, byte, byte) {
	if radix == 0 {
		radix = 16
	}
	if wildcards == nil {
		wildcards = DefaultWildcards
	}
	if separator == 0 {
		separator = ' '
	}
	if zoneSeparator == 0 {
		zoneSeparator = IPv6ZoneSeparator
	}
	return radix, wildcards, separator, zoneSeparator
}

func toParams(opts StringOptions) (res *addressStringParams) {
	//since the params here are not dependent on the section, we could cache the params in the options
	//this is not true on the IPv6 side where compression settings change based on the section
	options, hasCache := opts.(*stringOptions)
	if hasCache {
		res = options.cached
	}
	if res == nil {
		radix, wildcards, separator, _ := getDefaults(opts.GetRadix(), opts.GetWildcards(), opts.GetSeparator(), 0)
		res = &addressStringParams{
			radix:            radix,
			separator:        separator,
			hasSep:           opts.HasSeparator(),
			uppercase:        opts.IsUppercase(),
			expandSegments:   opts.IsExpandedSegments(),
			wildcards:        wildcards,
			segmentStrPrefix: opts.GetSegmentStrPrefix(),
			addressLabel:     opts.GetAddressLabel(),
			reverse:          opts.IsReverse(),
			splitDigits:      opts.IsSplitDigits(),
		}
		if hasCache {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&options.cached))
			atomic.StorePointer(dataLoc, unsafe.Pointer(res))
		}
	}
	return
}

func toParamsFromIPOptions(opts IPStringOptions) (res *addressStringParams) {
	//since the params here are not dependent on the section, we could cache the params in the options
	//this is not true on the IPv6 side where compression settings change based on the section
	options, hasCache := opts.(*ipStringOptions)
	if hasCache {
		res = options.cachedAddr
	}
	if res == nil {
		radix, wildcards, separator, zoneSeparator := getDefaults(opts.GetRadix(), opts.GetWildcards(), opts.GetSeparator(), opts.GetZoneSeparator())
		res = &addressStringParams{
			radix:            radix,
			separator:        separator,
			hasSep:           opts.HasSeparator(),
			uppercase:        opts.IsUppercase(),
			expandSegments:   opts.IsExpandedSegments(),
			wildcards:        wildcards,
			segmentStrPrefix: opts.GetSegmentStrPrefix(),
			addressLabel:     opts.GetAddressLabel(),
			reverse:          opts.IsReverse(),
			splitDigits:      opts.IsSplitDigits(),
			zoneSeparator:    zoneSeparator,
		}
		if hasCache {
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&options.cachedAddr))
			atomic.StorePointer(dataLoc, unsafe.Pointer(res))
		}
	}
	return
}

func (opts *ipv6StringOptions) from(addr *IPv6AddressSection) (res *ipv6StringParams) {
	radix, wildcards, separator, zoneSeparator := getDefaults(opts.GetRadix(), opts.GetWildcards(), opts.GetSeparator(), opts.GetZoneSeparator())
	res = &ipv6StringParams{
		ipAddressStringParams: ipAddressStringParams{
			addressStringParams: addressStringParams{
				radix:            radix,
				separator:        separator,
				hasSep:           opts.HasSeparator(),
				uppercase:        opts.IsUppercase(),
				expandSegments:   opts.IsExpandedSegments(),
				wildcards:        wildcards,
				segmentStrPrefix: opts.GetSegmentStrPrefix(),
				reverse:          opts.IsReverse(),
				splitDigits:      opts.IsSplitDigits(),
				addressLabel:     opts.GetAddressLabel(),
				zoneSeparator:    zoneSeparator,
			},
			wildcardOption: opts.GetWildcardOption(),
			addressSuffix:  opts.GetAddressSuffix(),
		},
	}
	if opts.compressOptions != nil {
		compressOptions := opts.GetCompressOptions()
		maxIndex, maxCount := addr.getCompressIndexAndCount(compressOptions, opts.makeMixed())
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

type divStringProvider interface {
	getLowerStringLength(radix int) int

	getUpperStringLength(radix int) int

	getLowerString(radix int, uppercase bool, appendable *strings.Builder)

	getLowerStringChopped(radix int, choppedDigits int, uppercase bool, appendable *strings.Builder)

	getUpperString(radix int, uppercase bool, appendable *strings.Builder)

	getUpperStringMasked(radix int, uppercase bool, appendable *strings.Builder)

	getSplitLowerString(radix int, choppedDigits int, uppercase bool,
		splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder)

	getSplitRangeString(rangeSeparator string, wildcard string, radix int, uppercase bool,
		splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string, appendable *strings.Builder) IncompatibleAddressError

	getSplitRangeStringLength(rangeSeparator string, wildcard string, leadingZeroCount int, radix int, uppercase bool,
		splitDigitSeparator byte, reverseSplitDigits bool, stringPrefix string) int

	getRangeDigitCount(radix int) int

	// if leadingZeroCount is -1, returns the number of leading zeros for maximum width, based on the width of the value
	adjustLowerLeadingZeroCount(leadingZeroCount int, radix int) int

	// if leadingZeroCount is -1, returns the number of leading zeros for maximum width, based on the width of the value
	adjustUpperLeadingZeroCount(leadingZeroCount int, radix int) int

	getMaxDigitCountRadix(radix int) int

	// returns the default radix for textual representations of addresses (10 for IPv4, 16 for IPv6)
	getDefaultTextualRadix() int // put this in divisionValues perhaps?  or use addrType

	// returns the number of digits for the maximum possible value of the division when using the default radix
	getMaxDigitCount() int

	// A simple string using just the lower value and the default radix.
	getDefaultLowerString() string

	// A simple string using just the lower and upper values and the default radix, separated by the default range character.
	getDefaultRangeString() string

	// This is the wildcard string to be used when producing the default strings with getString() or getWildcardString()
	//
	// Since no parameters for the string are provided, default settings are used, but they must be consistent with the address.
	//
	// For instance, generally the '*' is used as a wildcard to denote all possible values for a given segment,
	// but in some cases that character is used for a segment separator.
	//
	// Note that this only applies to "default" settings, there are additional string methods that allow you to specify these separator characters.
	// Those methods must be aware of the defaults as well, to know when they can defer to the defaults and when they cannot.
	//getDefaultSegmentWildcardString() string //not sure this needs to be here

	// This is the wildcard string to be used when producing the default strings with getString() or getWildcardString()
	//
	// Since no parameters for the string are provided, default settings are used, but they must be consistent with the address.
	//
	//For instance, generally the '-' is used as a range separator, but in some cases that character is used for a segment separator.
	//
	// Note that this only applies to "default" settings, there are additional string methods that allow you to specify these separator characters.
	// Those methods must be aware of the defaults as well, to know when they can defer to the defaults and when they cannot.
	getDefaultRangeSeparatorString() string
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

	hasSeparator() bool

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
	hasSep    bool // whether there is a separator at all
	uppercase bool //whether to print A or a

	//print the segments in reverse, and in the case of splitDigits, print the digits in reverse as well
	reverse bool

	//in each segment, split the digits with the separator, so that 123.456.1.1 becomes 1.2.3.4.5.6.1.1
	splitDigits   bool
	addressLabel  string
	zoneSeparator byte
}

// the setters and getters and constructors not implemented can be deleted, I only need the builder functions really

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

func (params *addressStringParams) hasSeparator() bool {
	return params.hasSep
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

// here we have the machinery to build a string, which calls into the division
// which is passed in, in fact the whole address passed in
// The IPv6 version of this stuff needs to stay in that class, it is aware tht
// it is dealing with a more complicated beast, just gotta be sure
// control does not pass into here from there
// eg call to getSegmentsStringLength calls appendSegment
// if we override appendSegment we must also override getSegmentsStringLength
//
// OK in more detail:
// there are 3 levels of these functions:
//AddressStringParams
//IPAddressStringParams - handles prefixes, for which you need isFullRange, isPrefixBlock, isSinglePrefixBlock, getPrefixAdjustedRangeString
//IPv6AddressStringParams - handles compression, for which you need your getZeroSegments amd getCompressIndexAndCount
//
// you will need to provide an independent set of these three functions for each level
// which will call into the corresponding types on the division and segment side
// the types will be interfaces at the two bottom levels:
// - AddressStringDivisionSeries for all divisions
//		This can use DivisionType
//		I believe I can merge AddressDivisionSeries/AddressStringDivisionSeries DivisionType/AddressStringDivision
//		But, for the time being, can keep those 4 types. merge them later
// - IPAddressDivisionSeries, an interface to represent the ip div/seg types
//		IPAddressSection, IPv4AddressSection, IPv6AddressSection, IPAddressLargeDivision
//		this interface will have a method to return IPAddressStringDivision, segments with prefix length functions
//		This will need a new method GetIPDivision() IPAddressStringDivision
// - the highest level can use IPv6AddressSection
//
// In both params and div side, I need to ensure my methods avoid the virtual method trap,
// where SubTypeX method subx calls ParentTypeY parenty which calls ParentTypeY parentz which is supposed to be overridden in SubTypeX
// In go I'll just have to use one of the several tricks, see #2 and #3 in: IDEAS for replacing virtual methods
//
// In Java it's a little bit easier to have those extra interfaces for strings.
// The reason is the way you can have the same method getDivision return different things in different types.
// In go you need to create duplicate methods, getStringDIvision, getGenericDivision, etc, to return the different interface types
//

// next let's figure out what methods we override in the division classes
// it seems isPrefixBlock() and isSinglePrefixBlock() are not part of the overriding stucture, they are simply called from the params classes
// Overridden:
// IPAddressDivision:
//		getUpperStringMasked,
//		getStringAsLower which is really getDefaultLowerString,
//		getWildcardString,
//		getString
// IPAddressSegment: getDefaultSegmentWildcardString

// getStandardString -> getLowerStandardString -> getStringAsLower
// getRangeStringCounts -> getRangeStringSep -> getUpperStringMasked
//
// getDefaultRangeString -> getDefaultRangeStringVals -> buildDefaultRangeString -> getRangeStringSep

// getString -> getDefaultRangeStringVals
// getString -> getDefaultRangeString
// getWildcardString -> getDefaultRangeString
// getWildcardString -> getString
// getDefaultRangeString -> getDefaultRangeStringVals
// getDefaultRangeStringVals -> buildDefaultRangeString -> getRangeStringSep
// getPrefixAdjustedRangeString -> getString
// getRangeString -> getWildcardString
// getStandardString -> getRangeString
// getStandardString -> getLowerStandardString

//xxx So how to handle the above? xxx
//you have basically two entry points, getStandardString and getLowerStandardString
//	plus a third in ipv6, getPrefixAdjustedRangeString
//these entrypoints call a sequence of methods that eventually hit a few selection overridden methods
// One option is to use func pointers inside the div types, put this requires initialization of those func pointers,
//		which is a PITA
// One option is to duplicate the methods leaning up to those calls, which I think is a non-starter
// One option is to put those select funcs into an interface and pass it in to the params,
//		and then pass that interface in to those entry points
//		and the type itself can be either the div type, or instead some separate type
//		But those interface methods also need to pass the same interface back as they call further methods
//		YOu have basically two sets of methods.  One is the shared set.  The second is the interface set, not shared.
//		I think both sets likely need access to the div types themselves, as well
//		hmmmmm
//		Obviously using enough interfaces and/or function ptr arguments should do the trick
//		Just need to figure out the best/simplest pattern
//		OK, I think I got it, you create a new wrapper type
//		The wrapper type as both methods and function pointers, both.
//		You create and initialize this type in the params at the entry points.
//		You call into this type as the new entry points.
//		It is basically the equivalent of an abstract class.
//		The shared methods are part of this new type and are in this new type.
//
//		type StringWriter {
//			func1(StringWriter, args) //examples are getString and getWildcardString
//			func2(StringWriter, args)
//
//			At this time I am not so sure any of the funcs need to call back into StringWriter.
// 			If they call into other methods on the same division type, that is generally ok.
//			Hold on: getWildcardString -> getDefaultRangeString -> getDefaultRangeStringVals -> buildDefaultRangeString -> getRangeStringSep -> getUpperStringMasked
//				getString -> getDefaultRangeStringVals -> buildDefaultRangeString -> getRangeStringSep -> getUpperStringMasked
//			The other problem is that some of these methods like getString() are public methods in the division,
//			so passing in a StringWriter is a no-go
//			So I need to ensure they don't need the StringWriter callback
//			IN tehse cases, the problem is the call to getRangeStringSep
//			But the overriding getUpperStringMasked not needed there
//			nor here:
//			getStandardString -> getRangeString -> getRangeStringCounts -> getRangeStringSep -> getUpperStringMasked
//			But it is needed here:
//			getPrefixAdjustedRangeString -> getRangeStringCounts -> getRangeStringSep -> getUpperStringMasked
//			In those cases, I can pass the StringWriter.  Do I want to?
//			No, because nothing in that chain is another one of the function pointers, BUT
//				getRangeStringSep is supposed to be inside the divs, since it is also called by getString
//			So.... Is there a case of getString, getWildcardString, getStringAsLower, getLowerString calling another overridden method in the list?
//			checking IPAddressDivision,
//				I think getString() is OK - getDefaultSegmentWildcardString would have been a problem but since IPAddressDivision merged to IPAddressSection, it's not
//				getWildcardString is OK
//				getStringAsLower is OK
//
//			So looks like getRangeStringSep is the only issue (I think), it needs to be in the divs, but it needs the StringWriter passed too for using getUpperStringMasked
//			it is in a parent class calling up into the sub class
//			We need to avoid the callbacks
//		}
//
//		func (StringWriter) method1() {} //entry points and other shared methods
//		func (StringWriter) method2() {}
//
//		in the params, you take the AddressDivisionSeries or the other IPAddressDivisionSeries or the IPv6AddressSection,
//		you call a method that creates this type (or gets the stored one) from it, then you call into that provided object
//
//		So, you could have done the Java side this way as well, which you kinda did.
//		The only diff is that the new type is separated from the original in go.
//		In java you could separate there too, but that would then require the creation of this new object at some point, and you'd store it as well.
//		By merging into the original classes in Java, you avoid that.
//

// LARGE vs STANDARD
// NOte, it seems a whole bunch of other methods are overridden in IPAddressLargeDivision, call them the L set
// That is largely the reason for the existence of AddressDivisionBase
// BUT, really they are all called by getStandardString and getLowerStandardString
// So, to replicate that, you have to worry about just those two methods
// And they are both the two entry points to producing ip division strings
// So in the end, you might want to have wrapper methods for those two in each of large and standard ip divisions,
// the wrappers will call general funcs, passing in the *AddressDivisionBase as an argument,
// the func parameter will be an interface that has all those L set methods,
// and then you can just have the implementations in the large and standard ip division types
// So that takes care of large vs standard
//
//  we want the pattern above, but we need more thought into this
// Actually, the statement that "they are all called by getStandardString and getLowerStandardString"
//	is not really true.  But in the end, you can likely reuse the same solution as I use above for the abstract stuff in general.
//	You will just need an expanded set of function pointers.
//	BUT you will once again have the same problem with getRangeStringSep, but with more functions, not just getUpperStringMasked
//
// buildDefaultRangeString and the like is an issue, it creates a StringBuilder to call into some of these shared funcs
// It seems to be the only one that does that
// I think that is key.  I think that you might want to instead cause that to use the full StringWriter framework.
// But do we want things like getString to be plugging into the full StringWriter framework, while at the same time being clients of it?
// Not really.
// Still confused here what to do.
// We want, once you are inside the divs, to not want to be pulled back int the StringWriter framework.
// Or, another way of looking at it, we want those secondary methods like getUpperStringMasked, getUpperString, etc,
// to NOT be abstract in the sense we go from general lower function to something more specialized
//
// Maybe two frameworks?  Yeah, you might need two.
// One, call it FL for framework lower, is for those lower level getUpperStringMasked, getUpperString.
// The other, call it FU for framework upper, is for the other methods that are called by the entry points, which is getString, getWildcardString.
// We've already figured how how FU works:
//
//		type StringWriter {
//			func1(args) //examples are getString and getWildcardString
//			func2(args)
//		}
//
//		func (StringWriter) method1() {} //entry points and other shared methods used by the params.  eg getStandardString.
//		func (StringWriter) method2() {}
//
// Now, for LU, we are inside high level methods like getString, and we want to call methods like getDefaultRangeString and getDefaultRangeStringVals
// Those are methods in base classes that eventually call methods overridden
// So here we want to use another framework.  We need those methods to take an interface that points to the overriden methods.
//	Yeah:
//		type StringProducer interface {
//			getUpperStringMasked string
//			getUpperString string
//		}
//  The shared lower methods must take this as an arg.  Not only that, the FU must also use one of these, since it too calls into them.
// This is tactic 1 of "IDEAS for replacing virtual methods".  Any method that calls an abstract or an overridden method,
//	either directly or indirectly, must use this tactic.  The method must either pass along the StringProducer (if it is lower level), or create it (if higher level).
// If a method is lower level but cannot pass it along, you must replicate the same method at a higher level.
// buildDefaultRangeString is one example, it must pass in this StringProducer.
//
//  this will work.  Use the FU LU frameworks.  The lower level functions that take StringProducer can be methods or functions.  Methods if they need lower level data, functions otherwise.
//
/*
	type StringWriter {
		StringProducer

		// function fields:
		func1(args) //examples to go here are getString and getWildcardString
		func2(args)	// anything these call inside the divs can create their own StringProducer objs to call shared methods in the divs
	}

	func (StringWriter) method1() {} //entry points and other shared methods used by the params.  eg getStandardString.
	func (StringWriter) method2() {}

	type StringProducer interface { // each of IPSegment, IPLargeDivision, Division gets mapped to this interface
		getUpperStringMasked string
		getUpperString string
		// the other abstract methods in AddressDivisionBase
	}

	In the end, this code might be cleaner than the Java code, although the callback tacking of using StringProducer objs as args is less clean that the Java code

*/

//
// These methods are overridden in IPAddressSegment, overriding default behaviour in AddressDivision
//		getUpperStringMasked,
//		getStringAsLower which is really getDefaultLowerString,
//		getWildcardString,
//		getString

//
//
//
//
//
//
//
//

//var (
//	_, _ divStringProvider = &AddressDivision{}, &IPAddressSegment{}
//)

func (params *addressStringParams) getSegmentsStringLength(part AddressDivisionSeries) int {
	count := 0
	divCount := part.GetDivisionCount()
	if divCount != 0 {
		for i := 0; i < divCount; i++ {
			count += params.appendSegment(i, nil, part)
		}
		//Character separator = getSeparator();
		if params.hasSep {
			count += divCount - 1 // the number of separators
		}
	}
	return count
}

func (params *addressStringParams) appendSegments(builder *strings.Builder, part AddressDivisionSeries) *strings.Builder {
	divCount := part.GetDivisionCount()
	if divCount != 0 {
		reverse := params.reverse
		i := 0
		hasSeparator := params.hasSep
		separator := params.separator
		for {
			segIndex := i
			if reverse {
				segIndex = divCount - i - 1
			}
			params.appendSegment(segIndex, builder, part)
			i++
			if i == divCount {
				break
			}
			if hasSeparator {
				builder.WriteByte(separator)
			}
		}
	}
	return builder
}

func (params *addressStringParams) appendSingleDivision(seg DivisionType, builder *strings.Builder) int {
	writer := stringWriter{seg}
	if builder == nil {
		return params.getAddressLabelLength() + writer.getStandardString(0, params, nil)
	}
	params.appendLabel(builder)
	writer.getStandardString(0, params, builder)
	return 0
}

func (params *addressStringParams) getDivisionStringLength(seg DivisionType) int {
	return params.appendSingleDivision(seg, nil)
}

func (params *addressStringParams) appendDivision(builder *strings.Builder, seg DivisionType) *strings.Builder {
	params.appendSingleDivision(seg, builder)
	return builder
}

func (params *addressStringParams) appendSegment(segmentIndex int, builder *strings.Builder, part AddressDivisionSeries) int {
	div := part.GetGenericDivision(segmentIndex)
	writer := stringWriter{div}
	return writer.getStandardString(segmentIndex, params, builder)
}

func (params *addressStringParams) getZoneLength(zone Zone) int {
	if zone != noZone {
		return len(zone) + 1 /* zone separator is one char */
	}
	return 0
}

func (params *addressStringParams) getZonedStringLength(addr AddressDivisionSeries, zone Zone) int {
	result := params.getStringLength(addr)
	if zone != noZone {
		result += params.getZoneLength(zone)
	}
	return result
}

func (params *addressStringParams) getStringLength(addr AddressDivisionSeries) int {
	return params.getAddressLabelLength() + params.getSegmentsStringLength(addr)
}

func (params *addressStringParams) appendZone(builder *strings.Builder, zone Zone) *strings.Builder {
	if zone != noZone {
		builder.WriteByte(params.zoneSeparator)
		builder.WriteString(string(zone))
	}
	return builder
}

func (params *addressStringParams) appendZoned(builder *strings.Builder, addr AddressDivisionSeries, zone Zone) *strings.Builder {
	params.appendLabel(builder)
	params.appendSegments(builder, addr)
	params.appendZone(builder, zone)
	return builder
}

func (params *addressStringParams) append(builder *strings.Builder, addr AddressDivisionSeries) *strings.Builder {
	return params.appendZoned(builder, addr, noZone)
}

func (params *addressStringParams) toZonedString(addr AddressDivisionSeries, zone Zone) string {
	length := params.getZonedStringLength(addr, zone)
	builder := &strings.Builder{}
	builder.Grow(length)
	params.appendZoned(builder, addr, zone)
	checkLengths(length, builder)
	return builder.String()
}

func (params *addressStringParams) appendLabel(builder *strings.Builder) *strings.Builder {
	str := params.addressLabel
	if str != "" {
		builder.WriteString(str)
	}
	return builder
}

func (params *addressStringParams) getAddressLabelLength() int {
	return len(params.addressLabel)
}

func (params *addressStringParams) toString(addr AddressDivisionSeries) string {
	return params.toZonedString(addr, noZone) //TODO I think this might be no longer necessary, we should move the zone stuff up now
}

//
func checkLengths(length int, builder *strings.Builder) {
	//Note: re-enable this when doing development
	//				 calcMatch := length == builder.length();
	//				 capMatch := length == builder.capacity();
	//				if(!calcMatch || !capMatch) {
	//					throw new IllegalStateException("length is " + builder.length() + ", capacity is " + builder.capacity() + ", expected length is " + length);
	//				}
}

func (params *addressStringParams) clone() *addressStringParams {
	result := *params
	return &result
}

//var _ addressDivisionWriter = &addressStringParams{}
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

func (params *ipAddressStringParams) appendSuffix(builder *strings.Builder) *strings.Builder {
	suffix := params.addressSuffix
	if len(suffix) > 0 {
		builder.WriteString(suffix)
	}
	return builder
}

func (params *ipAddressStringParams) getAddressSuffixLength() int {
	suffix := params.addressSuffix
	return len(suffix)
}

func (params *ipAddressStringParams) getTrailingSeparatorCount(addr AddressDivisionSeries) int {
	count := addr.GetDivisionCount()
	if count > 0 {
		return count - 1
	}
	return 0
}

func getPrefixIndicatorStringLength(addr AddressDivisionSeries) int {
	if addr.IsPrefixed() {
		return toUnsignedStringLengthFast(uint16(*addr.GetPrefixLength()), 10) + 1
	}
	return 0
}

func (params *ipAddressStringParams) getSegmentsStringLength(part AddressDivisionSeries) int {
	count := 0
	divCount := part.GetDivisionCount()
	if divCount != 0 {
		prefLen := part.GetPrefixLength()
		for i := 0; i < divCount; i++ {
			div := part.GetGenericDivision(i)
			count += params.appendSegment(i, div, prefLen, nil, part)
			if prefLen != nil {
				prefLen = cacheBitCount(*prefLen - div.GetBitCount())
			}
		}
		if params.hasSep {
			count += divCount - 1 // the number of separators
		}
	}
	return count
}

func (params *ipAddressStringParams) getStringLength(addr AddressDivisionSeries) int {
	count := params.getSegmentsStringLength(addr)
	if !params.reverse && !params.preferWildcards() {
		count += getPrefixIndicatorStringLength(addr)
	}
	return count + params.getAddressSuffixLength() + params.getAddressLabelLength()
}

func (params *ipAddressStringParams) appendPrefixIndicator(builder *strings.Builder, addr AddressDivisionSeries) *strings.Builder {
	if addr.IsPrefixed() {
		builder.WriteByte(PrefixLenSeparator)
		return toUnsignedStringCased(uint64(*addr.GetPrefixLength()), 10, 0, false, builder)
	}
	return builder
}

func (params *ipAddressStringParams) appendSegments(builder *strings.Builder, part AddressDivisionSeries) *strings.Builder {
	divCount := part.GetDivisionCount()
	if divCount != 0 {
		prefLen := part.GetPrefixLength()
		reverse := params.reverse
		i := 0
		hasSeparator := params.hasSep
		separator := params.separator
		for {
			segIndex := i
			if reverse {
				segIndex = divCount - i - 1
			}
			div := part.GetGenericDivision(segIndex)
			params.appendSegment(segIndex, div, prefLen, builder, part)
			if prefLen != nil {
				prefLen = cacheBitCount(*prefLen - div.GetBitCount())
			}
			i++
			if i == divCount {
				break
			}
			if hasSeparator {
				builder.WriteByte(separator)
			}
		}
	}
	return builder
}

func (params *ipAddressStringParams) append(builder *strings.Builder, addr AddressDivisionSeries, zone Zone) *strings.Builder {
	params.appendSuffix(params.appendZone(params.appendSegments(params.appendLabel(builder), addr), zone))
	if !params.reverse && !params.preferWildcards() {
		params.appendPrefixIndicator(builder, addr)
	}
	return builder
}

func (params *ipAddressStringParams) appendSegment(segmentIndex int, div DivisionType, divPrefixLen PrefixLen, builder *strings.Builder, part AddressDivisionSeries) int {
	//div := part.GetGenericIPDivision(segmentIndex)
	writer := stringWriter{div}
	//prefixLen := div.GetSegmentPrefixLength()
	// consider all the cases in which we need not account for prefix length
	if params.preferWildcards() ||
		divPrefixLen == nil ||
		*divPrefixLen >= div.GetBitCount() ||
		!part.IsPrefixBlock() ||
		params.isSplitDigits() {
		return writer.getStandardString(segmentIndex, params, builder)
	}
	// prefix length will have an impact on the string - either we need not print the range at all
	// because it is equivalent to the prefix length, or we need to adjust the upper value of the
	// range so that the host is zero when printing the string
	if div.ContainsSinglePrefixBlock(*divPrefixLen) {
		// if div.IsSinglePrefixBlock() {
		return writer.getLowerStandardString(segmentIndex, params, builder)
	}
	return writer.getPrefixAdjustedRangeString(segmentIndex, params, builder)
}

func (params *ipAddressStringParams) getZonedStringLength(addr AddressDivisionSeries, zone Zone) int {
	result := params.getStringLength(addr)
	if zone != noZone {
		result += params.getZoneLength(zone)
	}
	return result
}

func (params *ipAddressStringParams) toZonedString(addr AddressDivisionSeries, zone Zone) string {
	length := params.getZonedStringLength(addr, zone)
	builder := strings.Builder{}
	builder.Grow(length)
	params.append(&builder, addr, zone)
	checkLengths(length, &builder)
	return builder.String()
}

func (params *ipAddressStringParams) toString(addr AddressDivisionSeries) string {
	return params.toZonedString(addr, noZone)
}

func (params *ipAddressStringParams) clone() *ipAddressStringParams {
	result := *params
	expandSegment := params.expandSeg
	if expandSegment != nil {
		result.expandSeg = cloneInts(expandSegment)
	}
	return &result
}

//var _ ipAddressStringWriter = &ipAddressStringParams{}

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

func (params *ipv6StringParams) endIsCompressed(addr IPAddressSegmentSeries) bool {
	return params.nextUncompressedIndex >= addr.GetDivisionCount()
}

func (params *ipv6StringParams) isCompressed(addr IPAddressSegmentSeries) bool {
	return params.firstCompressedSegmentIndex >= 0
}

func (params *ipv6StringParams) getTrailingSeparatorCount(addr *IPv6AddressSection) int {
	return params.getTrailingSepCount(addr)
}

func (params *ipv6StringParams) getTrailingSepCount(addr IPAddressSegmentSeries) int {
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

func (params *ipv6StringParams) append(builder *strings.Builder, addr *IPv6AddressSection, zone Zone) *strings.Builder {
	// Our order is label, then segments, then zone, then suffix, then prefix length.
	params.appendSuffix(params.appendZone(params.appendSegments(params.appendLabel(builder), addr), zone))
	if !params.reverse && (!params.preferWildcards() || params.hostCompressed) {
		params.appendPrefixIndicator(builder, addr)
	}
	return builder
}

func (params *ipv6StringParams) appendSegments(builder *strings.Builder, addr *IPv6AddressSection) *strings.Builder {
	divisionCount := addr.GetDivisionCount()
	if divisionCount <= 0 {
		return builder
	}
	lastIndex := divisionCount - 1
	separator := params.separator
	reverse := params.reverse
	i := 0
	firstCompressedSegmentIndex := params.firstCompressedSegmentIndex
	nextUncompressedIndex := params.nextUncompressedIndex
	hasSep := params.hasSeparator()
	for {
		segIndex := i
		if reverse {
			segIndex = lastIndex - i
		}
		if segIndex < firstCompressedSegmentIndex || segIndex >= nextUncompressedIndex {
			div := addr.GetSegment(segIndex)
			prefLen := div.getDivisionPrefixLength()
			params.appendSegment(segIndex, div, prefLen, builder, addr)
			i++
			if i > lastIndex {
				break
			}
			if hasSep {
				builder.WriteByte(separator)
			}
		} else {
			firstCompressed := firstCompressedSegmentIndex
			if reverse {
				firstCompressed = nextUncompressedIndex - 1
			}
			if segIndex == firstCompressed && hasSep { //the segment is compressed
				builder.WriteByte(separator)
				if i == 0 { //when compressing the front we use two separators
					builder.WriteByte(separator)
				}
			} //else we are in the middle of a compressed set of segments, so nothing to write
			i++
			if i > lastIndex {
				break
			}
		}
	}
	return builder
}

func (params *ipv6StringParams) getSegmentsStringLength(part *IPv6AddressSection) int {
	count := 0
	divCount := part.GetDivisionCount()
	if divCount != 0 {
		i := 0
		firstCompressedSegmentIndex := params.firstCompressedSegmentIndex
		nextUncompressedIndex := params.nextUncompressedIndex
		for {
			if i < firstCompressedSegmentIndex || i >= nextUncompressedIndex {
				div := part.GetSegment(i)
				prefLen := div.GetSegmentPrefixLength()
				count += params.appendSegment(i, div, prefLen, nil, part)
				i++
				if i >= divCount {
					break
				}
				if params.hasSeparator() {
					count++
				}
			} else {
				if i == firstCompressedSegmentIndex && params.hasSeparator() { //the segment is compressed
					count++
					if i == 0 { //when compressing the front we use two separators
						count++
					}
				} //else we are in the middle of a compressed set of segments, so nothing to write
				i++
				if i >= divCount {
					break
				}
			}
		}
	}
	return count
}

func (params *ipv6StringParams) getStringLength(addr *IPv6AddressSection) int {
	count := params.getSegmentsStringLength(addr)
	if !params.reverse && (!params.preferWildcards() || params.hostCompressed) {
		count += getPrefixIndicatorStringLength(addr)
	}
	return count + params.getAddressSuffixLength() + params.getAddressLabelLength()
}

func (params *ipv6StringParams) getZonedStringLength(addr *IPv6AddressSection, zone Zone) int {
	result := params.getStringLength(addr)
	if zone != noZone {
		result += params.getZoneLength(zone)
	}
	return result
}

func (params *ipv6StringParams) toZonedString(addr *IPv6AddressSection, zone Zone) string {
	length := params.getZonedStringLength(addr, zone)
	builder := strings.Builder{}
	builder.Grow(length)
	params.append(&builder, addr, zone)
	checkLengths(length, &builder)
	return builder.String()
}

func (params *ipv6StringParams) toString(addr *IPv6AddressSection) string {
	return params.toZonedString(addr, noZone)
}

func (params *ipv6StringParams) clone() *ipv6StringParams {
	res := *params
	res.ipAddressStringParams = *res.ipAddressStringParams.clone()
	return &res
}

// Each IPv6StringParams has settings to write exactly one IPv6 address section string
//static class IPv6StringParams extends IPAddressStringParams<IPv6AddressSection> {
type ipv6v4MixedParams struct {
	ipv6Params *ipv6StringParams
	ipv4Params *ipAddressStringParams
}

func (params *ipv6v4MixedParams) getTrailingSegmentSeparator() byte {
	return params.ipv4Params.getTrailingSegmentSeparator()
}

func (params *ipv6v4MixedParams) getTrailingSeparatorCount(addr *IPv6v4MixedAddressSection) int {
	return params.ipv4Params.getTrailingSeparatorCount(addr.ipv4Section)
}

func (params *ipv6v4MixedParams) getStringLength(addr *IPv6v4MixedAddressSection, zone Zone) int {
	ipv6Params := params.ipv6Params
	ipv6length := ipv6Params.getSegmentsStringLength(addr.ipv6Section)
	ipv4length := params.ipv4Params.getSegmentsStringLength(addr.ipv4Section)
	length := ipv6length + ipv4length
	if ipv6Params.nextUncompressedIndex < addr.ipv6Section.GetSegmentCount() {
		length++
	}
	length += params.getPrefixStringLength(addr)
	length += ipv6Params.getZoneLength(zone)
	length += ipv6Params.getAddressSuffixLength()
	length += ipv6Params.getAddressLabelLength()
	return length
}

func (params *ipv6v4MixedParams) toString(addr *IPv6v4MixedAddressSection) string {
	return params.toZonedString(addr, noZone)
}

func (params *ipv6v4MixedParams) toZonedString(addr *IPv6v4MixedAddressSection, zone Zone) string {
	length := params.getStringLength(addr, zone)
	builder := &strings.Builder{}
	builder.Grow(length)
	params.append(builder, addr, zone)
	checkLengths(length, builder)
	return builder.String()
}

func (params *ipv6v4MixedParams) getDivisionStringLength(seg *AddressDivision) int {
	return params.ipv6Params.getDivisionStringLength(seg)
}

func (params *ipv6v4MixedParams) appendDivision(builder *strings.Builder, seg *AddressDivision) *strings.Builder {
	return params.ipv6Params.appendDivision(builder, seg)
}

func (params *ipv6v4MixedParams) append(builder *strings.Builder, addr *IPv6v4MixedAddressSection, zone Zone) *strings.Builder {
	ipv6Params := params.ipv6Params
	ipv6Params.appendLabel(builder)
	ipv6Params.appendSegments(builder, addr.ipv6Section)
	if ipv6Params.nextUncompressedIndex < addr.ipv6Section.GetSegmentCount() {
		builder.WriteByte(ipv6Params.getTrailingSegmentSeparator())
	}
	params.ipv4Params.appendSegments(builder, addr.ipv4Section)

	/*
	 * rfc 4038: for bracketed addresses, zone is inside and prefix outside, putting prefix after zone.
	 *
	 * Suffixes are things like .in-addr.arpa, .ip6.arpa, .ipv6-literal.net
	 * which generally convert an address string to a host
	 * As with our HostName, we support host/prefix in which case the prefix is applied
	 * to the resolved address.
	 *
	 * So in summary, our order is zone, then suffix, then prefix length.
	 */
	ipv6Params.appendZone(builder, zone)
	ipv6Params.appendSuffix(builder)
	params.appendPrefixIndicator(builder, addr)
	return builder
}

func (params *ipv6v4MixedParams) getPrefixStringLength(addr *IPv6v4MixedAddressSection) int {
	if params.requiresPrefixIndicatorIPv6(addr.ipv6Section) || params.requiresPrefixIndicatorIPv4(addr.ipv4Section) {
		return getPrefixIndicatorStringLength(addr)
	}
	return 0
}

func (params *ipv6v4MixedParams) appendPrefixIndicator(builder *strings.Builder, addr *IPv6v4MixedAddressSection) {
	if params.requiresPrefixIndicatorIPv6(addr.ipv6Section) || params.requiresPrefixIndicatorIPv4(addr.ipv4Section) {
		params.ipv6Params.appendPrefixIndicator(builder, addr)
	}
}

func (params *ipv6v4MixedParams) requiresPrefixIndicatorIPv4(ipv4Section *IPv4AddressSection) bool {
	return ipv4Section.IsPrefixed() && !params.ipv4Params.preferWildcards()
}

func (params *ipv6v4MixedParams) requiresPrefixIndicatorIPv6(ipv6Section *IPv6AddressSection) bool {
	ipv6Params := params.ipv6Params
	return ipv6Section.IsPrefixed() && (!ipv6Params.preferWildcards() || ipv6Params.hostCompressed)
}

func (params *ipv6v4MixedParams) clone() *ipv6v4MixedParams {
	ipv6Params := *params.ipv6Params
	ipv4Params := *params.ipv4Params
	return &ipv6v4MixedParams{
		ipv6Params: &ipv6Params,
		ipv4Params: &ipv4Params,
	}
}

type stringWriter struct {
	//divStringProvider // the division itself, seen as a string provider

	//div DivisionType // the division itself

	DivisionType

	// do these really need to be function pointers?
	// MAYBE
	// 1. THEY are methods in the divs to be accessible publicly , at least two are
	// 2. Those public methods will scale up, so technically maybe they do not need to be here
	// 3. BUT, are they in DivisionType?  Maybe two will be
	// 4. Maybe the other could be moved to divStringProvider?
	//maybe just call these on the div itself?
	//in there they should scale up
	//and move them into DivisionType too
	//
	//getStringAsLower  func() string
	//getString         func() string
	//getWildcardString func() string
}

//func (writer stringWriter) getStringAsLower() string {
//	return writer.div.getStringAsLower()
//}
//
//func (writer stringWriter) getString() string {
//	return writer.div.GetString()
//}
//
//func (writer stringWriter) getWildcardString() string {
//	return writer.div.GetWildcardString()
//}

func (writer stringWriter) getStringAsLower() string {
	return writer.DivisionType.getStringAsLower()
}

func (writer stringWriter) getString() string {
	return writer.GetString()
}

func (writer stringWriter) getWildcardString() string {
	return writer.GetWildcardString()
}

// Produces a string to represent the segment, using wildcards and range characters.
// Use this instead of getWildcardString() if you have a customized wildcard or range separator or you have a non-zero leadingZeroCount,
func (writer stringWriter) getStandardString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	//div := writer.div
	if !writer.IsMultiple() {
		splitDigits := params.isSplitDigits()
		if splitDigits {
			radix := params.getRadix()
			leadingZeroCount := params.getLeadingZeros(segmentIndex)
			leadingZeroCount = writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
			stringPrefix := params.getSegmentStrPrefix()
			prefLen := len(stringPrefix)
			if appendable == nil {
				var length int
				if leadingZeroCount != 0 {
					if leadingZeroCount < 0 {
						length = writer.getMaxDigitCountRadix(radix)
					} else {
						length = writer.getLowerStringLength(radix) + leadingZeroCount
					}
				} else {
					length = writer.getLowerStringLength(radix)
				}
				count := (length << 1) - 1
				if prefLen > 0 {
					count += length * prefLen
				}
				return count
			} else {
				var splitDigitSeparator byte = ' '
				if params.hasSeparator() {
					splitDigitSeparator = params.getSplitDigitSeparator()
				}
				reverseSplitDigits := params.isReverseSplitDigits()
				uppercase := params.isUppercase()
				if reverseSplitDigits {
					writer.getSplitLowerString(radix, 0, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
					if leadingZeroCount != 0 {
						appendable.WriteByte(splitDigitSeparator)
						getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
					}
				} else {
					if leadingZeroCount != 0 {
						getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
						appendable.WriteByte(splitDigitSeparator)
					}
					writer.getSplitLowerString(radix, 0, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
				}
				return 0
			}
		}
		return writer.getLowerStandardString(segmentIndex, params, appendable)
	} else if writer.IsFullRange() {
		wildcard := params.getWildcards().GetWildcard()
		if len(wildcard) > 0 {
			//if wildcard == writer.getDefaultSegmentWildcardString() { unnecessary and a PITA for golang
			//	setDefaultAsFullRangeWildcardString() //cache
			//}
			splitDigits := params.isSplitDigits()
			if splitDigits {
				radix := params.getRadix()
				if appendable == nil {
					length := writer.getMaxDigitCountRadix(radix)
					count := length*(len(wildcard)+1) - 1
					return count
				}
				var splitDigitSeparator byte = ' '
				if params.hasSeparator() {
					splitDigitSeparator = params.getSplitDigitSeparator()
				}
				digitCount := writer.getMaxDigitCountRadix(radix)
				getSplitCharStr(digitCount, splitDigitSeparator, wildcard, "", appendable)
				return 0
			}
			return getFullRangeString(wildcard, appendable)
		}
	}
	return writer.getRangeString(segmentIndex, params, appendable)
}

func (writer stringWriter) getPrefixAdjustedRangeString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	radix := params.getRadix()
	lowerLeadingZeroCount := writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
	upperLeadingZeroCount := writer.adjustUpperLeadingZeroCount(leadingZeroCount, radix)

	//if the wildcards match those in use by getString(), and there is no character prefix, let's defer to getString() so that it is cached
	wildcards := params.getWildcards()
	rangeSeparator := wildcards.GetRangeSeparator()
	rangeDigitCount := 0
	if len(wildcards.GetSingleWildcard()) != 0 {
		rangeDigitCount = writer.getRangeDigitCount(radix)
	}
	//div := writer.div

	//If we can, we reuse the standard string to construct this string (must have the same radix and no chopped digits)
	//We can insert leading zeros, string prefix, and a different separator string if necessary
	//Also, we cannot in the case of full range (in which case we are only here because we do not want '*')
	if rangeDigitCount == 0 && radix == writer.getDefaultTextualRadix() && !writer.IsFullRange() {
		//we call getString() to cache the result, and we call getString instead of getWildcardString() because it will also mask with the segment prefix length
		str := writer.getString()
		rangeSep := writer.getDefaultRangeSeparatorString()
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		if lowerLeadingZeroCount == 0 && upperLeadingZeroCount == 0 && rangeSep == rangeSeparator && prefLen == 0 {
			if appendable == nil {
				return len(str)
			} else {
				if params.isUppercase() {
					appendUppercase(str, radix, appendable)
				} else {
					appendable.WriteString(str)
				}
				return 0
			}
		} else {
			if appendable == nil {
				count := len(str) + (len(rangeSeparator) - len(rangeSep)) +
					lowerLeadingZeroCount + upperLeadingZeroCount
				if prefLen > 0 {
					count += prefLen << 1
				}
				return count
			} else {
				firstEnd := strings.Index(str, rangeSep)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if lowerLeadingZeroCount > 0 {
					getLeadingZeros(lowerLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[0:firstEnd])
				appendable.WriteString(rangeSeparator)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if upperLeadingZeroCount > 0 {
					getLeadingZeros(upperLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[firstEnd+len(rangeSep):])
				return 0
			}
		}
	}
	rangeDigitCount = writer.adjustRangeDigits(rangeDigitCount)
	if leadingZeroCount < 0 && appendable == nil {
		charLength := writer.getMaxDigitCountRadix(radix)
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		if rangeDigitCount != 0 {
			count := charLength
			if prefLen > 0 {
				count += prefLen
			}
			return count
		}
		count := charLength << 1
		if prefLen > 0 {
			count += prefLen << 1
		}
		count += len(rangeSeparator)
		return count
	}
	if rangeDigitCount != 0 {
		return writer.getRangeDigitString(segmentIndex, params, appendable)
	}
	return writer.getRangeStringWithCounts(segmentIndex, params, lowerLeadingZeroCount, upperLeadingZeroCount, true, appendable)
}

// before you move ahead, chexk to see if the methods below are called internally in the division classes
// If so, you cannot put them here.  In such cases they will need a divStringProvider arg added as well, most likely.
// I suppose that the more you can pull out here, the better, but be careful.
// ANything that is overridden cannot go here either.  Really just the entry points from params to divisions
// needs to be here.

// entry points:
// getStandardString
// getPrefixAdjustedRangeString
// getLowerStandardString
//

//stay away from buildDefaultRangeString
//getRangeString
// In go, getRangeStringSep should no longer be a method, since it will use divStringProvider
//getLowerString/getUpperString/getUpperStringMasked
// ok the ones below are all of it

func (writer stringWriter) getLowerStandardString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	count := 0
	stringPrefix := params.getSegmentStrPrefix()
	prefLen := len(stringPrefix)
	if prefLen > 0 {
		if appendable == nil {
			count += prefLen
		} else {
			appendable.WriteString(stringPrefix)
		}
	}
	radix := params.getRadix()
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	leadingZeroCount = writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
	if leadingZeroCount != 0 {
		if appendable == nil {
			if leadingZeroCount < 0 {
				return count + writer.getMaxDigitCountRadix(radix)
			} else {
				count += leadingZeroCount
			}
		} else {
			leadingZeroCount = writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
			getLeadingZeros(leadingZeroCount, appendable)
		}
	}
	uppercase := params.isUppercase()
	if radix == writer.getDefaultTextualRadix() {
		// equivalent to GetString for ip addresses but not getWildcardString
		// for addresses, equivalent to either one
		str := writer.getStringAsLower()
		if appendable == nil {
			return count + len(str)
		} else if uppercase {
			appendUppercase(str, radix, appendable)
		} else {
			appendable.WriteString(str)
		}
	} else {
		if appendable == nil {
			return count + writer.getLowerStringLength(radix)
		} else {
			writer.getLowerString(radix, uppercase, appendable)
		}
	}
	return 0
}

func (writer stringWriter) getRangeString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	splitDigits := params.isSplitDigits()
	radix := params.getRadix()
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	wildcards := params.getWildcards()
	rangeSeparator := wildcards.GetRangeSeparator()
	singleWC := wildcards.GetSingleWildcard()
	rangeDigitCount := 0
	if singleWC != "" {
		rangeDigitCount = writer.getRangeDigitCount(radix)
	}
	lowerLeadingZeroCount := writer.adjustLowerLeadingZeroCount(leadingZeroCount, radix)
	upperLeadingZeroCount := writer.adjustUpperLeadingZeroCount(leadingZeroCount, radix)
	//div := writer.div
	//check the case where we can use the result of getWildcardString which is cached.
	//It must have same radix and no chopped digits, and no splitting or reversal of digits.
	//We can insert leading zeros, string prefix, and a different separator string if necessary.
	//Also, we cannot in the case of full range (in which case we are only here because we do not want '*')
	if rangeDigitCount == 0 &&
		radix == writer.getDefaultTextualRadix() &&
		!splitDigits &&
		!writer.IsFullRange() {
		str := writer.getWildcardString()
		rangeSep := writer.getDefaultRangeSeparatorString()
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		if lowerLeadingZeroCount == 0 && upperLeadingZeroCount == 0 &&
			prefLen == 0 &&
			rangeSeparator == rangeSep {
			if appendable == nil {
				return len(str)
			}
			appendable.WriteString(str)
			return 0
		} else {
			if appendable == nil {
				count := len(str) + (len(rangeSeparator) - len(rangeSep)) + lowerLeadingZeroCount + upperLeadingZeroCount
				if prefLen > 0 {
					count += prefLen << 1
				}
				return count
			} else {
				firstEnd := strings.Index(str, rangeSep)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if lowerLeadingZeroCount > 0 {
					getLeadingZeros(lowerLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[0:firstEnd])
				appendable.WriteString(rangeSeparator)
				if prefLen > 0 {
					appendable.WriteString(stringPrefix)
				}
				if upperLeadingZeroCount > 0 {
					getLeadingZeros(upperLeadingZeroCount, appendable)
				}
				appendable.WriteString(str[firstEnd+len(rangeSep):])
				return 0
			}
		}
	}
	/*
	 split digits that result in digit ranges of * are similar to range digits range digits
	 eg f00-fff is both f__ and f.*.*
	 One difference is that for decimal last range digit is 0-5 (ie 255) but for split we only check full range (0-9)
	 eg 200-255 is 2__  but not 2.*.*
	 another difference: when calculating range digits, the count is 0 unless the entire range can be written as range digits
	 eg f10-fff has no range digits but is f.1-f.*
	*/
	if !splitDigits && leadingZeroCount < 0 && appendable == nil {
		stringPrefix := params.getSegmentStrPrefix()
		prefLen := len(stringPrefix)
		charLength := writer.getMaxDigitCountRadix(radix)
		if rangeDigitCount != 0 {
			count := charLength
			if prefLen > 0 {
				count += prefLen
			}
			return count
		}
		count := charLength << 1
		if prefLen > 0 {
			count += prefLen << 1
		}
		count += len(rangeSeparator)
		return count
	}
	rangeDigitCount = writer.adjustRangeDigits(rangeDigitCount)
	if rangeDigitCount != 0 {
		if splitDigits {
			return writer.getSplitRangeDigitString(segmentIndex, params, appendable)
		} else {
			return writer.getRangeDigitString(segmentIndex, params, appendable)
		}
	}
	if splitDigits {
		return writer.writeSplitRangeString(segmentIndex, params, appendable)
	}
	return writer.getRangeStringWithCounts(segmentIndex, params, lowerLeadingZeroCount, upperLeadingZeroCount, false, appendable)
}

func (writer stringWriter) getSplitRangeDigitString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	radix := params.getRadix()
	leadingZerosCount := params.getLeadingZeros(segmentIndex)
	leadingZerosCount = writer.adjustLowerLeadingZeroCount(leadingZerosCount, radix)
	stringPrefix := params.getSegmentStrPrefix()
	if appendable == nil {
		length := writer.getLowerStringLength(radix) + leadingZerosCount
		count := (length << 1) - 1
		prefLen := len(stringPrefix)
		if prefLen > 0 {
			count += length * prefLen
		}
		return count
	} else {
		wildcards := params.getWildcards()
		dc := writer.getRangeDigitCount(radix)
		rangeDigits := writer.adjustRangeDigits(dc)
		var splitDigitSeparator byte = ' '
		if params.hasSeparator() {
			splitDigitSeparator = params.getSplitDigitSeparator()
		}
		reverseSplitDigits := params.isReverseSplitDigits()
		uppercase := params.isUppercase()
		if reverseSplitDigits {
			getSplitCharStr(rangeDigits, splitDigitSeparator, wildcards.GetSingleWildcard(), stringPrefix, appendable)
			appendable.WriteByte(splitDigitSeparator)
			writer.getSplitLowerString(radix, rangeDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
			if leadingZerosCount > 0 {
				appendable.WriteByte(splitDigitSeparator)
				getSplitLeadingZeros(leadingZerosCount, splitDigitSeparator, stringPrefix, appendable)
			}
		} else {
			if leadingZerosCount != 0 {
				getSplitLeadingZeros(leadingZerosCount, splitDigitSeparator, stringPrefix, appendable)
				appendable.WriteByte(splitDigitSeparator)
			}
			writer.getSplitLowerString(radix, rangeDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable)
			appendable.WriteByte(splitDigitSeparator)
			getSplitCharStr(rangeDigits, splitDigitSeparator, wildcards.GetSingleWildcard(), stringPrefix, appendable)
		}
	}
	return 0
}

func (writer stringWriter) getRangeDigitString(segmentIndex int, params addressSegmentParams, appendable *strings.Builder) int {
	radix := params.getRadix()
	leadingZerosCount := params.getLeadingZeros(segmentIndex)
	leadingZerosCount = writer.adjustLowerLeadingZeroCount(leadingZerosCount, radix)
	stringPrefix := params.getSegmentStrPrefix()
	prefLen := len(stringPrefix)
	wildcards := params.getWildcards()
	dc := writer.getRangeDigitCount(radix)
	rangeDigits := writer.adjustRangeDigits(dc)
	if appendable == nil {
		return writer.getLowerStringLength(radix) + leadingZerosCount + prefLen
	} else {
		if prefLen > 0 {
			appendable.WriteString(stringPrefix)
		}
		if leadingZerosCount > 0 {
			getLeadingZeros(leadingZerosCount, appendable)
		}
		uppercase := params.isUppercase()
		writer.getLowerStringChopped(radix, rangeDigits, uppercase, appendable)
		for i := 0; i < rangeDigits; i++ {
			appendable.WriteString(wildcards.GetSingleWildcard())
		}
	}
	return 0
}

func (writer stringWriter) adjustRangeDigits(rangeDigits int) int {
	if rangeDigits != 0 {
		//Note: ranges like ___ intended to represent 0-fff cannot work because the range does not include 2 digit and 1 digit numbers
		//This only happens when the lower value is 0 and there is more than 1 range digit
		//That's because you can then omit any leading zeros.
		//Ranges like f___ representing f000-ffff are fine.
		if !writer.IncludesZero() || rangeDigits == 1 {
			return rangeDigits
		}
	}
	return 0
}

func (writer stringWriter) getRangeStringWithCounts(
	segmentIndex int,
	params addressSegmentParams,
	lowerLeadingZerosCount int,
	upperLeadingZerosCount int,
	maskUpper bool,
	appendable *strings.Builder) int {

	stringPrefix := params.getSegmentStrPrefix()
	radix := params.getRadix()
	rangeSeparator := params.getWildcards().GetRangeSeparator()
	uppercase := params.isUppercase()
	return getRangeString(writer.DivisionType, rangeSeparator, lowerLeadingZerosCount, upperLeadingZerosCount, stringPrefix, radix, uppercase, maskUpper, appendable)
}

func (writer stringWriter) writeSplitRangeString(
	segmentIndex int,
	params addressSegmentParams,
	appendable *strings.Builder) int {
	stringPrefix := params.getSegmentStrPrefix()
	radix := params.getRadix()
	leadingZeroCount := params.getLeadingZeros(segmentIndex)
	//for split ranges, it is the leading zeros of the upper value that matters
	leadingZeroCount = writer.adjustUpperLeadingZeroCount(leadingZeroCount, radix)
	wildcards := params.getWildcards()
	uppercase := params.isUppercase()
	var splitDigitSeparator byte = ' '
	if params.hasSeparator() {
		splitDigitSeparator = params.getSplitDigitSeparator()
	}
	reverseSplitDigits := params.isReverseSplitDigits()
	rangeSeparator := wildcards.GetRangeSeparator()
	if appendable == nil {
		return writer.getSplitRangeStringLength(
			rangeSeparator,
			wildcards.GetWildcard(),
			leadingZeroCount,
			radix,
			uppercase,
			splitDigitSeparator,
			reverseSplitDigits,
			stringPrefix)
	} else {
		hasLeadingZeros := leadingZeroCount != 0
		if hasLeadingZeros && !reverseSplitDigits {
			getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
			appendable.WriteByte(splitDigitSeparator)
			hasLeadingZeros = false
		}
		writer.getSplitRangeString(
			rangeSeparator,
			wildcards.GetWildcard(),
			radix,
			uppercase,
			splitDigitSeparator,
			reverseSplitDigits,
			stringPrefix,
			appendable)
		if hasLeadingZeros {
			appendable.WriteByte(splitDigitSeparator)
			getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable)
		}
	}
	return 0
}

func getSplitCharStr(count int, splitDigitSeparator byte, characters string, stringPrefix string, builder *strings.Builder) {
	prefLen := len(stringPrefix)
	if count > 0 {
		for {
			if prefLen > 0 {
				builder.WriteString(stringPrefix)
			}
			builder.WriteString(characters)
			count--
			if count <= 0 {
				break
			}
			builder.WriteByte(splitDigitSeparator)
		}
	}
}

func getSplitChar(count int, splitDigitSeparator, character byte, stringPrefix string, builder *strings.Builder) {
	prefLen := len(stringPrefix)
	if count > 0 {
		for {
			if prefLen > 0 {
				builder.WriteString(stringPrefix)
			}
			builder.WriteByte(character)
			count--
			if count <= 0 {
				break
			}
			builder.WriteByte(splitDigitSeparator)
		}
	}
}

func getSplitLeadingZeros(leadingZeroCount int, splitDigitSeparator byte, stringPrefix string, builder *strings.Builder) {
	getSplitChar(leadingZeroCount, splitDigitSeparator, '0', stringPrefix, builder)
}

func appendUppercase(str string, radix int, appendable *strings.Builder) {
	if radix > 10 {
		for i := 0; i < len(str); i++ {
			c := str[i]
			if c >= 'a' && c <= 'z' {
				c -= byte('a') - byte('A')
			}
			appendable.WriteByte(c)
		}
	} else {
		appendable.WriteString(str)
	}
}

func getFullRangeString(wildcard string, appendable *strings.Builder) int {
	if appendable == nil {
		return len(wildcard)
	}
	appendable.WriteString(wildcard)
	return 0
}

func getLeadingZeros(leadingZeroCount int, builder *strings.Builder) {
	if leadingZeroCount > 0 {
		stringArray := zeros
		increment := len(stringArray)
		if leadingZeroCount > increment {
			for leadingZeroCount > increment {
				builder.WriteString(stringArray)
				leadingZeroCount -= increment
			}
		}
		builder.WriteString(stringArray[:leadingZeroCount])
	}
}

const zeros = "00000000000000000000"

func toNormalizedStringRange(params *addressStringParams, lower, upper *AddressSection, zone Zone) string {
	length := params.getStringLength(lower) + params.getZonedStringLength(upper, zone)
	var builder strings.Builder
	separator := params.getWildcards().GetRangeSeparator()
	if separator != "" {
		length += len(separator)
		builder.Grow(length)
		params.append(&builder, lower).WriteString(separator)
		params.appendZoned(&builder, upper, zone)
	} else {
		builder.Grow(length)
		params.appendZoned(params.append(&builder, lower), upper, zone)
	}
	checkLengths(length, &builder)
	return builder.String()
}
