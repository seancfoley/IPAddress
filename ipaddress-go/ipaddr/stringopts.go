package ipaddr

// Wildcards specifies the wildcards to use when constructing a address string
type Wildcards interface {
	// if this returns an empty string, then the default separator RangeSeparatorStr is used
	GetRangeSeparator() string

	GetWildcard() string

	GetSingleWildcard() string
}

type wildcards struct {
	rangeSeparator, wildcard, singleWildcard string //rangeSeparator cannot be empty, the other two can
}

func (wildcards *wildcards) GetRangeSeparator() string {
	return wildcards.rangeSeparator
}

func (wildcards *wildcards) GetWildcard() string {
	return wildcards.wildcard
}

func (wildcards *wildcards) GetSingleWildcard() string {
	return wildcards.singleWildcard
}

var DefaultWildcards Wildcards = &wildcards{rangeSeparator: RangeSeparatorStr, wildcard: SegmentWildcardStr}

type WildcardsBuilder struct {
	wildcards
}

func (wildcards *WildcardsBuilder) SetRangeSeparator(str string) *WildcardsBuilder {
	wildcards.rangeSeparator = str
	return wildcards
}

func (wildcards *WildcardsBuilder) SetWildcard(str string) *WildcardsBuilder {
	wildcards.wildcard = str
	return wildcards
}

func (wildcards *WildcardsBuilder) SetSingleWildcard(str string) *WildcardsBuilder {
	wildcards.singleWildcard = str
	return wildcards
}

func (wildcards *WildcardsBuilder) GetWildcard(str string) *WildcardsBuilder {
	wildcards.wildcard = str
	return wildcards
}

func (wildcards *WildcardsBuilder) GetSingleWildcard(str string) *WildcardsBuilder {
	wildcards.singleWildcard = str
	return wildcards
}

func (wildcards *WildcardsBuilder) ToWildcards() Wildcards {
	res := wildcards.wildcards
	if res.rangeSeparator == "" {
		//rangeSeparator cannot be empty
		res.rangeSeparator = RangeSeparatorStr
	}
	return &res
}

//type StringOptionsBase struct {
//	// This is an object representing the string options converted to an object.
//	// It can write a supplied division using those params.
//	//Use this field if the options to params conversion is not dependent on the address part so it can be reused
//	cachedParams addressDivisionWriter
//}

// Represents a clear way to create a specific type of string.
type StringOptions interface {
	GetWildcards() Wildcards

	IsReverse() bool

	IsUppercase() bool

	IsExpandedSegments() bool

	GetRadix() int

	// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
	GetSeparator() byte

	HasSeparator() bool

	GetAddressLabel() string

	GetSegmentStrPrefix() string
}

type stringOptions struct {
	wildcards Wildcards

	base int // default is hex

	//the segment separator and in the case of split digits, the digit separator
	separator byte // default is ' ', but it's typically either '.' or ':'

	segmentStrPrefix,
	addrLabel string

	expandSegments,
	hasSeparator,
	reverse,
	uppercase bool

	cached *addressStringParams
}

func (w *stringOptions) GetWildcards() Wildcards {
	return w.wildcards
}

func (w *stringOptions) IsReverse() bool {
	return w.reverse
}

func (w *stringOptions) IsUppercase() bool {
	return w.uppercase
}

//func (w *stringOptions) isSplitDigits() bool {
//	return w.splitDigits
//}

func (w *stringOptions) IsExpandedSegments() bool {
	return w.expandSegments
}

func (w *stringOptions) GetRadix() int {
	return w.base
}

// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
func (w *stringOptions) GetSeparator() byte {
	return w.separator
}

func (w *stringOptions) HasSeparator() bool {
	return w.hasSeparator
}

func (w *stringOptions) GetAddressLabel() string {
	return w.addrLabel
}

func (w *stringOptions) GetSegmentStrPrefix() string {
	return w.segmentStrPrefix
}

var _ StringOptions = &stringOptions{}

type StringOptionsBuilder struct {
	stringOptions
}

func (w *StringOptionsBuilder) SetWildcards(wildcards Wildcards) *StringOptionsBuilder {
	w.wildcards = wildcards
	return w
}

func (w *StringOptionsBuilder) SetReverse(reverse bool) *StringOptionsBuilder {
	w.reverse = reverse
	return w
}

func (w *StringOptionsBuilder) SetUppercase(uppercase bool) *StringOptionsBuilder {
	w.uppercase = uppercase
	return w
}

//func (w *StringOptionsBuilder) setSplitDigits(splitDigits bool) *StringOptionsBuilder { // not public since only supported for IPv6 because it produces errors for ranged segments
//	w.splitDigits = splitDigits
//	return w
//}

func (w *StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *StringOptionsBuilder {
	w.expandSegments = expandSegments
	return w
}

func (w *StringOptionsBuilder) SetRadix(base int) *StringOptionsBuilder {
	w.base = base
	return w
}

func (w *StringOptionsBuilder) SetHasSeparator(has bool) *StringOptionsBuilder {
	w.hasSeparator = has
	return w
}

// separates the divisions of the address, typically ':' or '.'
func (w *StringOptionsBuilder) SetSeparator(separator byte) *StringOptionsBuilder {
	w.separator = separator
	w.SetHasSeparator(true)
	return w
}

func (w *StringOptionsBuilder) SetAddressLabel(label string) *StringOptionsBuilder {
	w.addrLabel = label
	return w
}

func (w *StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *StringOptionsBuilder {
	w.segmentStrPrefix = prefix
	return w
}

func (w *StringOptionsBuilder) ToOptions() StringOptions {
	res := w.stringOptions
	res.base, res.wildcards, res.separator, _ = getDefaults(res.base, res.wildcards, res.separator, 0)
	return &res
}

type WildcardOption string

const (
	WILDCARDS_NETWORK_ONLY WildcardOption = ""        //only print wildcards that are part of the network portion (only possible with subnet address notation, otherwise this option is ignored)
	WILDCARDS_ALL          WildcardOption = "allType" //print wildcards for any visible (non-compressed) segments
)

type WildcardOptions interface {
	GetWildcardOption() WildcardOption
	GetWildcards() Wildcards
}

type wildcardOptions struct {
	wildcardOption WildcardOption
	wildcards      Wildcards
}

func (w *wildcardOptions) GetWildcardOption() WildcardOption {
	return w.wildcardOption
}

func (w *wildcardOptions) GetWildcards() Wildcards {
	return w.wildcards
}

var _ WildcardOptions = &wildcardOptions{}

type WildcardOptionsBuilder struct {
	wildcardOptions
}

func (w *WildcardOptionsBuilder) SetWildcardOptions(wildcardOption WildcardOption) *WildcardOptionsBuilder {
	w.wildcardOption = wildcardOption
	return w
}

func (w *WildcardOptionsBuilder) SetWildcards(wildcards Wildcards) *WildcardOptionsBuilder {
	w.wildcards = wildcards
	return w
}

func (w *WildcardOptionsBuilder) ToOptions() WildcardOptions {
	cpy := w.wildcardOptions
	if w.wildcards == nil {
		w.wildcards = DefaultWildcards
	}
	return &cpy
}

type IPStringOptions interface {
	StringOptions

	GetAddressSuffix() string

	GetWildcardOptions() WildcardOptions

	GetWildcardOption() WildcardOption

	GetZoneSeparator() byte
}

type ipStringOptions struct {
	stringOptions

	addrSuffix     string
	wildcardOption WildcardOption // default is WILDCARDS_NETWORK_ONLY
	zoneSeparator  byte           // default is IPv6ZoneSeparator

	cachedIPAddr *ipAddressStringParams
	cachedAddr   *addressStringParams
}

// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
func (w *ipStringOptions) GetAddressSuffix() string {
	return w.addrSuffix
}

func (w *ipStringOptions) GetWildcardOptions() WildcardOptions {
	opts := &wildcardOptions{
		w.wildcardOption,
		w.GetWildcards(),
	}
	return opts
}

func (w *ipStringOptions) GetWildcardOption() WildcardOption {
	return w.wildcardOption

}

func (w *ipStringOptions) GetZoneSeparator() byte {
	return w.zoneSeparator
}

var _ IPStringOptions = &ipStringOptions{}

type IPStringOptionsBuilder struct {
	StringOptionsBuilder
	ipStringOptions ipStringOptions
}

// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
func (w *IPStringOptionsBuilder) SetAddressSuffix(suffix string) *IPStringOptionsBuilder {
	w.ipStringOptions.addrSuffix = suffix
	return w
}

func (w *IPStringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPStringOptionsBuilder {
	w.SetWildcards(wildcardOptions.GetWildcards())
	return w.SetWildcardOption(wildcardOptions.GetWildcardOption())
}

func (w *IPStringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPStringOptionsBuilder {
	w.ipStringOptions.wildcardOption = wildcardOption
	return w
}

func (w *IPStringOptionsBuilder) SetZoneSeparator(separator byte) *IPStringOptionsBuilder {
	w.ipStringOptions.zoneSeparator = separator
	return w
}

func (w *IPStringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetWildcards(wildcards)
	return w
}

func (w *IPStringOptionsBuilder) SetReverse(reverse bool) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetReverse(reverse)
	return w
}

func (w *IPStringOptionsBuilder) SetUppercase(uppercase bool) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetUppercase(uppercase)
	return w
}

//func (w *IPStringOptionsBuilder) setSplitDigits(splitDigits bool) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.setSplitDigits(splitDigits)
//	return w
//}

func (w *IPStringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetExpandedSegments(expandSegments)
	return w
}

func (w *IPStringOptionsBuilder) SetRadix(base int) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetRadix(base)
	return w
}

func (w *IPStringOptionsBuilder) SetHasSeparator(has bool) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetHasSeparator(has)
	return w
}

// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
func (w *IPStringOptionsBuilder) SetSeparator(separator byte) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetSeparator(separator)
	w.SetHasSeparator(true)
	return w
}

func (w *IPStringOptionsBuilder) SetAddressLabel(label string) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetAddressLabel(label)
	return w
}

func (w *IPStringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPStringOptionsBuilder {
	w.StringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return w
}

func (w *IPStringOptionsBuilder) ToOptions() IPStringOptions {
	res := w.ipStringOptions
	res.stringOptions = *w.StringOptionsBuilder.ToOptions().(*stringOptions)
	return &res
}

// NewIPv4StringOptionsBuilder returns a builder with default options set to create a specific type of IPv4 address string.
func NewIPv4StringOptionsBuilder() *IPStringOptionsBuilder {
	opts := IPStringOptionsBuilder{}
	return opts.SetRadix(IPv4DefaultTextualRadix).SetSeparator(IPv4SegmentSeparator)
}

// NewMACStringOptionsBuilder returns a builder with default options set to create a specific type of MAC address string.
func NewMACStringOptionsBuilder() *StringOptionsBuilder {
	opts := StringOptionsBuilder{}
	return opts.SetRadix(MACDefaultTextualRadix).SetSeparator(MACColonSegmentSeparator)
}

// NewIPv6StringOptionsBuilder returns a builder with default options set to create a specific type of IPv6 address string.
func NewIPv6StringOptionsBuilder() *IPv6StringOptionsBuilder {
	opts := IPv6StringOptionsBuilder{}
	return opts.SetRadix(IPv6DefaultTextualRadix).SetSeparator(IPv6SegmentSeparator)
}

type IPv6StringOptions interface {
	IPStringOptions

	GetIPv4Opts() IPStringOptions

	GetCompressOptions() CompressOptions

	// Whether every digit is separated from others by separators.  If mixed, this option is ignored.
	IsSplitDigits() bool // can produce IncompatibleAddressError for ranged series

	IsMixed() bool // can produce IncompatibleAddressError for ranges in the IPv4 part of the series
}

func isCacheable(options IPv6StringOptions) bool {
	return options.GetCompressOptions() == nil
}

// Provides a clear way to create a specific type of IPv6 address string.
type ipv6StringOptions struct {
	ipStringOptions
	ipv4Opts IPStringOptions

	//can be nil, which means no compression
	compressOptions CompressOptions

	cachedIPv6Addr      *ipv6StringParams
	cachedMixedIPv6Addr *ipv6v4MixedParams

	splitDigits bool
}

//func (opts *ipv6StringOptions) isCacheable() bool {
//	return opts.compressOptions == nil
//}

//func (opts *ipv6StringOptions) makeMixed() bool {
//	return opts.ipv4Opts != nil
//}

func (opts *ipv6StringOptions) IsSplitDigits() bool {
	return opts.splitDigits
}

func (opts *ipv6StringOptions) GetIPv4Opts() IPStringOptions {
	return opts.ipv4Opts
}

func (opts *ipv6StringOptions) GetCompressOptions() CompressOptions {
	return opts.compressOptions
}

func (opts *ipv6StringOptions) IsMixed() bool {
	return opts.ipv4Opts != nil
}

var _ IPv6StringOptions = &ipv6StringOptions{}

type IPv6StringOptionsBuilder struct {
	opts ipv6StringOptions

	IPStringOptionsBuilder

	makeMixed bool
}

func (builder *IPv6StringOptionsBuilder) IsMixed() bool {
	return builder.makeMixed
}

func (builder *IPv6StringOptionsBuilder) GetIPv4Opts() IPStringOptions {
	return builder.opts.ipv4Opts
}

func (builder *IPv6StringOptionsBuilder) GetCompressOptions() CompressOptions {
	return builder.opts.compressOptions
}

func (builder *IPv6StringOptionsBuilder) SetSplitDigits(splitDigits bool) *IPv6StringOptionsBuilder {
	builder.opts.splitDigits = splitDigits
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetCompressOptions(compressOptions CompressOptions) *IPv6StringOptionsBuilder {
	builder.opts.compressOptions = compressOptions
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetMixed(makeMixed bool) *IPv6StringOptionsBuilder {
	builder.makeMixed = makeMixed
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetMixedOptions(ipv4Options IPStringOptions) *IPv6StringOptionsBuilder {
	builder.makeMixed = true
	builder.opts.ipv4Opts = ipv4Options
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcardOptions(wildcardOptions)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetRadix(base int) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetRadix(base)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetHasSeparator(has bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetHasSeparator(has)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetSeparator(separator byte) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSeparator(separator)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetZoneSeparator(separator byte) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetZoneSeparator(separator)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetAddressSuffix(suffix string) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetAddressSuffix(suffix)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetReverse(reverse bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetReverse(reverse)
	return builder
}

func (builder *IPv6StringOptionsBuilder) SetUppercase(upper bool) *IPv6StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetUppercase(upper)
	return builder
}

func (builder *IPv6StringOptionsBuilder) ToOptions() IPv6StringOptions {
	if builder.makeMixed {
		if builder.opts.ipv4Opts == nil {
			builder.opts.ipv4Opts = NewIPv4StringOptionsBuilder().SetExpandedSegments(builder.expandSegments).
				SetWildcardOption(builder.ipStringOptions.wildcardOption).
				SetWildcards(builder.wildcards).ToOptions()
		}
	} else {
		builder.opts.ipv4Opts = nil
	}
	res := builder.opts
	res.ipStringOptions = *builder.IPStringOptionsBuilder.ToOptions().(*ipStringOptions)
	res.base, res.wildcards, res.separator, res.zoneSeparator = getDefaults(res.base, res.wildcards, res.separator, res.zoneSeparator)
	return &res
}

type CompressionChoiceOptions string

const (
	HOST_PREFERRED  CompressionChoiceOptions = "host preferred"  //if there is a host section, compress the host along with any adjoining zero segments, otherwise compress a range of zero segments
	MIXED_PREFERRED CompressionChoiceOptions = "mixed preferred" //if there is a mixed section that is compressible according to the MixedCompressionOptions, compress the mixed section along with any adjoining zero segments, otherwise compress a range of zero segments
	ZEROS_OR_HOST   CompressionChoiceOptions = ""                //compress the largest range of zero or host segments
	ZEROS           CompressionChoiceOptions = "zeros"           //compress the largest range of zero segments
)

func (c CompressionChoiceOptions) compressHost() bool {
	return c != ZEROS
}

type MixedCompressionOptions string

const (
	NO_MIXED_COMPRESSION  MixedCompressionOptions = "no mixed compression" //do not allow compression of a mixed section
	NO_HOST               MixedCompressionOptions = "no host"              ////allow compression of a mixed section when there is no host section
	COVERED_BY_HOST       MixedCompressionOptions = "covered by host"
	YES_MIXED_COMPRESSION MixedCompressionOptions = "" //allow compression of a mixed section
)

func (m MixedCompressionOptions) compressMixed(addressSection *IPv6AddressSection) bool {
	switch m {
	case YES_MIXED_COMPRESSION:
		return true
	case NO_MIXED_COMPRESSION:
		return false
	case NO_HOST:
		return !addressSection.IsPrefixed()
	case COVERED_BY_HOST:
		if addressSection.IsPrefixed() {
			//mixedDistance := int(IPv6MixedOriginalSegmentCount - addressSection.addressSegmentIndex)
			//if mixedDistance < 0 {
			//	mixedDistance = 0
			//}
			mixedDistance := IPv6MixedOriginalSegmentCount
			mixedCount := addressSection.GetSegmentCount() - mixedDistance
			if mixedCount > 0 {
				return (BitCount(mixedDistance) * addressSection.GetBitsPerSegment()) >= *addressSection.GetNetworkPrefixLength()
			}
		}
		return true
	default:
		return true
	}
}

type CompressOptions interface {
	GetCompressionChoiceOptions() CompressionChoiceOptions

	GetMixedCompressionOptions() MixedCompressionOptions

	CompressSingle() bool
}

type compressOptions struct {
	compressSingle bool

	rangeSelection CompressionChoiceOptions

	//options for addresses with an ipv4 section
	compressMixedOptions MixedCompressionOptions
}

func (c *compressOptions) GetCompressionChoiceOptions() CompressionChoiceOptions {
	return c.rangeSelection
}

func (c *compressOptions) GetMixedCompressionOptions() MixedCompressionOptions {
	return c.compressMixedOptions
}

func (c *compressOptions) CompressSingle() bool {
	return c.compressSingle
}

var _ CompressOptions = &compressOptions{}

type CompressOptionsBuilder struct {
	compressOptions
}

func (builder *CompressOptionsBuilder) SetCompressSingle(compressSingle bool) *CompressOptionsBuilder {
	builder.compressSingle = compressSingle
	return builder
}

func (builder *CompressOptionsBuilder) SetRangeSelection(rangeSelection CompressionChoiceOptions) *CompressOptionsBuilder {
	builder.rangeSelection = rangeSelection
	return builder
}

func (builder *CompressOptionsBuilder) SetMixedOptions(compressMixedOptions MixedCompressionOptions) *CompressOptionsBuilder {
	builder.compressMixedOptions = compressMixedOptions
	return builder
}

func (builder *CompressOptionsBuilder) ToOptions() CompressOptions {
	res := builder.compressOptions
	return &res
}
