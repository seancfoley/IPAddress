//
// Copyright 2020-2022 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/*
addrstr provides interfaces for specifying how to create specific strings from addresses and address sections,
as well as builder types to construct instances of those interfaces.

For example, StringOptionsBuilder produces instances implementing StringOptions for specifiying generic strings.
More specific builders and corresponding interface types exist for more specific address versions and types.

Each instance produced by a builders is immutable.
*/
package addrstr

import "unsafe"

var (
	falseVal = false
	trueVal  = true
)

// Wildcards specifies the wildcards to use when constructing a address string
type Wildcards interface {
	// GetRangeSeparator returns the wildcard used to separate the lower and upper boundary (inclusive) of a range of values.
	// if this returns an empty string, then the default separator RangeSeparatorStr is used, which is the hyphen '-'
	GetRangeSeparator() string

	// GetWildcard returns the wildcard used for representing any legitimate value, which is the asterisk '*' by default
	GetWildcard() string

	// GetSingleWildcard returns the wildcard used for representing any single digit, which is the underscore '_' by default
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

var DefaultWildcards Wildcards = &wildcards{rangeSeparator: rangeSeparatorStr, wildcard: segmentWildcardStr}

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

const (
	ipv6SegmentSeparator     = ':'
	ipv6ZoneSeparator        = '%'
	ipv4SegmentSeparator     = '.'
	macColonSegmentSeparator = ':'
	rangeSeparatorStr        = "-"
	segmentWildcardStr       = "*"
)

func (wildcards *WildcardsBuilder) ToWildcards() Wildcards {
	res := wildcards.wildcards
	if res.rangeSeparator == "" {
		//rangeSeparator cannot be empty
		res.rangeSeparator = rangeSeparatorStr
	}
	return &res
}

// StringOptions represents a clear way to create a specific type of string.
type StringOptions interface {
	GetWildcards() Wildcards

	IsReverse() bool

	IsUppercase() bool

	IsExpandedSegments() bool

	// the default is hexadecimal unless build using an IPv4 options build in which case the default is decimal
	GetRadix() int

	// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
	// the default is a space, unless built using a MAC, IPv6 or IPv4 options builder in which case the separator is ':' for MAC and IPv6 and '.' for IPv4
	GetSeparator() byte

	// default is false, no separator, unless built using a MAC, IPv6 or IPv4 options builder in which case there is a default separator
	HasSeparator() bool

	GetAddressLabel() string

	GetSegmentStrPrefix() string
}

type stringOptionsCache struct {
	cached unsafe.Pointer
}

type stringOptions struct {
	wildcards Wildcards

	base int // default is hex

	//the segment separator and in the case of split digits, the digit separator
	separator byte // default is ' ', but it's typically either '.' or ':'

	segmentStrPrefix,
	addrLabel string

	expandSegments,
	reverse,
	uppercase bool

	hasSeparator *bool // default is false, no separator

	stringOptionsCache
}

func (opts *stringOptions) GetStringOptionsCache() *unsafe.Pointer {
	return &opts.stringOptionsCache.cached
}

func (opts *stringOptions) GetWildcards() Wildcards {
	return opts.wildcards
}

func (opts *stringOptions) IsReverse() bool {
	return opts.reverse
}

func (opts *stringOptions) IsUppercase() bool {
	return opts.uppercase
}

func (opts *stringOptions) IsExpandedSegments() bool {
	return opts.expandSegments
}

func (opts *stringOptions) GetRadix() int {
	return opts.base
}

// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
func (opts *stringOptions) GetSeparator() byte {
	return opts.separator
}

func (opts *stringOptions) HasSeparator() bool {
	if opts.hasSeparator == nil {
		return false
	}
	return *opts.hasSeparator
}

func (opts *stringOptions) GetAddressLabel() string {
	return opts.addrLabel
}

func (opts *stringOptions) GetSegmentStrPrefix() string {
	return opts.segmentStrPrefix
}

var _ StringOptions = &stringOptions{}

func getDefaults(radix int, wildcards Wildcards, separator byte) (int, Wildcards, byte) {
	if radix == 0 {
		radix = 16
	}
	if wildcards == nil {
		wildcards = DefaultWildcards
	}
	if separator == 0 {
		separator = ' '
	}
	return radix, wildcards, separator
}

func getIPDefaults(zoneSeparator byte) byte {
	if zoneSeparator == 0 {
		zoneSeparator = ipv6ZoneSeparator
	}
	return zoneSeparator
}

func getIPv6Defaults(hasSeparator *bool, separator byte) (*bool, byte) {
	if hasSeparator == nil {
		hasSeparator = &trueVal
	}
	if separator == 0 {
		separator = ipv6SegmentSeparator
	}
	return hasSeparator, separator
}

func getIPv4Defaults(hasSeparator *bool, separator byte, radix int) (*bool, byte, int) {
	if hasSeparator == nil {
		hasSeparator = &trueVal
	}
	if radix == 0 {
		radix = 10
	}
	if separator == 0 {
		separator = ipv4SegmentSeparator
	}
	return hasSeparator, separator, radix
}

func getMACDefaults(hasSeparator *bool, separator byte) (*bool, byte) {
	if hasSeparator == nil {
		hasSeparator = &trueVal
	}
	if separator == 0 {
		separator = macColonSegmentSeparator
	}
	return hasSeparator, separator
}

type StringOptionsBuilder struct {
	stringOptions
}

func (builder *StringOptionsBuilder) SetWildcards(wildcards Wildcards) *StringOptionsBuilder {
	builder.wildcards = wildcards
	return builder
}

func (builder *StringOptionsBuilder) SetReverse(reverse bool) *StringOptionsBuilder {
	builder.reverse = reverse
	return builder
}

func (builder *StringOptionsBuilder) SetUppercase(uppercase bool) *StringOptionsBuilder {
	builder.uppercase = uppercase
	return builder
}

func (builder *StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *StringOptionsBuilder {
	builder.expandSegments = expandSegments
	return builder
}

func (builder *StringOptionsBuilder) SetRadix(base int) *StringOptionsBuilder {
	builder.base = base
	return builder
}

func (builder *StringOptionsBuilder) SetHasSeparator(has bool) *StringOptionsBuilder {
	if has {
		builder.hasSeparator = &trueVal
	} else {
		builder.hasSeparator = &falseVal
	}
	return builder
}

// separates the divisions of the address, typically ':' or '.'
func (builder *StringOptionsBuilder) SetSeparator(separator byte) *StringOptionsBuilder {
	builder.separator = separator
	builder.SetHasSeparator(true)
	return builder
}

func (builder *StringOptionsBuilder) SetAddressLabel(label string) *StringOptionsBuilder {
	builder.addrLabel = label
	return builder
}

func (builder *StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *StringOptionsBuilder {
	builder.segmentStrPrefix = prefix
	return builder
}

func (builder *StringOptionsBuilder) ToOptions() StringOptions {
	res := builder.stringOptions
	res.base, res.wildcards, res.separator = getDefaults(res.base, res.wildcards, res.separator)
	return &res
}

type MACStringOptionsBuilder struct {
	StringOptionsBuilder
}

func (builder *MACStringOptionsBuilder) SetWildcards(wildcards Wildcards) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetWildcards(wildcards)
	return builder
}

func (builder *MACStringOptionsBuilder) SetReverse(reverse bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetReverse(reverse)
	return builder
}

func (builder *MACStringOptionsBuilder) SetUppercase(uppercase bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetUppercase(uppercase)
	return builder
}

func (builder *MACStringOptionsBuilder) SetExpandedSegments(expandSegments bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

func (builder *MACStringOptionsBuilder) SetRadix(base int) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetRadix(base)
	return builder
}

func (builder *MACStringOptionsBuilder) SetHasSeparator(has bool) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetHasSeparator(has)
	return builder
}

// separates the divisions of the address, typically ':' or '.'
func (builder *MACStringOptionsBuilder) SetSeparator(separator byte) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSeparator(separator)
	return builder
}

func (builder *MACStringOptionsBuilder) SetAddressLabel(label string) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetAddressLabel(label)
	return builder
}

func (builder *MACStringOptionsBuilder) SetSegmentStrPrefix(prefix string) *MACStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

func (builder *MACStringOptionsBuilder) ToOptions() StringOptions {
	b := &builder.StringOptionsBuilder
	b.hasSeparator, b.separator = getMACDefaults(b.hasSeparator, b.separator)
	return builder.StringOptionsBuilder.ToOptions()
}

type WildcardOption string

const (

	// only print wildcards that are part of the network portion (only possible with subnet address notation, otherwise this option is ignored)
	WildcardsNetworkOnly WildcardOption = ""

	// print wildcards for any visible (non-compressed) segments
	WildcardsAll WildcardOption = "allType"
)

type WildcardOptions interface {
	GetWildcardOption() WildcardOption
	GetWildcards() Wildcards
}

type wildcardOptions struct {
	wildcardOption WildcardOption
	wildcards      Wildcards
}

func (opts *wildcardOptions) GetWildcardOption() WildcardOption {
	return opts.wildcardOption
}

func (opts *wildcardOptions) GetWildcards() Wildcards {
	return opts.wildcards
}

var _ WildcardOptions = &wildcardOptions{}

type WildcardOptionsBuilder struct {
	wildcardOptions
}

func (builder *WildcardOptionsBuilder) SetWildcardOptions(wildcardOption WildcardOption) *WildcardOptionsBuilder {
	builder.wildcardOption = wildcardOption
	return builder
}

func (builder *WildcardOptionsBuilder) SetWildcards(wildcards Wildcards) *WildcardOptionsBuilder {
	builder.wildcards = wildcards
	return builder
}

func (builder *WildcardOptionsBuilder) ToOptions() WildcardOptions {
	cpy := builder.wildcardOptions
	if builder.wildcards == nil {
		builder.wildcards = DefaultWildcards
	}
	return &cpy
}

type IPStringOptions interface {
	StringOptions

	GetAddressSuffix() string

	GetWildcardOption() WildcardOption
}

type ipStringOptionsCache struct {
	cachedIPAddr,
	cachedAddr unsafe.Pointer
}

type ipStringOptions struct {
	stringOptions

	addrSuffix     string
	wildcardOption WildcardOption // default is WildcardsNetworkOnly
	zoneSeparator  byte           // default is IPv6ZoneSeparator

	ipStringOptionsCache
}

func (opts *ipStringOptions) GetIPStringOptionsIPCache() *unsafe.Pointer {
	return &opts.ipStringOptionsCache.cachedIPAddr
}

func (opts *ipStringOptions) GetIPStringOptionsCache() *unsafe.Pointer {
	return &opts.ipStringOptionsCache.cachedAddr
}

// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
func (opts *ipStringOptions) GetAddressSuffix() string {
	return opts.addrSuffix
}

func (opts *ipStringOptions) GetWildcardOptions() WildcardOptions {
	options := &wildcardOptions{
		opts.wildcardOption,
		opts.GetWildcards(),
	}
	return options
}

func (opts *ipStringOptions) GetWildcardOption() WildcardOption {
	return opts.wildcardOption

}

func (opts *ipStringOptions) GetZoneSeparator() byte {
	return opts.zoneSeparator
}

var _ IPStringOptions = &ipStringOptions{}

type IPStringOptionsBuilder struct {
	StringOptionsBuilder
	ipStringOptions ipStringOptions
}

// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
func (builder *IPStringOptionsBuilder) SetAddressSuffix(suffix string) *IPStringOptionsBuilder {
	builder.ipStringOptions.addrSuffix = suffix
	return builder
}

// SetWildcardOptions is a convenience method for setting both the WildcardOption and the Wildcards at the same time
// It overrides previous calls to SetWildcardOption and SetWildcards,
// and is overridden by subsequent calls to those methods.
func (builder *IPStringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPStringOptionsBuilder {
	builder.SetWildcards(wildcardOptions.GetWildcards())
	return builder.SetWildcardOption(wildcardOptions.GetWildcardOption())
}

func (builder *IPStringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPStringOptionsBuilder {
	builder.ipStringOptions.wildcardOption = wildcardOption
	return builder
}

func (builder *IPStringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetWildcards(wildcards)
	return builder
}

func (builder *IPStringOptionsBuilder) SetZoneSeparator(separator byte) *IPStringOptionsBuilder {
	builder.ipStringOptions.zoneSeparator = separator
	return builder
}

func (builder *IPStringOptionsBuilder) SetReverse(reverse bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetReverse(reverse)
	return builder
}

func (builder *IPStringOptionsBuilder) SetUppercase(uppercase bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetUppercase(uppercase)
	return builder
}

func (builder *IPStringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

func (builder *IPStringOptionsBuilder) SetRadix(base int) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetRadix(base)
	return builder
}

func (builder *IPStringOptionsBuilder) SetHasSeparator(has bool) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetHasSeparator(has)
	return builder
}

// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
func (builder *IPStringOptionsBuilder) SetSeparator(separator byte) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSeparator(separator)
	return builder
}

func (builder *IPStringOptionsBuilder) SetAddressLabel(label string) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetAddressLabel(label)
	return builder
}

func (builder *IPStringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPStringOptionsBuilder {
	builder.StringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

func (builder *IPStringOptionsBuilder) ToOptions() IPStringOptions {
	builder.ipStringOptions.zoneSeparator = getIPDefaults(builder.ipStringOptions.zoneSeparator)
	res := builder.ipStringOptions
	res.stringOptions = *builder.StringOptionsBuilder.ToOptions().(*stringOptions)
	return &res
}

type IPv4StringOptionsBuilder struct {
	IPStringOptionsBuilder
}

// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
func (builder *IPv4StringOptionsBuilder) SetAddressSuffix(suffix string) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetAddressSuffix(suffix)
	return builder
}

// SetWildcardOptions is a convenience method for setting both the WildcardOption and the Wildcards at the same time
// It overrides previous calls to SetWildcardOption and SetWildcards,
// and is overridden by subsequent calls to those methods.
func (builder *IPv4StringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcardOptions(wildcardOptions)
	return builder.SetWildcardOption(wildcardOptions.GetWildcardOption())
}

func (builder *IPv4StringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcardOption(wildcardOption)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetWildcards(wildcards)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetZoneSeparator(separator byte) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetZoneSeparator(separator)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetReverse(reverse bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetReverse(reverse)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetUppercase(uppercase bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetUppercase(uppercase)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetExpandedSegments(expandSegments)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetRadix(base int) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetRadix(base)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetHasSeparator(has bool) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetHasSeparator(has)
	return builder
}

// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
func (builder *IPv4StringOptionsBuilder) SetSeparator(separator byte) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSeparator(separator)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetAddressLabel(label string) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetAddressLabel(label)
	return builder
}

func (builder *IPv4StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPv4StringOptionsBuilder {
	builder.IPStringOptionsBuilder.SetSegmentStrPrefix(prefix)
	return builder
}

func (builder *IPv4StringOptionsBuilder) ToOptions() IPStringOptions {
	b := &builder.StringOptionsBuilder
	b.hasSeparator, b.separator, b.base = getIPv4Defaults(b.hasSeparator, b.separator, b.base)
	return builder.IPStringOptionsBuilder.ToOptions()
}

type IPv6StringOptions interface {
	IPStringOptions

	// Returns the options used for creating the embedded IPv4 address string in a mixed IPv6 address,
	// which comes from the last 32 bits of the IPv6 address.
	// For example: a:b:c:d:e:f:1.2.3.4
	GetIPv4Opts() IPStringOptions

	GetCompressOptions() CompressOptions

	// Whether every digit is separated from others by separators.  If mixed, this option is ignored.
	IsSplitDigits() bool // can produceaddrerr.IncompatibleAddressError for ranged series

	IsMixed() bool // can produceaddrerr.IncompatibleAddressError for ranges in the IPv4 part of the series

	GetZoneSeparator() byte
}

type ipv6StringOptionsCache struct {
	cachedIPv6Addr,
	cachedMixedIPv6Addr unsafe.Pointer
}

// Provides a clear way to create a specific type of IPv6 address string.
type ipv6StringOptions struct {
	ipStringOptions
	ipv4Opts IPStringOptions

	//can be nil, which means no compression
	compressOptions CompressOptions

	ipv6StringOptionsCache

	splitDigits bool
}

func (opts *ipv6StringOptions) GetIPv6StringOptionsCache() *unsafe.Pointer {
	return &opts.ipv6StringOptionsCache.cachedIPv6Addr
}

func (opts *ipv6StringOptions) GetIPv6StringOptionsMixedCache() *unsafe.Pointer {
	return &opts.ipv6StringOptionsCache.cachedMixedIPv6Addr
}

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
			builder.opts.ipv4Opts = new(IPv4StringOptionsBuilder).SetExpandedSegments(builder.expandSegments).
				SetWildcardOption(builder.ipStringOptions.wildcardOption).
				SetWildcards(builder.wildcards).ToOptions()
		}
	} else {
		builder.opts.ipv4Opts = nil
	}
	b := &builder.IPStringOptionsBuilder.StringOptionsBuilder
	b.hasSeparator, b.separator = getIPv6Defaults(b.hasSeparator, b.separator)
	res := builder.opts
	res.ipStringOptions = *builder.IPStringOptionsBuilder.ToOptions().(*ipStringOptions)
	return &res
}

type CompressionChoiceOptions string

const (
	HostPreferred    CompressionChoiceOptions = "host preferred"  //if there is a host section, compress the host along with any adjoining zero segments, otherwise compress a range of zero segments
	MixedPreferred   CompressionChoiceOptions = "mixed preferred" //if there is a mixed section that is compressible according to the MixedCompressionOptions, compress the mixed section along with any adjoining zero segments, otherwise compress a range of zero segments
	ZerosOrHost      CompressionChoiceOptions = ""                //compress the largest range of zero or host segments
	ZerosCompression CompressionChoiceOptions = "zeros"           //compress the largest range of zero segments
)

func (choice CompressionChoiceOptions) CompressHost() bool {
	return choice != ZerosCompression
}

type MixedCompressionOptions string

const (
	NoMixedCompression            MixedCompressionOptions = "no mixed compression" //do not allow compression of a mixed section
	MixedCompressionNoHost        MixedCompressionOptions = "no host"              ////allow compression of a mixed section when there is no host section
	MixedCompressionCoveredByHost MixedCompressionOptions = "covered by host"
	AllowMixedCompression         MixedCompressionOptions = "" //allow compression of a mixed section
)

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

func (opts *compressOptions) GetCompressionChoiceOptions() CompressionChoiceOptions {
	return opts.rangeSelection
}

func (opts *compressOptions) GetMixedCompressionOptions() MixedCompressionOptions {
	return opts.compressMixedOptions
}

func (opts *compressOptions) CompressSingle() bool {
	return opts.compressSingle
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
