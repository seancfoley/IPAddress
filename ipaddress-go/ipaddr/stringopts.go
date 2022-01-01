//
// Copyright 2020-2021 Sean C Foley
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

package ipaddr

//import "unsafe"
//
//// Wildcards specifies the wildcards to use when constructing a address string
//type Wildcards interface {
//	// GetRangeSeparator returns the wildcard used to separate the lower and upper boundary (inclusive) of a range of values.
//	// if this returns an empty string, then the default separator RangeSeparatorStr is used, which is the hyphen '-'
//	GetRangeSeparator() string
//
//	// GetWildcard returns the wildcard used for representing any legitimate value, which is the asterisk '*' by default
//	GetWildcard() string
//
//	// GetSingleWildcard returns the wildcard used for representing any single digit, which is the underscore '_' by default
//	GetSingleWildcard() string
//}
//
//type wildcards struct {
//	rangeSeparator, wildcard, singleWildcard string //rangeSeparator cannot be empty, the other two can
//}
//
//func (wildcards *wildcards) GetRangeSeparator() string {
//	return wildcards.rangeSeparator
//}
//
//func (wildcards *wildcards) GetWildcard() string {
//	return wildcards.wildcard
//}
//
//func (wildcards *wildcards) GetSingleWildcard() string {
//	return wildcards.singleWildcard
//}
//
//var DefaultWildcards Wildcards = &wildcards{rangeSeparator: RangeSeparatorStr, wildcard: SegmentWildcardStr}
//
//type WildcardsBuilder struct {
//	wildcards
//}
//
//func (wildcards *WildcardsBuilder) SetRangeSeparator(str string) *WildcardsBuilder {
//	wildcards.rangeSeparator = str
//	return wildcards
//}
//
//func (wildcards *WildcardsBuilder) SetWildcard(str string) *WildcardsBuilder {
//	wildcards.wildcard = str
//	return wildcards
//}
//
//func (wildcards *WildcardsBuilder) SetSingleWildcard(str string) *WildcardsBuilder {
//	wildcards.singleWildcard = str
//	return wildcards
//}
//
//func (wildcards *WildcardsBuilder) GetWildcard(str string) *WildcardsBuilder {
//	wildcards.wildcard = str
//	return wildcards
//}
//
//func (wildcards *WildcardsBuilder) GetSingleWildcard(str string) *WildcardsBuilder {
//	wildcards.singleWildcard = str
//	return wildcards
//}
//
//func (wildcards *WildcardsBuilder) ToWildcards() Wildcards {
//	res := wildcards.wildcards
//	if res.rangeSeparator == "" {
//		//rangeSeparator cannot be empty
//		res.rangeSeparator = RangeSeparatorStr
//	}
//	return &res
//}
//
////type StringOptionsBase struct {
////	// This is an object representing the string options converted to an object.
////	// It can write a supplied division using those params.
////	//Use this field if the options to params conversion is not dependent on the address part so it can be reused
////	cachedParams addressDivisionWriter
////}
//
//// Represents a clear way to create a specific type of string.
//type StringOptions interface {
//	GetWildcards() Wildcards
//
//	IsReverse() bool
//
//	IsUppercase() bool
//
//	IsExpandedSegments() bool
//
//	// the default is hexadecimal unless build using an IPv4 options build in which case the default is decimal
//	GetRadix() int
//
//	// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
//	// the default is a space, unless built using a MACSize, IPv6 or IPv4 options builder in which case the separator is ':' for MACSize and IPv6 wand '.' for IPv4
//	GetSeparator() byte
//
//	// default is false, no separator, unless built using a MACSize, IPv6 or IPv4 options builder in which case there is a default separator
//	HasSeparator() bool
//
//	GetAddressLabel() string
//
//	GetSegmentStrPrefix() string
//}
//
//type stringOptionsCache struct {
//	//cached *addressStringParams
//	cached unsafe.Pointer
//}
//
//type stringOptions struct {
//	wildcards Wildcards
//
//	base int // default is hex
//
//	//the segment separator and in the case of split digits, the digit separator
//	separator byte // default is ' ', but it's typically either '.' or ':'
//
//	segmentStrPrefix,
//	addrLabel string
//
//	expandSegments,
//	reverse,
//	uppercase bool
//
//	hasSeparator *bool // default is false, no separator
//
//	stringOptionsCache
//}
//
//func (w *stringOptions) GetStringOptionsCache() *stringOptionsCache {
//	return &w.stringOptionsCache
//}
//
//func (w *stringOptions) GetWildcards() Wildcards {
//	return w.wildcards
//}
//
//func (w *stringOptions) IsReverse() bool {
//	return w.reverse
//}
//
//func (w *stringOptions) IsUppercase() bool {
//	return w.uppercase
//}
//
////func (w *stringOptions) isSplitDigits() bool {
////	return w.splitDigits
////}
//
//func (w *stringOptions) IsExpandedSegments() bool {
//	return w.expandSegments
//}
//
//func (w *stringOptions) GetRadix() int {
//	return w.base
//}
//
//// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
//func (w *stringOptions) GetSeparator() byte {
//	return w.separator
//}
//
//func (w *stringOptions) HasSeparator() bool {
//	if w.hasSeparator == nil {
//		return false
//	}
//	return *w.hasSeparator
//}
//
//func (w *stringOptions) GetAddressLabel() string {
//	return w.addrLabel
//}
//
//func (w *stringOptions) GetSegmentStrPrefix() string {
//	return w.segmentStrPrefix
//}
//
//var _ StringOptions = &stringOptions{}
//
//func getDefaults(radix int, wildcards Wildcards, separator byte) (int, Wildcards, byte) {
//	if radix == 0 {
//		radix = 16
//	}
//	if wildcards == nil {
//		wildcards = DefaultWildcards
//	}
//	if separator == 0 {
//		separator = ' '
//	}
//	return radix, wildcards, separator
//}
//
//func getIPDefaults(zoneSeparator byte) byte {
//	if zoneSeparator == 0 {
//		zoneSeparator = IPv6ZoneSeparator
//	}
//	return zoneSeparator
//}
//
//func getIPv6Defaults(hasSeparator *bool, separator byte) (*bool, byte) {
//	if hasSeparator == nil {
//		hasSeparator = &trueVal
//	}
//	if separator == 0 {
//		separator = IPv6SegmentSeparator
//	}
//	return hasSeparator, separator
//}
//
//func getIPv4Defaults(hasSeparator *bool, separator byte, radix int) (*bool, byte, int) {
//	if hasSeparator == nil {
//		hasSeparator = &trueVal
//	}
//	if radix == 0 {
//		radix = 10
//	}
//	if separator == 0 {
//		separator = IPv4SegmentSeparator
//	}
//	return hasSeparator, separator, radix
//}
//
//func getMACDefaults(hasSeparator *bool, separator byte) (*bool, byte) {
//	if hasSeparator == nil {
//		hasSeparator = &trueVal
//	}
//	if separator == 0 {
//		separator = MACColonSegmentSeparator
//	}
//	return hasSeparator, separator
//}
//
//type StringOptionsBuilder struct {
//	stringOptions
//}
//
//func (w *StringOptionsBuilder) SetWildcards(wildcards Wildcards) *StringOptionsBuilder {
//	w.wildcards = wildcards
//	return w
//}
//
//func (w *StringOptionsBuilder) SetReverse(reverse bool) *StringOptionsBuilder {
//	w.reverse = reverse
//	return w
//}
//
//func (w *StringOptionsBuilder) SetUppercase(uppercase bool) *StringOptionsBuilder {
//	w.uppercase = uppercase
//	return w
//}
//
//func (w *StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *StringOptionsBuilder {
//	w.expandSegments = expandSegments
//	return w
//}
//
//func (w *StringOptionsBuilder) SetRadix(base int) *StringOptionsBuilder {
//	w.base = base
//	return w
//}
//
//func (w *StringOptionsBuilder) SetHasSeparator(has bool) *StringOptionsBuilder {
//	if has {
//		w.hasSeparator = &trueVal
//	} else {
//		w.hasSeparator = &falseVal
//	}
//	return w
//}
//
//// separates the divisions of the address, typically ':' or '.'
//func (w *StringOptionsBuilder) SetSeparator(separator byte) *StringOptionsBuilder {
//	w.separator = separator
//	w.SetHasSeparator(true)
//	return w
//}
//
//func (w *StringOptionsBuilder) SetAddressLabel(label string) *StringOptionsBuilder {
//	w.addrLabel = label
//	return w
//}
//
//func (w *StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *StringOptionsBuilder {
//	w.segmentStrPrefix = prefix
//	return w
//}
//
//func (w *StringOptionsBuilder) ToOptions() StringOptions {
//	res := w.stringOptions
//	res.base, res.wildcards, res.separator = getDefaults(res.base, res.wildcards, res.separator)
//	return &res
//}
//
//type MACStringOptionsBuilder struct {
//	StringOptionsBuilder
//}
//
//func (w *MACStringOptionsBuilder) SetWildcards(wildcards Wildcards) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetWildcards(wildcards)
//	return w
//}
//
//func (w *MACStringOptionsBuilder) SetReverse(reverse bool) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetReverse(reverse)
//	return w
//}
//
//func (w *MACStringOptionsBuilder) SetUppercase(uppercase bool) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetUppercase(uppercase)
//	return w
//}
//
//func (w *MACStringOptionsBuilder) SetExpandedSegments(expandSegments bool) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetExpandedSegments(expandSegments)
//	return w
//}
//
//func (w *MACStringOptionsBuilder) SetRadix(base int) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetRadix(base)
//	return w
//}
//
//func (w *MACStringOptionsBuilder) SetHasSeparator(has bool) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetHasSeparator(has)
//	return w
//}
//
//// separates the divisions of the address, typically ':' or '.'
//func (w *MACStringOptionsBuilder) SetSeparator(separator byte) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetSeparator(separator)
//	return w
//}
//
//func (w *MACStringOptionsBuilder) SetAddressLabel(label string) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetAddressLabel(label)
//	return w
//}
//
//func (w *MACStringOptionsBuilder) SetSegmentStrPrefix(prefix string) *MACStringOptionsBuilder {
//	w.StringOptionsBuilder.SetSegmentStrPrefix(prefix)
//	return w
//}
//
//func (builder *MACStringOptionsBuilder) ToOptions() StringOptions {
//	b := &builder.StringOptionsBuilder
//	b.hasSeparator, b.separator = getMACDefaults(b.hasSeparator, b.separator)
//	return builder.StringOptionsBuilder.ToOptions()
//}
//
//type WildcardOption string
//
//const (
//
//	// only print wildcards that are part of the network portion (only possible with subnet address notation, otherwise this option is ignored)
//	WildcardsNetworkOnly WildcardOption = ""
//
//	// print wildcards for any visible (non-compressed) segments
//	WildcardsAll WildcardOption = "allType"
//)
//
//type WildcardOptions interface {
//	GetWildcardOption() WildcardOption
//	GetWildcards() Wildcards
//}
//
//type wildcardOptions struct {
//	wildcardOption WildcardOption
//	wildcards      Wildcards
//}
//
//func (w *wildcardOptions) GetWildcardOption() WildcardOption {
//	return w.wildcardOption
//}
//
//func (w *wildcardOptions) GetWildcards() Wildcards {
//	return w.wildcards
//}
//
//var _ WildcardOptions = &wildcardOptions{}
//
//type WildcardOptionsBuilder struct {
//	wildcardOptions
//}
//
//func (w *WildcardOptionsBuilder) SetWildcardOptions(wildcardOption WildcardOption) *WildcardOptionsBuilder {
//	w.wildcardOption = wildcardOption
//	return w
//}
//
//func (w *WildcardOptionsBuilder) SetWildcards(wildcards Wildcards) *WildcardOptionsBuilder {
//	w.wildcards = wildcards
//	return w
//}
//
//func (w *WildcardOptionsBuilder) ToOptions() WildcardOptions {
//	cpy := w.wildcardOptions
//	if w.wildcards == nil {
//		w.wildcards = DefaultWildcards
//	}
//	return &cpy
//}
//
//type IPStringOptions interface {
//	StringOptions
//
//	GetAddressSuffix() string
//
//	GetWildcardOption() WildcardOption
//
//	//GetZoneSeparator() byte
//}
//
//type ipStringOptionsCache struct {
//	//cachedIPAddr *ipAddressStringParams
//	//cachedAddr   *addressStringParams
//	cachedIPAddr,
//	cachedAddr unsafe.Pointer
//}
//
//type ipStringOptions struct {
//	stringOptions
//
//	addrSuffix     string
//	wildcardOption WildcardOption // default is WildcardsNetworkOnly
//	zoneSeparator  byte           // default is IPv6ZoneSeparator
//
//	ipStringOptionsCache
//}
//
//func (w *ipStringOptions) GetIPStringOptionsCache() *ipStringOptionsCache {
//	return &w.ipStringOptionsCache
//}
//
//// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
//func (w *ipStringOptions) GetAddressSuffix() string {
//	return w.addrSuffix
//}
//
//func (w *ipStringOptions) GetWildcardOptions() WildcardOptions {
//	opts := &wildcardOptions{
//		w.wildcardOption,
//		w.GetWildcards(),
//	}
//	return opts
//}
//
//func (w *ipStringOptions) GetWildcardOption() WildcardOption {
//	return w.wildcardOption
//
//}
//
//func (w *ipStringOptions) GetZoneSeparator() byte {
//	return w.zoneSeparator
//}
//
//var _ IPStringOptions = &ipStringOptions{}
//
//type IPStringOptionsBuilder struct {
//	StringOptionsBuilder
//	ipStringOptions ipStringOptions
//}
//
//// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
//func (w *IPStringOptionsBuilder) SetAddressSuffix(suffix string) *IPStringOptionsBuilder {
//	w.ipStringOptions.addrSuffix = suffix
//	return w
//}
//
//// SetWildcardOptions is a convenience method for setting both the WildcardOption and the Wildcards at the same time
//// It overrides previous calls to SetWildcardOption and SetWildcards,
//// and is overridden by subsequent calls to those methods.
//func (w *IPStringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPStringOptionsBuilder {
//	w.SetWildcards(wildcardOptions.GetWildcards())
//	return w.SetWildcardOption(wildcardOptions.GetWildcardOption())
//}
//
//func (w *IPStringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPStringOptionsBuilder {
//	w.ipStringOptions.wildcardOption = wildcardOption
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetWildcards(wildcards)
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetZoneSeparator(separator byte) *IPStringOptionsBuilder {
//	w.ipStringOptions.zoneSeparator = separator
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetReverse(reverse bool) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetReverse(reverse)
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetUppercase(uppercase bool) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetUppercase(uppercase)
//	return w
//}
//
////func (w *IPStringOptionsBuilder) setSplitDigits(splitDigits bool) *IPStringOptionsBuilder {
////	w.StringOptionsBuilder.setSplitDigits(splitDigits)
////	return w
////}
//
//func (w *IPStringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetExpandedSegments(expandSegments)
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetRadix(base int) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetRadix(base)
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetHasSeparator(has bool) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetHasSeparator(has)
//	return w
//}
//
//// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
//func (w *IPStringOptionsBuilder) SetSeparator(separator byte) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetSeparator(separator)
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetAddressLabel(label string) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetAddressLabel(label)
//	return w
//}
//
//func (w *IPStringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPStringOptionsBuilder {
//	w.StringOptionsBuilder.SetSegmentStrPrefix(prefix)
//	return w
//}
//
//func (w *IPStringOptionsBuilder) ToOptions() IPStringOptions {
//	w.ipStringOptions.zoneSeparator = getIPDefaults(w.ipStringOptions.zoneSeparator)
//	res := w.ipStringOptions
//	res.stringOptions = *w.StringOptionsBuilder.ToOptions().(*stringOptions)
//	return &res
//}
//
//type IPv4StringOptionsBuilder struct {
//	IPStringOptionsBuilder
//}
//
//// .in-addr.arpa, .ip6.arpa, .ipv6-literal.net are examples of suffixes tacked onto the end of address strings
//func (w *IPv4StringOptionsBuilder) SetAddressSuffix(suffix string) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetAddressSuffix(suffix)
//	return w
//}
//
//// SetWildcardOptions is a convenience method for setting both the WildcardOption and the Wildcards at the same time
//// It overrides previous calls to SetWildcardOption and SetWildcards,
//// and is overridden by subsequent calls to those methods.
//func (w *IPv4StringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetWildcardOptions(wildcardOptions)
//	return w.SetWildcardOption(wildcardOptions.GetWildcardOption())
//}
//
//func (w *IPv4StringOptionsBuilder) SetWildcardOption(wildcardOption WildcardOption) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetWildcardOption(wildcardOption)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetWildcards(wildcards Wildcards) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetWildcards(wildcards)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetZoneSeparator(separator byte) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetZoneSeparator(separator)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetReverse(reverse bool) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetReverse(reverse)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetUppercase(uppercase bool) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetUppercase(uppercase)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetExpandedSegments(expandSegments)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetRadix(base int) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetRadix(base)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetHasSeparator(has bool) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetHasSeparator(has)
//	return w
//}
//
//// separates the divisions of the address, typically ':' or '.', but also can be null for no separator
//func (w *IPv4StringOptionsBuilder) SetSeparator(separator byte) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetSeparator(separator)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetAddressLabel(label string) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetAddressLabel(label)
//	return w
//}
//
//func (w *IPv4StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPv4StringOptionsBuilder {
//	w.IPStringOptionsBuilder.SetSegmentStrPrefix(prefix)
//	return w
//}
//
//func (builder *IPv4StringOptionsBuilder) ToOptions() IPStringOptions {
//	b := &builder.StringOptionsBuilder
//	b.hasSeparator, b.separator, b.base = getIPv4Defaults(b.hasSeparator, b.separator, b.base)
//	return builder.IPStringOptionsBuilder.ToOptions()
//}
//
////xxx this blows xxxx
////xxx use a bool and get rid of these xxx
////xxx actually, can just use zero values for the separator and radix
////BUT how to handle ipv4? maybe IPStringOptionsBuilder has defaults of radix 10 and sep ., ipv6 otherwise
////OR you create a new IPv4StringOptionsBuilder?  It just wraps IPStringOptionsBuilder?
////If you do that, maybe you remove the default separator
////but then, you already have hex as the default radix - so not so sure
////hmmmmm
////Let us wrap both MACSize and IPv4
////and then all three MACSize/IPv4/6 will all have their own getDefaults
////xxx
//
////// NewIPv4StringOptionsBuilder returns a builder with default options set to create a specific type of IPv4 address string.
////func NewIPv4StringOptionsBuilder() *IPStringOptionsBuilder {
////	opts := IPStringOptionsBuilder{}
////	return opts.SetRadix(IPv4DefaultTextualRadix).SetSeparator(IPv4SegmentSeparator)
////}
////
////// NewMACStringOptionsBuilder returns a builder with default options set to create a specific type of MACSize address string.
////func NewMACStringOptionsBuilder() *StringOptionsBuilder {
////	opts := StringOptionsBuilder{}
////	return opts.SetRadix(MACDefaultTextualRadix).SetSeparator(MACColonSegmentSeparator)
////}
////
////// NewIPv6StringOptionsBuilder returns a builder with default options set to create a specific type of IPv6 address string.
////func NewIPv6StringOptionsBuilder() *IPv6StringOptionsBuilder {
////	opts := IPv6StringOptionsBuilder{}
////	return opts.SetRadix(IPv6DefaultTextualRadix).SetSeparator(IPv6SegmentSeparator)
////}
//
//type IPv6StringOptions interface {
//	IPStringOptions
//
//	// Returns the options used for creating the embedded IPv4 address string in a mixed IPv6 address,
//	// which comes from the last 32 bits of the IPv6 address.
//	// For example: a:b:c:d:e:f:1.2.3.4
//	GetIPv4Opts() IPStringOptions
//
//	GetCompressOptions() CompressOptions
//
//	// Whether every digit is separated from others by separators.  If mixed, this option is ignored.
//	IsSplitDigits() bool // can produceaddrerr.IncompatibleAddressError for ranged series
//
//	IsMixed() bool // can produceaddrerr.IncompatibleAddressError for ranges in the IPv4 part of the series
//
//	GetZoneSeparator() byte
//}
//
//func isCacheable(options IPv6StringOptions) bool {
//	return options.GetCompressOptions() == nil
//}
//
//type ipv6StringOptionsCache struct {
//	//cachedIPv6Addr      *ipv6StringParams
//	//cachedMixedIPv6Addr *ipv6v4MixedParams
//	cachedIPv6Addr,
//	cachedMixedIPv6Addr unsafe.Pointer
//}
//
//// Provides a clear way to create a specific type of IPv6 address string.
//type ipv6StringOptions struct {
//	ipStringOptions
//	ipv4Opts IPStringOptions
//
//	//can be nil, which means no compression
//	compressOptions CompressOptions
//
//	ipv6StringOptionsCache
//
//	splitDigits bool
//}
//
//func (opts *ipv6StringOptions) GetIPv6StringOptionsCache() *ipv6StringOptionsCache {
//	return &opts.ipv6StringOptionsCache
//}
//
////func (opts *ipv6StringOptions) isCacheable() bool {
////	return opts.compressOptions == nil
////}
//
////func (opts *ipv6StringOptions) makeMixed() bool {
////	return opts.ipv4Opts != nil
////}
//
//func (opts *ipv6StringOptions) IsSplitDigits() bool {
//	return opts.splitDigits
//}
//
//func (opts *ipv6StringOptions) GetIPv4Opts() IPStringOptions {
//	return opts.ipv4Opts
//}
//
//func (opts *ipv6StringOptions) GetCompressOptions() CompressOptions {
//	return opts.compressOptions
//}
//
//func (opts *ipv6StringOptions) IsMixed() bool {
//	return opts.ipv4Opts != nil
//}
//
//var _ IPv6StringOptions = &ipv6StringOptions{}
//
//type IPv6StringOptionsBuilder struct {
//	opts ipv6StringOptions
//
//	IPStringOptionsBuilder
//
//	makeMixed bool
//}
//
//func (builder *IPv6StringOptionsBuilder) IsMixed() bool {
//	return builder.makeMixed
//}
//
//func (builder *IPv6StringOptionsBuilder) GetIPv4Opts() IPStringOptions {
//	return builder.opts.ipv4Opts
//}
//
//func (builder *IPv6StringOptionsBuilder) GetCompressOptions() CompressOptions {
//	return builder.opts.compressOptions
//}
//
//func (builder *IPv6StringOptionsBuilder) SetSplitDigits(splitDigits bool) *IPv6StringOptionsBuilder {
//	builder.opts.splitDigits = splitDigits
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetCompressOptions(compressOptions CompressOptions) *IPv6StringOptionsBuilder {
//	builder.opts.compressOptions = compressOptions
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetMixed(makeMixed bool) *IPv6StringOptionsBuilder {
//	builder.makeMixed = makeMixed
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetMixedOptions(ipv4Options IPStringOptions) *IPv6StringOptionsBuilder {
//	builder.makeMixed = true
//	builder.opts.ipv4Opts = ipv4Options
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetWildcardOptions(wildcardOptions WildcardOptions) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetWildcardOptions(wildcardOptions)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetExpandedSegments(expandSegments bool) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetExpandedSegments(expandSegments)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetRadix(base int) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetRadix(base)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetHasSeparator(has bool) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetHasSeparator(has)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetSeparator(separator byte) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetSeparator(separator)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetZoneSeparator(separator byte) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetZoneSeparator(separator)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetAddressSuffix(suffix string) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetAddressSuffix(suffix)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetSegmentStrPrefix(prefix string) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetSegmentStrPrefix(prefix)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetReverse(reverse bool) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetReverse(reverse)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) SetUppercase(upper bool) *IPv6StringOptionsBuilder {
//	builder.IPStringOptionsBuilder.SetUppercase(upper)
//	return builder
//}
//
//func (builder *IPv6StringOptionsBuilder) ToOptions() IPv6StringOptions {
//	if builder.makeMixed {
//		if builder.opts.ipv4Opts == nil {
//			builder.opts.ipv4Opts = new(IPv4StringOptionsBuilder).SetExpandedSegments(builder.expandSegments).
//				SetWildcardOption(builder.ipStringOptions.wildcardOption).
//				SetWildcards(builder.wildcards).ToOptions()
//		}
//	} else {
//		builder.opts.ipv4Opts = nil
//	}
//	b := &builder.IPStringOptionsBuilder.StringOptionsBuilder
//	b.hasSeparator, b.separator = getIPv6Defaults(b.hasSeparator, b.separator)
//	res := builder.opts
//	res.ipStringOptions = *builder.IPStringOptionsBuilder.ToOptions().(*ipStringOptions)
//	return &res
//}
//
//type CompressionChoiceOptions string
//
//const (
//	HostPreferred    CompressionChoiceOptions = "host preferred"  //if there is a host section, compress the host along with any adjoining zero segments, otherwise compress a range of zero segments
//	MixedPreferred   CompressionChoiceOptions = "mixed preferred" //if there is a mixed section that is compressible according to the MixedCompressionOptions, compress the mixed section along with any adjoining zero segments, otherwise compress a range of zero segments
//	ZerosOrHost      CompressionChoiceOptions = ""                //compress the largest range of zero or host segments
//	ZerosCompression CompressionChoiceOptions = "zeros"           //compress the largest range of zero segments
//)
//
//func (c CompressionChoiceOptions) compressHost() bool {
//	return c != ZerosCompression
//}
//
//type MixedCompressionOptions string
//
//const (
//	NoMixedCompression            MixedCompressionOptions = "no mixed compression" //do not allow compression of a mixed section
//	MixedCompressionNoHost        MixedCompressionOptions = "no host"              ////allow compression of a mixed section when there is no host section
//	MixedCompressionCoveredByHost MixedCompressionOptions = "covered by host"
//	AllowMixedCompression         MixedCompressionOptions = "" //allow compression of a mixed section
//)
//
////func (m MixedCompressionOptions) compressMixed(addressSection *IPv6AddressSection) bool {
////	switch m {
////	case AllowMixedCompression:
////		return true
////	case NoMixedCompression:
////		return false
////	case MixedCompressionNoHost:
////		return !addressSection.IsPrefixed()
////	case MixedCompressionCoveredByHost:
////		if addressSection.IsPrefixed() {
////			mixedDistance := IPv6MixedOriginalSegmentCount
////			mixedCount := addressSection.GetSegmentCount() - mixedDistance
////			if mixedCount > 0 {
////				return (BitCount(mixedDistance) * addressSection.GetBitsPerSegment()) >= addressSection.getNetworkPrefixLen().bitCount()
////			}
////		}
////		return true
////	default:
////		return true
////	}
////}
//
//type CompressOptions interface {
//	GetCompressionChoiceOptions() CompressionChoiceOptions
//
//	GetMixedCompressionOptions() MixedCompressionOptions
//
//	CompressSingle() bool
//}
//
//type compressOptions struct {
//	compressSingle bool
//
//	rangeSelection CompressionChoiceOptions
//
//	//options for addresses with an ipv4 section
//	compressMixedOptions MixedCompressionOptions
//}
//
//func (c *compressOptions) GetCompressionChoiceOptions() CompressionChoiceOptions {
//	return c.rangeSelection
//}
//
//func (c *compressOptions) GetMixedCompressionOptions() MixedCompressionOptions {
//	return c.compressMixedOptions
//}
//
//func (c *compressOptions) CompressSingle() bool {
//	return c.compressSingle
//}
//
//var _ CompressOptions = &compressOptions{}
//
//type CompressOptionsBuilder struct {
//	compressOptions
//}
//
//func (builder *CompressOptionsBuilder) SetCompressSingle(compressSingle bool) *CompressOptionsBuilder {
//	builder.compressSingle = compressSingle
//	return builder
//}
//
//func (builder *CompressOptionsBuilder) SetRangeSelection(rangeSelection CompressionChoiceOptions) *CompressOptionsBuilder {
//	builder.rangeSelection = rangeSelection
//	return builder
//}
//
//func (builder *CompressOptionsBuilder) SetMixedOptions(compressMixedOptions MixedCompressionOptions) *CompressOptionsBuilder {
//	builder.compressMixedOptions = compressMixedOptions
//	return builder
//}
//
//func (builder *CompressOptionsBuilder) ToOptions() CompressOptions {
//	res := builder.compressOptions
//	return &res
//}
