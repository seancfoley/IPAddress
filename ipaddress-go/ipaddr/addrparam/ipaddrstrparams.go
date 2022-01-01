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

package addrparam

import "strings"

//func convertIPAddrParams(orig IPAddressStringParams) *ipAddressStringParameters { //note this is a duplicate of getPrivateParams which calls ToIPAddressStringParamsBuilder(orig).ToParams()
//	if params, ok := orig.(*ipAddressStringParameters); ok {
//		return params
//	}
//	origIPv4 := orig.GetIPv4Params()
//	origIPv4Range := origIPv4.GetRangeParams()
//	origIPv6 := orig.GetIPv6Params()
//	origIPv6Range := origIPv6.GetRangeParams()
//	origMixedIPv4 := origIPv6.GetEmbeddedIPv4AddressParams()
//	origMixedIPv4Range := origMixedIPv4.GetRangeParams()
//	paramsBuilder := IPAddressStringParamsBuilder{}
//	return paramsBuilder.
//		// general settings
//		AllowIPv6(orig.AllowsIPv6()).
//		AllowIPv4(orig.AllowsIPv4()).
//		SetEmptyLoopback(orig.EmptyIsLoopback()).
//		AllowMask(orig.AllowsMask()).
//		AllowPrefixOnly(orig.AllowsPrefixOnly()).
//		AllowPrefix(orig.AllowsPrefix()).
//		AllowEmpty(orig.AllowsEmpty()).
//		AllowSingleSegment(orig.AllowsSingleSegment()).
//		AllowAll(orig.AllowsAll()).
//		//
//		// IPv6 settings
//		GetIPv6AddressParamsBuilder().
//		AllowZone(origIPv6.AllowsZone()).
//		AllowMixed(origIPv6.AllowsMixed()).
//		AllowBase85(origIPv6.AllowsBase85()).
//		AllowBinary(origIPv6.AllowsBinary()).
//		AllowWildcardedSeparator(origIPv6.AllowsWildcardedSeparator()).
//		AllowLeadingZeros(origIPv6.AllowsLeadingZeros()).
//		AllowUnlimitedLeadingZeros(origIPv6.AllowsUnlimitedLeadingZeros()).
//		AllowPrefixesBeyondAddressSize(origIPv6.AllowsPrefixesBeyondAddressSize()).
//		AllowPrefixLenLeadingZeros(origIPv6.AllowsPrefixLenLeadingZeros()).
//		//
//		// IPv6 ranges
//		GetRangeParamsBuilder().
//		AllowWildcard(origIPv6Range.AllowsWildcard()).
//		AllowRangeSeparator(origIPv6Range.AllowsRangeSeparator()).
//		AllowReverseRange(origIPv6Range.AllowsReverseRange()).
//		AllowInferredBoundary(origIPv6Range.AllowsInferredBoundary()).
//		AllowSingleWildcard(origIPv6Range.AllowsSingleWildcard()).
//		GetIPv6ParentBuilder().
//		//
//		// mixed-in embedded ipv4AddrType settings (the 1.2.3.4 in a:b:c:d:e:f:1.2.3.4)
//		GetEmbeddedIPv4AddressParamsBuilder().
//		Allow_inet_aton_hex(origMixedIPv4.Allows_inet_aton_hex()).
//		Allow_inet_aton_octal(origMixedIPv4.Allows_inet_aton_octal()).
//		Allow_inet_aton_leading_zeros(origMixedIPv4.Allows_inet_aton_leading_zeros()).
//		Allow_inet_aton_joinedSegments(origMixedIPv4.Allows_inet_aton_joinedSegments()).
//		AllowBinary(origMixedIPv4.AllowsBinary()).
//		AllowUnlimitedLeadingZeros(origMixedIPv4.AllowsUnlimitedLeadingZeros()).
//		AllowWildcardedSeparator(origMixedIPv4.AllowsWildcardedSeparator()).
//		AllowLeadingZeros(origMixedIPv4.AllowsLeadingZeros()).
//		//
//		// embedded IPv4 ranges
//		GetRangeParamsBuilder().
//		AllowWildcard(origMixedIPv4Range.AllowsWildcard()).
//		AllowRangeSeparator(origMixedIPv4Range.AllowsRangeSeparator()).
//		AllowReverseRange(origMixedIPv4Range.AllowsReverseRange()).
//		AllowInferredBoundary(origMixedIPv4Range.AllowsInferredBoundary()).
//		AllowSingleWildcard(origMixedIPv4Range.AllowsSingleWildcard()).
//		GetIPv4ParentBuilder().
//		GetParentBuilder().
//		//
//		//IPv4 settings
//		GetIPv4AddressParamsBuilder().
//		Allow_inet_aton_hex(origIPv4.Allows_inet_aton_hex()).
//		Allow_inet_aton_octal(origIPv4.Allows_inet_aton_octal()).
//		Allow_inet_aton_leading_zeros(origIPv4.Allows_inet_aton_leading_zeros()).
//		Allow_inet_aton_joinedSegments(origIPv4.Allows_inet_aton_joinedSegments()).
//		Allow_inet_aton_single_segment_mask(origIPv4.Allows_inet_aton_single_segment_mask()).
//		AllowPrefixesBeyondAddressSize(origIPv4.AllowsPrefixesBeyondAddressSize()).
//		AllowPrefixLenLeadingZeros(origIPv4.AllowsPrefixLenLeadingZeros()).
//		AllowBinary(origIPv4.AllowsBinary()).
//		SetNetwork(origIPv4.GetNetwork()).
//		AllowUnlimitedLeadingZeros(origIPv4.AllowsUnlimitedLeadingZeros()).
//		AllowWildcardedSeparator(origIPv4.AllowsWildcardedSeparator()).
//		AllowLeadingZeros(origIPv4.AllowsLeadingZeros()).
//		//
//		//  IPv4 ranges
//		GetRangeParamsBuilder().
//		AllowWildcard(origIPv4Range.AllowsWildcard()).
//		AllowRangeSeparator(origIPv4Range.AllowsRangeSeparator()).
//		AllowReverseRange(origIPv4Range.AllowsReverseRange()).
//		AllowInferredBoundary(origIPv4Range.AllowsInferredBoundary()).
//		AllowSingleWildcard(origIPv4Range.AllowsSingleWildcard()).
//		GetIPv4ParentBuilder().
//		GetParentBuilder().
//		//
//		ToParams().(*ipAddressStringParameters)
//}

func CopyIPAddressStringParams(orig IPAddressStringParams) IPAddressStringParams {
	if p, ok := orig.(*ipAddressStringParameters); ok {
		return p
	}
	return new(IPAddressStringParamsBuilder).Set(orig).ToParams()
}

//func DefaultIPAddressParams() IPAddressStringParams {
//	xxx use builder instead xxx
//	return &ipAddressStringParameters{}
//}

// IPAddressStringParams can be used to control string parsing of IP address strings,
// indicating what to allow, what to disallow, and other options.
// You can use IPAddressStringParamsBuilder to construct an IPAddressStringParams.
type IPAddressStringParams interface {
	AddressStringParams

	// AllowsPrefixOnly indicates whether strings like /16 are interpreted as the corresponding network mask like 255.255.0.0
	// The mask version is determined by GetPreferredVersion() in the cases where it is ambiguous.
	//AllowsPrefixOnly() bool

	// AllowsPrefix indicates whether addresses with prefix length like 1.2.0.0/16 are allowed.
	AllowsPrefix() bool

	// EmptyStrParsedAs determines how an zero-length empty string is translated to an address.
	// If the option is ZeroAddressOption or LoopbackOption, then if defers to GetPreferredVersion() for the version.
	EmptyStrParsedAs() EmptyStrOption

	// EmptyStrParsedAs determines how the "all" string "*" is translated to addresses.
	// If the option is AllPreferredIPVersion, then if defers to GetPreferredVersion() for the version.
	AllStrParsedAs() AllStrOption

	AllowsMask() bool

	// GetPreferredVersion indicates the version to use for ambiguous addresses strings,
	// like prefix lengths less than 32 bits which are translated to masks,
	// the "all" address or the "empty" address.
	// The default is IPv6.
	//
	// If either of AllowsIPv4() or AllowsIPv6() returns false, then those settings take precedence over this setting.
	GetPreferredVersion() IPVersion

	AllowsIPv4() bool
	AllowsIPv6() bool
	GetIPv4Params() IPv4AddressStringParams
	GetIPv6Params() IPv6AddressStringParams
}

type EmptyStrOption string

const (
	NoAddressOption   EmptyStrOption = "none"
	ZeroAddressOption EmptyStrOption = "" // the default for Go is the zero address, which means zero strings are translated to zero addresses
	LoopbackOption    EmptyStrOption = "loopback"
)

type AllStrOption string

const (
	AllAddresses          AllStrOption = "" // the default for Go
	AllPreferredIPVersion AllStrOption = "preferred"
)

var _ IPAddressStringParams = &ipAddressStringParameters{}

type IPv4AddressStringParams interface {
	IPAddressStringFormatParams

	// Allows ipv4 inet_aton hexadecimal format 0xa.0xb.0xc.0cd
	Allows_inet_aton_hex() bool

	// Allows ipv4 inet_aton octal format, 04.05.06.07 being an example.
	// Can be overridden by allowLeadingZeros
	Allows_inet_aton_octal() bool

	// Allows ipv4 joined segments like 1.2.3, 1.2, or just 1
	//
	// For the case of just 1 segment, the behaviour is controlled by allowSingleSegment
	Allows_inet_aton_joinedSegments() bool

	// If you allow ipv4 joined segments, whether you allow a mask that looks like a prefix length: 1.2.3.5/255
	Allows_inet_aton_single_segment_mask() bool

	// Allows ipv4 inet_aton hexadecimal or octal to have leading zeros, such as in the first two segments of 0x0a.00b.c.d
	// The first 0 is not considered a leading zero, it either denotes octal or hex depending on whether it is followed by an 'x'.
	// ZerosCompression that appear afterwards are inet_aton leading zeros.
	Allows_inet_aton_leading_zeros() bool
}

var _ IPv4AddressStringParams = &ipv4AddressStringParameters{}

type IPv6AddressStringParams interface {
	IPAddressStringFormatParams

	// Allow mixed-in embedded IPv4 like a:b:c:d:e:f:1.2.3.4
	AllowsMixed() bool

	// Allow zones like a:b:c:d:e:f:a:b%zone
	AllowsZone() bool

	// Allow the zone character % with no following zone
	AllowsEmptyZone() bool

	// Allow IPv6 single-segment base 85 addresses
	AllowsBase85() bool

	// The parameters that will be used for embedded mixed addresses if AllowsMixed() is true
	GetMixedParams() IPAddressStringParams

	// The IPv4 part of the IPAddressStringParams returned by GetMixedParameters(), which is the part that matters most
	GetEmbeddedIPv4AddressParams() IPv4AddressStringParams
}

var _ IPv6AddressStringParams = &ipv6AddressStringParameters{}

type IPAddressStringFormatParams interface {
	AddressStringFormatParams

	// Allow prefix length values greater than 32 for IPv4 or greater than 128 for IPv6
	AllowsPrefixesBeyondAddressSize() bool

	// Allow leading zeros in the prefix length like 1.2.3.4/016
	AllowsPrefixLenLeadingZeros() bool

	// Allow binary addresses like 11111111.0.1.0 or 1111111111111111::
	AllowsBinary() bool
}

func init() {
	defaultEmbeddedBuilder.
		AllowEmpty(false).
		AllowPrefix(false).
		AllowMask(false).
		//AllowPrefixOnly(false).
		AllowAll(false).
		AllowIPv6(false).
		GetIPv6AddressParamsBuilder().
		AllowZone(true).
		AllowEmptyZone(true)
	defaultEmbeddedParams =
		defaultEmbeddedBuilder.
			ToParams().(*ipAddressStringParameters)
}

var defaultEmbeddedBuilder IPAddressStringParamsBuilder
var defaultEmbeddedParams *ipAddressStringParameters

// ipAddressStringParameters has parameters for parsing IP address strings
// They are immutable and can be constructed using an IPAddressStringParamsBuilder
type ipAddressStringParameters struct {
	addressStringParameters
	ipv4Params ipv4AddressStringParameters
	ipv6Params ipv6AddressStringParameters

	emptyStringOption EmptyStrOption
	allStringOption   AllStrOption
	preferredVersion  IPVersion

	//emptyIsNotLoopback,
	//noPrefixOnly,
	noPrefix, noMask, noIPv6, noIPv4 bool
}

//// Whether a string like "/16" is allowed as a stand-in for the associated network mask 255.255.0.0 or ffff::
//// The mask version is dependent on the preferred IP version
//func (params *ipAddressStringParameters) AllowsPrefixOnly() bool {
//	return !params.noPrefixOnly
//}

func (params *ipAddressStringParameters) AllowsPrefix() bool {
	return !params.noPrefix
}

func (params *ipAddressStringParameters) EmptyStrParsedAs() EmptyStrOption {
	return params.emptyStringOption
}

func (params *ipAddressStringParameters) AllStrParsedAs() AllStrOption {
	return params.allStringOption
}

func (params *ipAddressStringParameters) GetPreferredVersion() IPVersion {
	return params.preferredVersion
}

func (params *ipAddressStringParameters) AllowsMask() bool {
	return !params.noMask
}

func (params *ipAddressStringParameters) AllowsIPv4() bool {
	return !params.noIPv4
}

func (params *ipAddressStringParameters) AllowsIPv6() bool {
	return !params.noIPv6
}

func (params *ipAddressStringParameters) GetIPv4Params() IPv4AddressStringParams {
	return &params.ipv4Params
}

func (params *ipAddressStringParameters) GetIPv6Params() IPv6AddressStringParams {
	return &params.ipv6Params
}

// IPAddressStringParamsBuilder builds an IPAddressStringParameters
type IPAddressStringParamsBuilder struct {
	params ipAddressStringParameters
	AddressStringParamsBuilder
	ipv4Builder IPv4AddressStringParamsBuilder
	ipv6Builder IPv6AddressStringParamsBuilder

	parent *HostNameParamsBuilder
}

func (builder *IPAddressStringParamsBuilder) GetParentBuilder() *HostNameParamsBuilder {
	return builder.parent
}

func (builder *IPAddressStringParamsBuilder) ToParams() IPAddressStringParams {
	// We do not return a pointer to builder.params because that would make it possible to change a ipAddressStringParameters
	// by continuing to use the same builder,
	// and we want immutable objects for thread-safety,
	// so we cannot allow it
	result := builder.params
	result.addressStringParameters = *builder.AddressStringParamsBuilder.ToParams().(*addressStringParameters)
	result.ipv4Params = *builder.ipv4Builder.ToParams().(*ipv4AddressStringParameters)
	result.ipv6Params = *builder.ipv6Builder.ToParams().(*ipv6AddressStringParameters)
	return &result
}

func (builder *IPAddressStringParamsBuilder) GetIPv6AddressParamsBuilder() (result *IPv6AddressStringParamsBuilder) {
	result = &builder.ipv6Builder
	result.parent = builder
	return
}

func (builder *IPAddressStringParamsBuilder) GetIPv4AddressParamsBuilder() (result *IPv4AddressStringParamsBuilder) {
	result = &builder.ipv4Builder
	result.parent = builder
	return
}

//func (builder *IPAddressStringParamsBuilder) SetHostParams(params HostNameParams) *IPAddressStringParamsBuilder {
//	return ToIPAddressStringParamsBuilder(params.GetIPAddressParams())
//}

func (builder *IPAddressStringParamsBuilder) Set(params IPAddressStringParams) *IPAddressStringParamsBuilder {
	return builder.set(params, false)
}

func (builder *IPAddressStringParamsBuilder) set(params IPAddressStringParams, isMixed bool) *IPAddressStringParamsBuilder {
	//var result IPAddressStringParamsBuilder
	if p, ok := params.(*ipAddressStringParameters); ok {
		builder.params = *p
	} else {
		builder.params = ipAddressStringParameters{
			//noPrefixOnly:      !params.AllowsPrefixOnly(),
			preferredVersion:  params.GetPreferredVersion(),
			emptyStringOption: params.EmptyStrParsedAs(),
			allStringOption:   params.AllStrParsedAs(),
			noPrefix:          !params.AllowsPrefix(),
			noMask:            !params.AllowsMask(),
			noIPv6:            !params.AllowsIPv6(),
			noIPv4:            !params.AllowsIPv4(),
		}
	}
	builder.AddressStringParamsBuilder.set(params)
	builder.ipv4Builder.Set(params.GetIPv4Params())
	builder.ipv6Builder.set(params.GetIPv6Params(), isMixed)
	//builder.AddressStringParamsBuilder = *ToAddressStringParamsBuilder(params)
	//builder.ipv4Builder = *ToIPv4AddressStringParamsBuilder(params.GetIPv4Params())
	//builder.ipv6Builder = *toIPv6AddressStringParamsBuilder(params.GetIPv6Params(), isMixed)
	return builder
}

func (builder *IPAddressStringParamsBuilder) AllowEmpty(allow bool) *IPAddressStringParamsBuilder {
	builder.allowEmpty(allow)
	return builder
}

func (builder *IPAddressStringParamsBuilder) AllowSingleSegment(allow bool) *IPAddressStringParamsBuilder {
	builder.allowSingleSegment(allow)
	return builder
}

func (builder *IPAddressStringParamsBuilder) AllowAll(allow bool) *IPAddressStringParamsBuilder {
	builder.allowAll(allow)
	return builder
}

func (builder *IPAddressStringParamsBuilder) ParseEmptyStrAs(option EmptyStrOption) *IPAddressStringParamsBuilder {
	builder.params.emptyStringOption = option
	//if option != NoAddressOption {
	builder.AllowEmpty(true)
	//}
	return builder
}

func (builder *IPAddressStringParamsBuilder) ParseAllStrAs(option AllStrOption) *IPAddressStringParamsBuilder {
	builder.params.allStringOption = option
	return builder
}

func (builder *IPAddressStringParamsBuilder) SetPreferredVersion(version IPVersion) *IPAddressStringParamsBuilder {
	builder.params.preferredVersion = version
	return builder
}

func (builder *IPAddressStringParamsBuilder) AllowPrefix(allow bool) *IPAddressStringParamsBuilder {
	builder.params.noPrefix = !allow
	return builder
}

func (builder *IPAddressStringParamsBuilder) AllowMask(allow bool) *IPAddressStringParamsBuilder {
	builder.params.noMask = !allow
	return builder
}

//func (builder *IPAddressStringParamsBuilder) AllowPrefixOnly(allow bool) *IPAddressStringParamsBuilder {
//	builder.params.noPrefixOnly = !allow
//	return builder
//}

func (builder *IPAddressStringParamsBuilder) AllowIPv4(allow bool) *IPAddressStringParamsBuilder {
	builder.params.noIPv4 = !allow
	return builder
}

func (builder *IPAddressStringParamsBuilder) AllowIPv6(allow bool) *IPAddressStringParamsBuilder {
	builder.params.noIPv6 = !allow
	return builder
}

func (builder *IPAddressStringParamsBuilder) AllowWildcardedSeparator(allow bool) *IPAddressStringParamsBuilder {
	builder.GetIPv4AddressParamsBuilder().AllowWildcardedSeparator(allow)
	builder.GetIPv6AddressParamsBuilder().AllowWildcardedSeparator(allow)
	return builder
}

func (builder *IPAddressStringParamsBuilder) SetRangeParams(rangeParams RangeParams) *IPAddressStringParamsBuilder {
	builder.GetIPv4AddressParamsBuilder().SetRangeParams(rangeParams)
	builder.GetIPv6AddressParamsBuilder().SetRangeParams(rangeParams)
	return builder
}

func (builder *IPAddressStringParamsBuilder) Allow_inet_aton(allow bool) *IPAddressStringParamsBuilder {
	builder.GetIPv4AddressParamsBuilder().Allow_inet_aton(allow)
	builder.GetIPv6AddressParamsBuilder().Allow_mixed_inet_aton(allow)
	return builder
}

type ipAddressStringFormatParameters struct {
	addressStringFormatParameters

	allowPrefixesBeyondAddrSize,
	noPrefixLengthLeadingZeros,
	noBinary bool
}

func (params *ipAddressStringFormatParameters) AllowsPrefixesBeyondAddressSize() bool {
	return params.allowPrefixesBeyondAddrSize
}

func (params *ipAddressStringFormatParameters) AllowsPrefixLenLeadingZeros() bool {
	return !params.noPrefixLengthLeadingZeros
}

func (params *ipAddressStringFormatParameters) AllowsBinary() bool {
	return !params.noBinary
}

type IPAddressStringFormatParamsBuilder struct {
	AddressStringFormatParamsBuilder

	ipParams ipAddressStringFormatParameters

	parent *IPAddressStringParamsBuilder
}

func (builder *IPAddressStringFormatParamsBuilder) GetParentBuilder() *IPAddressStringParamsBuilder {
	return builder.parent
}

func (builder *IPAddressStringFormatParamsBuilder) ToParams() IPAddressStringFormatParams {
	result := &builder.ipParams
	result.addressStringFormatParameters = *builder.AddressStringFormatParamsBuilder.ToParams().(*addressStringFormatParameters)
	return result
}

func (builder *IPAddressStringFormatParamsBuilder) set(params IPAddressStringFormatParams) {
	//xxx
	//var result IPAddressStringFormatParamsBuilder
	if p, ok := params.(*ipAddressStringFormatParameters); ok {
		builder.ipParams = *p
	} else {
		builder.ipParams = ipAddressStringFormatParameters{
			allowPrefixesBeyondAddrSize: params.AllowsPrefixesBeyondAddressSize(),
			noPrefixLengthLeadingZeros:  !params.AllowsPrefixLenLeadingZeros(),
			noBinary:                    !params.AllowsBinary(),
		}
	}
	builder.AddressStringFormatParamsBuilder.set(params)
	//builder.AddressStringFormatParamsBuilder = *ToAddressStringFormatParamsBuilder(params)
	//return &result
}

func (builder *IPAddressStringFormatParamsBuilder) AllowsPrefixesBeyondAddressSize() bool {
	return builder.ipParams.AllowsPrefixesBeyondAddressSize()
}

func (builder *IPAddressStringFormatParamsBuilder) AllowsPrefixLenLeadingZeros() bool {
	return builder.ipParams.AllowsPrefixLenLeadingZeros()
}

func (builder *IPAddressStringFormatParamsBuilder) AllowsBinary() bool {
	return builder.ipParams.AllowsBinary()
}

func (builder *IPAddressStringFormatParamsBuilder) allowBinary(allow bool) {
	builder.ipParams.noBinary = !allow
}

func (builder *IPAddressStringFormatParamsBuilder) allowPrefixesBeyondAddressSize(allow bool) {
	builder.ipParams.allowPrefixesBeyondAddrSize = allow
}

func (builder *IPAddressStringFormatParamsBuilder) allowPrefixLengthLeadingZeros(allow bool) {
	builder.ipParams.noPrefixLengthLeadingZeros = !allow
}

type ipv6AddressStringParameters struct {
	ipAddressStringFormatParameters

	noMixed, noZone, noBase85, noEmptyZone bool

	embeddedParams *ipAddressStringParameters
}

func (params *ipv6AddressStringParameters) AllowsMixed() bool {
	return !params.noMixed
}

func (params *ipv6AddressStringParameters) AllowsZone() bool {
	return !params.noZone
}

func (params *ipv6AddressStringParameters) AllowsEmptyZone() bool {
	return !params.noEmptyZone
}

func (params *ipv6AddressStringParameters) AllowsBase85() bool {
	return !params.noBase85
}

func (params *ipv6AddressStringParameters) GetMixedParams() IPAddressStringParams {
	var result *ipAddressStringParameters = params.embeddedParams
	if result == nil {
		result = defaultEmbeddedParams
	}
	return result
}

func (params *ipv6AddressStringParameters) GetEmbeddedIPv4AddressParams() IPv4AddressStringParams {
	return params.embeddedParams.GetIPv4Params()
}

type IPv6AddressStringParamsBuilder struct {
	// This is not anonymous since it clashes with IPAddressStringFormatParamsBuilder,
	// both have ipAddressStringFormatParameters and AddressStringFormatParams
	// and thee builder IPAddressStringFormatParamsBuilder takes precedence
	params ipv6AddressStringParameters

	embeddedBuilder *IPAddressStringParamsBuilder

	IPAddressStringFormatParamsBuilder
}

func (builder *IPv6AddressStringParamsBuilder) ToParams() IPv6AddressStringParams {
	result := &builder.params
	result.ipAddressStringFormatParameters = *builder.IPAddressStringFormatParamsBuilder.ToParams().(*ipAddressStringFormatParameters)
	if emb := builder.embeddedBuilder; emb == nil {
		result.embeddedParams = defaultEmbeddedParams
	} else {
		result.embeddedParams = emb.ToParams().(*ipAddressStringParameters)
	}
	return result
}

func (builder *IPv6AddressStringParamsBuilder) GetRangeParamsBuilder() *RangeParamsBuilder {
	result := &builder.rangeParamsBuilder
	result.parent = builder
	return result
}

func (builder *IPv6AddressStringParamsBuilder) AllowsMixed() bool {
	return builder.params.AllowsMixed()
}

func (builder *IPv6AddressStringParamsBuilder) AllowsZone() bool {
	return builder.params.AllowsZone()
}

func (builder *IPv6AddressStringParamsBuilder) AllowsEmptyZone() bool {
	return builder.params.AllowsEmptyZone()
}

func (builder *IPv6AddressStringParamsBuilder) AllowsBase85() bool {
	return builder.params.AllowsBase85()
}

func (builder *IPv6AddressStringParamsBuilder) AllowBase85(allow bool) *IPv6AddressStringParamsBuilder {
	builder.params.noBase85 = !allow
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) Set(params IPv6AddressStringParams) *IPv6AddressStringParamsBuilder {
	return builder.set(params, false)
}

func (builder *IPv6AddressStringParamsBuilder) set(params IPv6AddressStringParams, isMixed bool) *IPv6AddressStringParamsBuilder {
	//var result IPv6AddressStringParamsBuilder
	if p, ok := params.(*ipv6AddressStringParameters); ok {
		builder.params = *p
	} else {
		builder.params = ipv6AddressStringParameters{
			noMixed:     !params.AllowsMixed(),
			noZone:      !params.AllowsZone(),
			noEmptyZone: !params.AllowsEmptyZone(),
			noBase85:    !params.AllowsBase85(),
			//network:  params.GetNetwork(),
		}
	}
	//builder.IPAddressStringFormatParamsBuilder = *ToIPAddressStringFormatParamsBuilder(params)
	//if !isMixed {
	//	builder.getEmbeddedIPv4ParametersBuilder().ipv4Builder = *ToIPv4AddressStringParamsBuilder(params.GetEmbeddedIPv4AddressParams())
	//}
	builder.IPAddressStringFormatParamsBuilder.set(params)
	if !isMixed {
		builder.getEmbeddedIPv4ParametersBuilder().ipv4Builder.Set(params.GetEmbeddedIPv4AddressParams())
	}
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowZone(allow bool) *IPv6AddressStringParamsBuilder {
	builder.params.noZone = !allow

	//we must decide whether to treat the % character as a zone when parsing the mixed part
	//if considered zone, then the zone character is actually part of the encompassing ipv6 address
	//otherwise, the zone character is an sql wildcard that is part of the mixed address
	//So whether we consider the % character a zone must match the same setting for the encompassing address

	// ipv4Builder can be nil when builder == &defaultEmbeddedBuilder.ipv6Builder, see getEmbeddedIPv4ParametersBuilder()
	if ipv4Builder := builder.getEmbeddedIPv4ParametersBuilder(); ipv4Builder != nil {
		ipv4Builder.GetIPv6AddressParamsBuilder().params.noZone = !allow
	}
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowEmptyZone(allow bool) *IPv6AddressStringParamsBuilder {
	builder.params.noEmptyZone = !allow

	// ipv4Builder can be nil when builder == &defaultEmbeddedBuilder.ipv6Builder, see getEmbeddedIPv4ParametersBuilder()
	if ipv4Builder := builder.getEmbeddedIPv4ParametersBuilder(); ipv4Builder != nil {
		ipv4Builder.GetIPv6AddressParamsBuilder().params.noEmptyZone = !allow
	}
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowMixed(allow bool) *IPv6AddressStringParamsBuilder {
	builder.params.noMixed = !allow
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) getEmbeddedIPv4ParametersBuilder() (result *IPAddressStringParamsBuilder) {
	if builder == &defaultEmbeddedBuilder.ipv6Builder {
		return nil
	}
	if result = builder.embeddedBuilder; result == nil {
		result = &IPAddressStringParamsBuilder{}
		// copy in proper default values for embedded IPv4 addresses, which differ from defaults for typical ipv4AddrType addresses
		*result = defaultEmbeddedBuilder
		builder.embeddedBuilder = result
	}
	result.GetIPv4AddressParamsBuilder().mixedParent = builder
	return
}

func (builder *IPv6AddressStringParamsBuilder) GetEmbeddedIPv4AddressParamsBuilder() (result *IPv4AddressStringParamsBuilder) {
	return builder.getEmbeddedIPv4ParametersBuilder().GetIPv4AddressParamsBuilder()
}

func (builder *IPv6AddressStringParamsBuilder) Allow_mixed_inet_aton(allow bool) *IPv6AddressStringParamsBuilder {
	builder.getEmbeddedIPv4ParametersBuilder().GetIPv4AddressParamsBuilder().Allow_inet_aton(allow)
	if allow { // if we allow inet_aton in the mixed part, then of course that insinuates that we allow the mixed part
		builder.AllowMixed(allow)
	}
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowBinary(allow bool) *IPv6AddressStringParamsBuilder {
	builder.GetEmbeddedIPv4AddressParamsBuilder().AllowBinary(allow)
	builder.allowBinary(allow)
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowWildcardedSeparator(allow bool) *IPv6AddressStringParamsBuilder {
	builder.GetEmbeddedIPv4AddressParamsBuilder().AllowWildcardedSeparator(allow)
	builder.allowWildcardedSeparator(allow)
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowLeadingZeros(allow bool) *IPv6AddressStringParamsBuilder {
	builder.GetEmbeddedIPv4AddressParamsBuilder().allowLeadingZeros(allow)
	builder.allowLeadingZeros(allow)
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowUnlimitedLeadingZeros(allow bool) *IPv6AddressStringParamsBuilder {
	builder.GetEmbeddedIPv4AddressParamsBuilder().AllowUnlimitedLeadingZeros(allow)
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) SetRangeParams(rangeParams RangeParams) *IPv6AddressStringParamsBuilder {
	builder.GetEmbeddedIPv4AddressParamsBuilder().SetRangeParams(rangeParams)
	builder.setRangeParameters(rangeParams)
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowPrefixesBeyondAddressSize(allow bool) *IPv6AddressStringParamsBuilder {
	builder.allowPrefixesBeyondAddressSize(allow)
	return builder
}

func (builder *IPv6AddressStringParamsBuilder) AllowPrefixLenLeadingZeros(allow bool) *IPv6AddressStringParamsBuilder {
	builder.allowPrefixLengthLeadingZeros(allow)
	return builder
}

type ipv4AddressStringParameters struct {
	ipAddressStringFormatParameters

	no_inet_aton_hex,
	no_inet_aton_octal,
	no_inet_aton_joinedSegments,
	inet_aton_single_segment_mask,
	no_inet_aton_leading_zeros bool
}

func (params *ipv4AddressStringParameters) Allows_inet_aton_hex() bool {
	return !params.no_inet_aton_hex
}

func (params *ipv4AddressStringParameters) Allows_inet_aton_octal() bool {
	return !params.no_inet_aton_octal
}

func (params *ipv4AddressStringParameters) Allows_inet_aton_joinedSegments() bool {
	return !params.no_inet_aton_joinedSegments
}

func (params *ipv4AddressStringParameters) Allows_inet_aton_single_segment_mask() bool {
	return params.inet_aton_single_segment_mask
}

func (params *ipv4AddressStringParameters) Allows_inet_aton_leading_zeros() bool {
	return !params.no_inet_aton_leading_zeros
}

type IPv4AddressStringParamsBuilder struct {
	// This is not anonymous since it clashes with IPAddressStringFormatParamsBuilder,
	// both have ipAddressStringFormatParameters and AddressStringFormatParams
	// IPAddressStringFormatParamsBuilder takes precedence
	params ipv4AddressStringParameters

	IPAddressStringFormatParamsBuilder

	mixedParent *IPv6AddressStringParamsBuilder
}

func (builder *IPv4AddressStringParamsBuilder) ToParams() IPv4AddressStringParams {
	result := &builder.params
	result.ipAddressStringFormatParameters = *builder.IPAddressStringFormatParamsBuilder.ToParams().(*ipAddressStringFormatParameters)
	return result
}

// If this builder was obtained by a call to getEmbeddedIPv4ParamsBuilder() from IPv6AddressStringParamsBuilder,
// returns that IPv6AddressStringParamsBuilder
func (params *IPv4AddressStringParamsBuilder) GetEmbeddedIPv4AddressParentBuilder() *IPv6AddressStringParamsBuilder {
	return params.mixedParent
}

func (params *IPv4AddressStringParamsBuilder) GetRangeParamsBuilder() *RangeParamsBuilder {
	result := &params.rangeParamsBuilder
	result.parent = params
	return result
}

func (builder *IPv4AddressStringParamsBuilder) Set(params IPv4AddressStringParams) *IPv4AddressStringParamsBuilder {
	//xxx
	//var result IPv4AddressStringParamsBuilder
	if p, ok := params.(*ipv4AddressStringParameters); ok {
		builder.params = *p
	} else {
		builder.params = ipv4AddressStringParameters{
			no_inet_aton_hex:              !params.Allows_inet_aton_hex(),
			no_inet_aton_octal:            !params.Allows_inet_aton_octal(),
			no_inet_aton_joinedSegments:   !params.Allows_inet_aton_joinedSegments(),
			inet_aton_single_segment_mask: params.Allows_inet_aton_single_segment_mask(),
			no_inet_aton_leading_zeros:    !params.Allows_inet_aton_leading_zeros(),
			//network:                       params.GetNetwork(),
		}
	}
	builder.IPAddressStringFormatParamsBuilder.set(params)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) Allow_inet_aton(allow bool) *IPv4AddressStringParamsBuilder {
	builder.params.no_inet_aton_joinedSegments = !allow
	builder.params.no_inet_aton_octal = !allow
	builder.params.no_inet_aton_hex = !allow
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) Allow_inet_aton_hex(allow bool) *IPv4AddressStringParamsBuilder {
	builder.params.no_inet_aton_hex = !allow
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) Allow_inet_aton_octal(allow bool) *IPv4AddressStringParamsBuilder {
	builder.params.no_inet_aton_octal = !allow
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) Allow_inet_aton_leading_zeros(allow bool) *IPv4AddressStringParamsBuilder {
	builder.params.no_inet_aton_leading_zeros = !allow
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) Allow_inet_aton_joinedSegments(allow bool) *IPv4AddressStringParamsBuilder {
	builder.params.no_inet_aton_joinedSegments = !allow
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) Allow_inet_aton_single_segment_mask(allow bool) *IPv4AddressStringParamsBuilder {
	builder.params.inet_aton_single_segment_mask = allow
	return builder
}
func (builder *IPv4AddressStringParamsBuilder) AllowWildcardedSeparator(allow bool) *IPv4AddressStringParamsBuilder {
	builder.allowWildcardedSeparator(allow)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) AllowLeadingZeros(allow bool) *IPv4AddressStringParamsBuilder {
	builder.allowLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) AllowUnlimitedLeadingZeros(allow bool) *IPv4AddressStringParamsBuilder {
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) SetRangeParams(rangeParams RangeParams) *IPv4AddressStringParamsBuilder {
	builder.setRangeParameters(rangeParams)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) AllowPrefixesBeyondAddressSize(allow bool) *IPv4AddressStringParamsBuilder {
	builder.allowPrefixesBeyondAddressSize(allow)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) AllowPrefixLenLeadingZeros(allow bool) *IPv4AddressStringParamsBuilder {
	builder.allowPrefixLengthLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParamsBuilder) AllowBinary(allow bool) *IPv4AddressStringParamsBuilder {
	builder.allowBinary(allow)
	return builder
}

type IPVersion string

const (
	IndeterminateIPVersion IPVersion = ""
	IPv4                   IPVersion = "IPv4"
	IPv6                   IPVersion = "IPv6"
)

func (version IPVersion) IsIPv6() bool {
	return strings.EqualFold(string(version), string(IPv6))
}

func (version IPVersion) IsIPv4() bool {
	return strings.EqualFold(string(version), string(IPv4))
}

func (version IPVersion) IsIndeterminate() bool {
	if len(version) == 4 {
		// we allow mixed case in the event code is converted a string to IPVersion
		dig := version[3]
		return (dig != '4' && dig != '6') || !strings.EqualFold(string(version[:3]), "IPv")
	}
	return true
}

//// returns an index starting from 0 with IndeterminateIPVersion being the highest
//func (version IPVersion) index() int {
//	if version.IsIPv4() {
//		return 0
//	} else if version.IsIPv6() {
//		return 1
//	}
//	return 2
//}
//
//func (version IPVersion) Equal(other IPVersion) bool {
//	return strings.EqualFold(string(version), string(other)) || (version.IsIndeterminate() && other.IsIndeterminate())
//}

func (version IPVersion) String() string {
	return string(version)
}

//func (version IPVersion) getNetwork() (network IPAddressNetwork) {
//	if version.IsIPv6() {
//		network = IPv6Network
//	} else if version.IsIPv4() {
//		network = IPv4Network
//	}
//	return
//}
//
//func (version IPVersion) toType() (t addrType) {
//	if version.IsIPv6() {
//		t = ipv6Type
//	} else if version.IsIPv4() {
//		t = ipv4Type
//	}
//	return
//}

//func (version IPVersion) GetMaxSegmentValue() SegInt {
//	if version.IsIPv4() {
//		return IPv4MaxValuePerSegment
//	} else if version.IsIPv6() {
//		return IPv6MaxValuePerSegment
//	}
//	return 0
//}
//
//func (version IPVersion) GetBytesPerSegment() int {
//	if version.IsIPv4() {
//		return IPv4BytesPerSegment
//	} else if version.IsIPv6() {
//		return IPv6BytesPerSegment
//	}
//	return 0
//}
//
//func (version IPVersion) GetBitsPerSegment() BitCount {
//	if version.IsIPv4() {
//		return IPv4BitsPerSegment
//	} else if version.IsIPv6() {
//		return IPv6BitsPerSegment
//	}
//	return 0
//}
//
//func (version IPVersion) GetByteCount() int {
//	if version.IsIPv4() {
//		return IPv4ByteCount
//	} else if version.IsIPv6() {
//		return IPv6ByteCount
//	}
//	return 0
//}
//
//func (version IPVersion) GetSegmentCount() int {
//	if version.IsIPv4() {
//		return IPv4SegmentCount
//	} else if version.IsIPv6() {
//		return IPv6SegmentCount
//	}
//	return 0
//}
//
//func (version IPVersion) GetBitCount() BitCount {
//	if version.IsIPv4() {
//		return IPv4BitCount
//	} else if version.IsIPv6() {
//		return IPv6BitCount
//	}
//	return 0
//}
