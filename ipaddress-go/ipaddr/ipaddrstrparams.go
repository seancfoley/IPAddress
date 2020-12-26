package ipaddr

func convertIPAddrParams(orig IPAddressStringParameters) *ipAddressStringParameters { //note this is a duplicate of getPrivateParams which calls ToIPAddressStringParamsBuilder(orig).ToParams()
	if params, ok := orig.(*ipAddressStringParameters); ok {
		return params
	}
	origIPv4 := orig.GetIPv4Parameters()
	origIPv4Range := origIPv4.GetRangeParameters()
	origIPv6 := orig.GetIPv6Parameters()
	origIPv6Range := origIPv6.GetRangeParameters()
	origMixedIPv4 := origIPv6.GetEmbeddedIPv4AddressParams()
	origMixedIPv4Range := origMixedIPv4.GetRangeParameters()
	paramsBuilder := IPAddressStringParametersBuilder{}
	return paramsBuilder.
		// general settings
		AllowIPv6(orig.AllowsIPv6()).
		AllowIPv4(orig.AllowsIPv4()).
		SetEmptyLoopback(orig.EmptyIsLoopback()).
		AllowMask(orig.AllowsMask()).
		AllowPrefixOnly(orig.AllowsPrefixOnly()).
		AllowPrefix(orig.AllowsPrefix()).
		AllowEmpty(orig.AllowsEmpty()).
		AllowSingleSegment(orig.AllowsSingleSegment()).
		AllowAll(orig.AllowsAll()).
		//
		// IPv6 settings
		GetIPv6AddressParametersBuilder().
		AllowZone(origIPv6.AllowsZone()).
		AllowMixed(origIPv6.AllowsMixed()).
		AllowBase85(origIPv6.AllowsBase85()).
		AllowBinary(origIPv6.AllowsBinary()).
		AllowWildcardedSeparator(origIPv6.AllowsWildcardedSeparator()).
		AllowLeadingZeros(origIPv6.AllowsLeadingZeros()).
		AllowUnlimitedLeadingZeros(origIPv6.AllowsUnlimitedLeadingZeros()).
		AllowPrefixesBeyondAddressSize(origIPv6.AllowsPrefixesBeyondAddressSize()).
		AllowPrefixLengthLeadingZeros(origIPv6.AllowsPrefixLengthLeadingZeros()).
		//
		// IPv6 ranges
		GetRangeParametersBuilder().
		AllowWildcard(origIPv6Range.AllowsWildcard()).
		AllowRangeSeparator(origIPv6Range.AllowsRangeSeparator()).
		AllowReverseRange(origIPv6Range.AllowsReverseRange()).
		AllowInferredBoundary(origIPv6Range.AllowsInferredBoundary()).
		AllowSingleWildcard(origIPv6Range.AllowsSingleWildcard()).
		GetIPv6ParentBuilder().
		//
		// mixed-in embedded IPV4 settings (the 1.2.3.4 in a:b:c:d:e:f:1.2.3.4)
		GetEmbeddedIPv4AddressParametersBuilder().
		Allow_inet_aton_hex(origMixedIPv4.Allows_inet_aton_hex()).
		Allow_inet_aton_octal(origMixedIPv4.Allows_inet_aton_octal()).
		Allow_inet_aton_leading_zeros(origMixedIPv4.Allows_inet_aton_leading_zeros()).
		Allow_inet_aton_joinedSegments(origMixedIPv4.Allows_inet_aton_joinedSegments()).
		AllowBinary(origMixedIPv4.AllowsBinary()).
		AllowUnlimitedLeadingZeros(origMixedIPv4.AllowsUnlimitedLeadingZeros()).
		AllowWildcardedSeparator(origMixedIPv4.AllowsWildcardedSeparator()).
		AllowLeadingZeros(origMixedIPv4.AllowsLeadingZeros()).
		//
		// embedded IPv4 ranges
		GetRangeParametersBuilder().
		AllowWildcard(origMixedIPv4Range.AllowsWildcard()).
		AllowRangeSeparator(origMixedIPv4Range.AllowsRangeSeparator()).
		AllowReverseRange(origMixedIPv4Range.AllowsReverseRange()).
		AllowInferredBoundary(origMixedIPv4Range.AllowsInferredBoundary()).
		AllowSingleWildcard(origMixedIPv4Range.AllowsSingleWildcard()).
		GetIPv4ParentBuilder().
		GetParentBuilder().
		//
		//IPv4 settings
		GetIPv4AddressParametersBuilder().
		Allow_inet_aton_hex(origIPv4.Allows_inet_aton_hex()).
		Allow_inet_aton_octal(origIPv4.Allows_inet_aton_octal()).
		Allow_inet_aton_leading_zeros(origIPv4.Allows_inet_aton_leading_zeros()).
		Allow_inet_aton_joinedSegments(origIPv4.Allows_inet_aton_joinedSegments()).
		Allow_inet_aton_single_segment_mask(origIPv4.Allows_inet_aton_single_segment_mask()).
		AllowPrefixesBeyondAddressSize(origIPv4.AllowsPrefixesBeyondAddressSize()).
		AllowPrefixLengthLeadingZeros(origIPv4.AllowsPrefixLengthLeadingZeros()).
		AllowBinary(origIPv4.AllowsBinary()).
		SetNetwork(origIPv4.GetNetwork()).
		AllowUnlimitedLeadingZeros(origIPv4.AllowsUnlimitedLeadingZeros()).
		AllowWildcardedSeparator(origIPv4.AllowsWildcardedSeparator()).
		AllowLeadingZeros(origIPv4.AllowsLeadingZeros()).
		//
		//  IPv4 ranges
		GetRangeParametersBuilder().
		AllowWildcard(origIPv4Range.AllowsWildcard()).
		AllowRangeSeparator(origIPv4Range.AllowsRangeSeparator()).
		AllowReverseRange(origIPv4Range.AllowsReverseRange()).
		AllowInferredBoundary(origIPv4Range.AllowsInferredBoundary()).
		AllowSingleWildcard(origIPv4Range.AllowsSingleWildcard()).
		GetIPv4ParentBuilder().
		GetParentBuilder().
		//
		ToParams().(*ipAddressStringParameters)
}

type IPAddressStringParameters interface {
	AddressStringParameters
	AllowsPrefixOnly() bool
	AllowsPrefix() bool
	EmptyIsLoopback() bool
	AllowsMask() bool
	AllowsIPv4() bool
	AllowsIPv6() bool
	GetIPv4Parameters() IPv4AddressStringParameters
	GetIPv6Parameters() IPv6AddressStringParameters
}

var _ IPAddressStringParameters = &ipAddressStringParameters{}

type IPv4AddressStringParameters interface {
	IPAddressStringFormatParameters

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
	// Zeros that appear afterwards are inet_aton leading zeros.
	Allows_inet_aton_leading_zeros() bool

	// The network that will be used to construct addresses - both parameters inside the network, and the network's address creator
	GetNetwork() *IPv4AddressNetwork // TODO you'd want to avoid exposing the default IPv6AddressNetwork, you might want to copy, or use an interface, or something.  But only applies with anonymous fields of public types.
}

var _ IPv4AddressStringParameters = &ipv4AddressStringParameters{}

type IPv6AddressStringParameters interface {
	IPAddressStringFormatParameters

	// Allow mixed-in embedded IPv4 like a:b:c:d:e:f:1.2.3.4
	AllowsMixed() bool

	// Allow zones like a:b:c:d:e:f:a:b%zone
	AllowsZone() bool

	// Allow IPv6 single-segment base 85 addresses
	AllowsBase85() bool

	// The parameters that will be used for embedded mixed addresses if AllowsMixed() is true
	GetMixedParameters() IPAddressStringParameters

	// The IPv4 part of the IPAddressStringParameters returned by GetMixedParameters(), which is the part that matters most
	GetEmbeddedIPv4AddressParams() IPv4AddressStringParameters

	// The network that will be used to construct addresses - both parameters inside the network, and the network's address creator
	GetNetwork() *IPv6AddressNetwork // TODO you'd want to avoid exposing the default IPv6AddressNetwork, you might want to copy, or use an interface, or something
}

var _ IPv6AddressStringParameters = &ipv6AddressStringParameters{}

type IPAddressStringFormatParameters interface {
	AddressStringFormatParameters

	// Allow prefix length values greater than 32 for IPv4 or greater than 128 for IPv6
	AllowsPrefixesBeyondAddressSize() bool

	// Allow leading zeros in the prefix length like 1.2.3.4/016
	AllowsPrefixLengthLeadingZeros() bool

	// Allow binary addresses like 11111111.0.1.0 or 1111111111111111::
	AllowsBinary() bool
}

func init() {
	defaultEmbeddedBuilder.
		AllowEmpty(false).
		AllowPrefix(false).
		AllowMask(false).
		AllowPrefixOnly(false).
		AllowAll(false).
		AllowIPv6(false).
		GetIPv6AddressParametersBuilder().
		AllowZone(true)
	defaultEmbeddedParams =
		defaultEmbeddedBuilder.
			ToParams().(*ipAddressStringParameters)
}

var defaultEmbeddedBuilder IPAddressStringParametersBuilder
var defaultEmbeddedParams *ipAddressStringParameters

// ipAddressStringParameters has parameters for parsing IP address strings
// They are immutable and can be constructed using an IPAddressStringParametersBuilder
type ipAddressStringParameters struct {
	addressStringParameters
	ipv4Params ipv4AddressStringParameters
	ipv6Params ipv6AddressStringParameters

	noPrefixOnly, emptyIsNotLoopback, noPrefix, noMask, noIPv6, noIPv4 bool
}

func (params *ipAddressStringParameters) AllowsPrefixOnly() bool {
	return !params.noPrefixOnly
}

func (params *ipAddressStringParameters) AllowsPrefix() bool {
	return !params.noPrefix
}

func (params *ipAddressStringParameters) EmptyIsLoopback() bool {
	return !params.emptyIsNotLoopback
}

func (params *ipAddressStringParameters) AllowsMask() bool {
	return !params.noMask
}

func (params *ipAddressStringParameters) AllowsIPv4() bool {
	return !params.noIPv6
}

func (params *ipAddressStringParameters) AllowsIPv6() bool {
	return !params.noIPv4
}

func (params *ipAddressStringParameters) inferVersion() IPVersion {
	if params.AllowsIPv6() {
		if !params.AllowsIPv4() {
			return IPv6
		}
	} else if params.AllowsIPv4() {
		return IPv4
	}
	return INDETERMINATE_VERSION
}

func (params *ipAddressStringParameters) GetIPv4Parameters() IPv4AddressStringParameters {
	return &params.ipv4Params
}

func (params *ipAddressStringParameters) GetIPv6Parameters() IPv6AddressStringParameters {
	return &params.ipv6Params
}

// IPAddressStringParametersBuilder builds an ipAddressStringParameters
type IPAddressStringParametersBuilder struct {
	params ipAddressStringParameters
	AddressStringParametersBuilder
	ipv4Builder IPv4AddressStringParametersBuilder
	ipv6Builder IPv6AddressStringParametersBuilder

	parent *HostNameParametersBuilder
}

func ToIPAddressStringParamsBuilder(params IPAddressStringParameters) *IPAddressStringParametersBuilder {
	return toIPAddressStringParamsBuilder(params, false)
}

func toIPAddressStringParamsBuilder(params IPAddressStringParameters, isMixed bool) *IPAddressStringParametersBuilder {
	var result IPAddressStringParametersBuilder
	if p, ok := params.(*ipAddressStringParameters); ok {
		result.params = *p
	} else {
		result.params = ipAddressStringParameters{
			noPrefixOnly:       !params.AllowsPrefixOnly(),
			emptyIsNotLoopback: !params.EmptyIsLoopback(),
			noPrefix:           !params.AllowsPrefix(),
			noMask:             !params.AllowsMask(),
			noIPv6:             !params.AllowsIPv6(),
			noIPv4:             !params.AllowsIPv4(),
		}
	}
	result.AddressStringParametersBuilder = *ToAddressStringParamsBuilder(params)
	result.ipv4Builder = *ToIPv4AddressStringParamsBuilder(params.GetIPv4Parameters())
	result.ipv6Builder = *toIPv6AddressStringParamsBuilder(params.GetIPv6Parameters(), isMixed)
	return &result
}

func (builder *IPAddressStringParametersBuilder) ToParams() IPAddressStringParameters {
	// We do not return a pointer to builder.params because that would make it possible to change a ipAddressStringParameters
	// by continuing to use the same builder,
	// and we want immutable objects for thread-safety,
	// so we cannot allow it
	result := builder.params
	result.addressStringParameters = *builder.AddressStringParametersBuilder.ToParams().(*addressStringParameters)
	result.ipv4Params = *builder.ipv4Builder.ToParams().(*ipv4AddressStringParameters)
	result.ipv6Params = *builder.ipv6Builder.ToParams().(*ipv6AddressStringParameters)
	return &result
}

func (builder *IPAddressStringParametersBuilder) GetIPv6AddressParametersBuilder() (result *IPv6AddressStringParametersBuilder) {
	result = &builder.ipv6Builder
	result.parent = builder
	return
}

func (builder *IPAddressStringParametersBuilder) GetIPv4AddressParametersBuilder() (result *IPv4AddressStringParametersBuilder) {
	result = &builder.ipv4Builder
	result.parent = builder
	return
}

func (builder *IPAddressStringParametersBuilder) AllowEmpty(allow bool) *IPAddressStringParametersBuilder {
	builder.allowEmpty(allow)
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowSingleSegment(allow bool) *IPAddressStringParametersBuilder {
	builder.allowSingleSegment(allow)
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowAll(allow bool) *IPAddressStringParametersBuilder {
	builder.allowAll(allow)
	return builder
}

func (builder *IPAddressStringParametersBuilder) SetEmptyLoopback(allow bool) *IPAddressStringParametersBuilder {
	builder.params.emptyIsNotLoopback = !allow
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowPrefix(allow bool) *IPAddressStringParametersBuilder {
	builder.params.noPrefix = !allow
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowMask(allow bool) *IPAddressStringParametersBuilder {
	builder.params.noMask = !allow
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowPrefixOnly(allow bool) *IPAddressStringParametersBuilder {
	builder.params.noPrefixOnly = !allow
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowIPv4(allow bool) *IPAddressStringParametersBuilder {
	builder.params.noIPv4 = !allow
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowIPv6(allow bool) *IPAddressStringParametersBuilder {
	builder.params.noIPv6 = !allow
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowWildcardedSeparator(allow bool) *IPAddressStringParametersBuilder {
	builder.GetIPv4AddressParametersBuilder().AllowWildcardedSeparator(allow)
	builder.GetIPv6AddressParametersBuilder().AllowWildcardedSeparator(allow)
	return builder
}

func (builder *IPAddressStringParametersBuilder) SetRangeParameters(rangeParams RangeParameters) *IPAddressStringParametersBuilder {
	builder.GetIPv4AddressParametersBuilder().SetRangeParameters(rangeParams)
	builder.GetIPv6AddressParametersBuilder().SetRangeParameters(rangeParams)
	return builder
}

func (builder *IPAddressStringParametersBuilder) Allow_inet_aton(allow bool) *IPAddressStringParametersBuilder {
	builder.GetIPv4AddressParametersBuilder().Allow_inet_aton(allow)
	builder.GetIPv6AddressParametersBuilder().Allow_mixed_inet_aton(allow)
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

func (params *ipAddressStringFormatParameters) AllowsPrefixLengthLeadingZeros() bool {
	return !params.noPrefixLengthLeadingZeros
}

func (params *ipAddressStringFormatParameters) AllowsBinary() bool {
	return !params.noBinary
}

type IPAddressStringFormatParametersBuilder struct {
	AddressStringFormatParamsBuilder

	ipParams ipAddressStringFormatParameters

	parent *IPAddressStringParametersBuilder
}

func ToIPAddressStringFormatParamsBuilder(params IPAddressStringFormatParameters) *IPAddressStringFormatParametersBuilder {
	var result IPAddressStringFormatParametersBuilder
	if p, ok := params.(*ipAddressStringFormatParameters); ok {
		result.ipParams = *p
	} else {
		result.ipParams = ipAddressStringFormatParameters{
			allowPrefixesBeyondAddrSize: params.AllowsPrefixesBeyondAddressSize(),
			noPrefixLengthLeadingZeros:  !params.AllowsPrefixLengthLeadingZeros(),
			noBinary:                    !params.AllowsBinary(),
		}
	}
	result.AddressStringFormatParamsBuilder = *ToAddressStringFormatParamsBuilder(params)
	return &result
}

func (builder *IPAddressStringFormatParametersBuilder) GetParentBuilder() *IPAddressStringParametersBuilder {
	return builder.parent
}

func (builder *IPAddressStringFormatParametersBuilder) ToParams() IPAddressStringFormatParameters {
	result := &builder.ipParams
	result.addressStringFormatParameters = *builder.AddressStringFormatParamsBuilder.ToParams().(*addressStringFormatParameters)
	return result
}

func (builder *IPAddressStringFormatParametersBuilder) AllowsPrefixesBeyondAddressSize() bool {
	return builder.ipParams.AllowsPrefixesBeyondAddressSize()
}

func (builder *IPAddressStringFormatParametersBuilder) AllowsPrefixLengthLeadingZeros() bool {
	return builder.ipParams.AllowsPrefixLengthLeadingZeros()
}

func (builder *IPAddressStringFormatParametersBuilder) AllowsBinary() bool {
	return builder.ipParams.AllowsBinary()
}

func (builder *IPAddressStringFormatParametersBuilder) allowBinary(allow bool) {
	builder.ipParams.noBinary = !allow
}

func (builder *IPAddressStringFormatParametersBuilder) allowPrefixesBeyondAddressSize(allow bool) {
	builder.ipParams.allowPrefixesBeyondAddrSize = allow
}

func (builder *IPAddressStringFormatParametersBuilder) allowPrefixLengthLeadingZeros(allow bool) {
	builder.ipParams.noPrefixLengthLeadingZeros = !allow
}

type ipv6AddressStringParameters struct {
	ipAddressStringFormatParameters

	noMixed, noZone, noBase85 bool

	network *IPv6AddressNetwork

	embeddedParams *ipAddressStringParameters
}

func (params *ipv6AddressStringParameters) AllowsMixed() bool {
	return !params.noMixed
}

func (params *ipv6AddressStringParameters) AllowsZone() bool {
	return !params.noZone
}

func (params *ipv6AddressStringParameters) AllowsBase85() bool {
	return !params.noBase85
}

func (params *ipv6AddressStringParameters) GetMixedParameters() IPAddressStringParameters {
	return params.embeddedParams
}

func (params *ipv6AddressStringParameters) GetEmbeddedIPv4AddressParams() IPv4AddressStringParameters {
	return params.embeddedParams.GetIPv4Parameters()
}

func (params *ipv6AddressStringParameters) GetNetwork() *IPv6AddressNetwork {
	if params.network == nil {
		return &DefaultIPv6Network
	}
	return params.network
}

type IPv6AddressStringParametersBuilder struct {
	// This is not anonymous since it clashes with IPAddressStringFormatParametersBuilder,
	// both have ipAddressStringFormatParameters and AddressStringFormatParameters
	// and thee builder IPAddressStringFormatParametersBuilder takes precedence
	params ipv6AddressStringParameters

	embeddedBuilder *IPAddressStringParametersBuilder

	IPAddressStringFormatParametersBuilder
}

func ToIPv6AddressStringParamsBuilder(params IPv6AddressStringParameters) *IPv6AddressStringParametersBuilder {
	return toIPv6AddressStringParamsBuilder(params, false)
}

func toIPv6AddressStringParamsBuilder(params IPv6AddressStringParameters, isMixed bool) *IPv6AddressStringParametersBuilder {
	var result IPv6AddressStringParametersBuilder
	if p, ok := params.(*ipv6AddressStringParameters); ok {
		result.params = *p
	} else {
		result.params = ipv6AddressStringParameters{
			noMixed:  !params.AllowsMixed(),
			noZone:   !params.AllowsZone(),
			noBase85: !params.AllowsBase85(),
			network:  params.GetNetwork(),
		}
	}
	result.IPAddressStringFormatParametersBuilder = *ToIPAddressStringFormatParamsBuilder(params)
	if !isMixed {
		result.getEmbeddedIPv4ParametersBuilder().ipv4Builder = *ToIPv4AddressStringParamsBuilder(params.GetEmbeddedIPv4AddressParams())
	}
	return &result
}

func (builder *IPv6AddressStringParametersBuilder) ToParams() IPv6AddressStringParameters {
	result := &builder.params
	result.ipAddressStringFormatParameters = *builder.IPAddressStringFormatParametersBuilder.ToParams().(*ipAddressStringFormatParameters)
	if emb := builder.embeddedBuilder; emb == nil {
		result.embeddedParams = defaultEmbeddedParams
	} else {
		result.embeddedParams = emb.ToParams().(*ipAddressStringParameters)
	}
	return result
}

func (params *IPv6AddressStringParametersBuilder) GetRangeParametersBuilder() *RangeParametersBuilder {
	result := &params.rangeParamsBuilder
	result.parent = params
	return result
}

func (builder *IPv6AddressStringParametersBuilder) SetNetwork(network *IPv6AddressNetwork) *IPv6AddressStringParametersBuilder {
	builder.params.network = network
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowsMixed() bool {
	return builder.params.AllowsMixed()
}

func (builder *IPv6AddressStringParametersBuilder) AllowsZone() bool {
	return builder.params.AllowsZone()
}

func (builder *IPv6AddressStringParametersBuilder) AllowsBase85() bool {
	return builder.params.AllowsBase85()
}

func (builder *IPv6AddressStringParametersBuilder) AllowBase85(allow bool) *IPv6AddressStringParametersBuilder {
	builder.params.noBase85 = !allow
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowZone(allow bool) *IPv6AddressStringParametersBuilder {
	builder.params.noZone = !allow

	//we must decide whether to treat the % character as a zone when parsing the mixed part
	//if considered zone, then the zone character is actually part of the encompassing ipv6 address
	//otherwise, the zone character is an sql wildcard that is part of the mixed address
	//So whether we consider the % character a zone must match the same setting for the encompassing address

	// ipv4Builder can be nil when builder == &defaultEmbeddedBuilder.ipv6Builder, see getEmbeddedIPv4ParametersBuilder()
	if ipv4Builder := builder.getEmbeddedIPv4ParametersBuilder(); ipv4Builder != nil {
		ipv4Builder.GetIPv6AddressParametersBuilder().params.noZone = !allow
	}
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowMixed(allow bool) *IPv6AddressStringParametersBuilder {
	builder.params.noMixed = !allow
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) getEmbeddedIPv4ParametersBuilder() (result *IPAddressStringParametersBuilder) {
	if builder == &defaultEmbeddedBuilder.ipv6Builder {
		return nil
	}
	if result = builder.embeddedBuilder; result == nil {
		result = &IPAddressStringParametersBuilder{}
		// copy in proper default values for embedded IPv4 addresses, which differ from defaults for typical IPV4 addresses
		*result = defaultEmbeddedBuilder
		builder.embeddedBuilder = result
	}
	result.GetIPv4AddressParametersBuilder().mixedParent = builder
	return
}

func (builder *IPv6AddressStringParametersBuilder) GetEmbeddedIPv4AddressParametersBuilder() (result *IPv4AddressStringParametersBuilder) {
	return builder.getEmbeddedIPv4ParametersBuilder().GetIPv4AddressParametersBuilder()
}

func (builder *IPv6AddressStringParametersBuilder) Allow_mixed_inet_aton(allow bool) *IPv6AddressStringParametersBuilder {
	builder.getEmbeddedIPv4ParametersBuilder().Allow_inet_aton(allow)
	if allow { // if we allow inet_aton in the mixed part, then of course that insinuates that we allow the mixed part
		builder.AllowMixed(allow)
	}
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowBinary(allow bool) *IPv6AddressStringParametersBuilder {
	builder.GetEmbeddedIPv4AddressParametersBuilder().AllowBinary(allow)
	builder.allowBinary(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowWildcardedSeparator(allow bool) *IPv6AddressStringParametersBuilder {
	builder.GetEmbeddedIPv4AddressParametersBuilder().AllowWildcardedSeparator(allow)
	builder.allowWildcardedSeparator(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowLeadingZeros(allow bool) *IPv6AddressStringParametersBuilder {
	builder.GetEmbeddedIPv4AddressParametersBuilder().allowLeadingZeros(allow)
	builder.allowLeadingZeros(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowUnlimitedLeadingZeros(allow bool) *IPv6AddressStringParametersBuilder {
	builder.GetEmbeddedIPv4AddressParametersBuilder().AllowUnlimitedLeadingZeros(allow)
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) SetRangeParameters(rangeParams RangeParameters) *IPv6AddressStringParametersBuilder {
	builder.GetEmbeddedIPv4AddressParametersBuilder().SetRangeParameters(rangeParams)
	builder.setRangeParameters(rangeParams)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowPrefixesBeyondAddressSize(allow bool) *IPv6AddressStringParametersBuilder {
	builder.allowPrefixesBeyondAddressSize(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowPrefixLengthLeadingZeros(allow bool) *IPv6AddressStringParametersBuilder {
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

	network *IPv4AddressNetwork
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

func (params *ipv4AddressStringParameters) GetNetwork() *IPv4AddressNetwork {
	if params.network == nil {
		return &DefaultIPv4Network
	}
	return params.network
}

type IPv4AddressStringParametersBuilder struct {
	// This is not anonymous since it clashes with IPAddressStringFormatParametersBuilder,
	// both have ipAddressStringFormatParameters and AddressStringFormatParameters
	// IPAddressStringFormatParametersBuilder takes precedence
	params ipv4AddressStringParameters

	IPAddressStringFormatParametersBuilder

	mixedParent *IPv6AddressStringParametersBuilder
}

func ToIPv4AddressStringParamsBuilder(params IPv4AddressStringParameters) *IPv4AddressStringParametersBuilder {
	var result IPv4AddressStringParametersBuilder
	if p, ok := params.(*ipv4AddressStringParameters); ok {
		result.params = *p
	} else {
		result.params = ipv4AddressStringParameters{
			no_inet_aton_hex:              params.Allows_inet_aton_hex(),
			no_inet_aton_octal:            params.Allows_inet_aton_octal(),
			no_inet_aton_joinedSegments:   params.Allows_inet_aton_joinedSegments(),
			inet_aton_single_segment_mask: params.Allows_inet_aton_single_segment_mask(),
			no_inet_aton_leading_zeros:    params.Allows_inet_aton_leading_zeros(),
			network:                       params.GetNetwork(),
		}
	}
	result.IPAddressStringFormatParametersBuilder = *ToIPAddressStringFormatParamsBuilder(params)
	return &result
}

func (builder *IPv4AddressStringParametersBuilder) ToParams() IPv4AddressStringParameters {
	result := &builder.params
	result.ipAddressStringFormatParameters = *builder.IPAddressStringFormatParametersBuilder.ToParams().(*ipAddressStringFormatParameters)
	return result
}

// If this builder was obtained by a call to getEmbeddedIPv4ParametersBuilder() from IPv6AddressStringParametersBuilder,
// returns that IPv6AddressStringParametersBuilder
func (params *IPv4AddressStringParametersBuilder) GetEmbeddedIPv4AddressParentBuilder() *IPv6AddressStringParametersBuilder {
	return params.mixedParent
}

func (params *IPv4AddressStringParametersBuilder) GetRangeParametersBuilder() *RangeParametersBuilder {
	result := &params.rangeParamsBuilder
	result.parent = params
	return result
}

func (builder *IPv4AddressStringParametersBuilder) SetNetwork(network *IPv4AddressNetwork) *IPv4AddressStringParametersBuilder {
	builder.params.network = network
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) Allow_inet_aton(allow bool) *IPv4AddressStringParametersBuilder {
	builder.params.no_inet_aton_joinedSegments = !allow
	builder.params.no_inet_aton_octal = !allow
	builder.params.no_inet_aton_hex = !allow
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) Allow_inet_aton_hex(allow bool) *IPv4AddressStringParametersBuilder {
	builder.params.no_inet_aton_hex = !allow
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) Allow_inet_aton_octal(allow bool) *IPv4AddressStringParametersBuilder {
	builder.params.no_inet_aton_octal = !allow
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) Allow_inet_aton_leading_zeros(allow bool) *IPv4AddressStringParametersBuilder {
	builder.params.no_inet_aton_leading_zeros = !allow
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) Allow_inet_aton_joinedSegments(allow bool) *IPv4AddressStringParametersBuilder {
	builder.params.no_inet_aton_joinedSegments = !allow
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) Allow_inet_aton_single_segment_mask(allow bool) *IPv4AddressStringParametersBuilder {
	builder.params.inet_aton_single_segment_mask = allow
	return builder
}
func (builder *IPv4AddressStringParametersBuilder) AllowWildcardedSeparator(allow bool) *IPv4AddressStringParametersBuilder {
	builder.allowWildcardedSeparator(allow)
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) AllowLeadingZeros(allow bool) *IPv4AddressStringParametersBuilder {
	builder.allowLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) AllowUnlimitedLeadingZeros(allow bool) *IPv4AddressStringParametersBuilder {
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) SetRangeParameters(rangeParams RangeParameters) *IPv4AddressStringParametersBuilder {
	builder.setRangeParameters(rangeParams)
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) AllowPrefixesBeyondAddressSize(allow bool) *IPv4AddressStringParametersBuilder {
	builder.allowPrefixesBeyondAddressSize(allow)
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) AllowPrefixLengthLeadingZeros(allow bool) *IPv4AddressStringParametersBuilder {
	builder.allowPrefixLengthLeadingZeros(allow)
	return builder
}

func (builder *IPv4AddressStringParametersBuilder) AllowBinary(allow bool) *IPv4AddressStringParametersBuilder {
	builder.allowBinary(allow)
	return builder
}
