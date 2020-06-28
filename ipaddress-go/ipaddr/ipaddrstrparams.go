package ipaddr

// IPAddressStringParametersBuilder has parameters for parsing IP address strings
// They are immutable and must be constructed using an IPAddressStringParametersBuilder
type IPAddressStringParameters struct {
	addressStringParameters
	ipv4Params IPv4AddressStringParameters
	ipv6Params IPv6AddressStringParameters

	noPrefixOnly, emptyIsNotLoopback, noPrefix, noMask, noIPv6, noIPv4 bool //TODO need accessors for these
}

func (params *IPAddressStringParameters) getIPv4Parameters() *IPv4AddressStringParameters {
	return &params.ipv4Params
}

func (params *IPAddressStringParameters) getIPv6Parameters() *IPv6AddressStringParameters {
	return &params.ipv6Params
}

// IPAddressStringParametersBuilder builds an IPAddressStringParameters
type IPAddressStringParametersBuilder struct {
	params IPAddressStringParameters
	addressStringParametersBuilderBase
	//TODO ipv4Builder IPv4AddressStringParametersBuilder
	//TODO ipv6Builder IPv6AddressStringParametersBuilder
}

func NewIPAddressStringParametersBuilder() *IPAddressStringParametersBuilder {
	return &IPAddressStringParametersBuilder{}
}

func (builder *IPAddressStringParametersBuilder) ToParams() *IPAddressStringParameters {
	result := builder.params
	result.addressStringParameters = builder.addressStringParametersBuilderBase.addressStringParameters
	//TODO copy into result ipv4paramsbuilder results and ipv6 too
	return &result
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

func (builder *IPAddressStringParametersBuilder) EmptyIsLoopback(val bool) *IPAddressStringParametersBuilder {
	builder.params.emptyIsNotLoopback = !val
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowPrefix(val bool) *IPAddressStringParametersBuilder {
	builder.params.noPrefix = !val
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowMask(val bool) *IPAddressStringParametersBuilder {
	builder.params.noMask = !val
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowPrefixOnly(val bool) *IPAddressStringParametersBuilder {
	builder.params.noPrefixOnly = !val
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowIPv4(val bool) *IPAddressStringParametersBuilder {
	builder.params.noIPv4 = !val
	return builder
}

func (builder *IPAddressStringParametersBuilder) AllowIPv6(val bool) *IPAddressStringParametersBuilder {
	builder.params.noIPv6 = !val
	return builder
}

//TODO these 3, you also need to add the accessors to the ipv4 and ipv6 builders
//public Builder allowWildcardedSeparator(boolean allow) {
//getIPv4AddressParametersBuilder().allowWildcardedSeparator(allow);
//getIPv6AddressParametersBuilder().allowWildcardedSeparator(allow);
//return this;
//}
//
//public Builder setRangeOptions(RangeParameters rangeOptions) {
//getIPv4AddressParametersBuilder().setRangeOptions(rangeOptions);
//getIPv6AddressParametersBuilder().setRangeOptions(rangeOptions);
//return this;
//}
//
//public Builder allow_inet_aton(boolean allow) {
//getIPv4AddressParametersBuilder().allow_inet_aton(allow);
//getIPv6AddressParametersBuilder().allow_mixed_inet_aton(allow);
//return this;
//}

//TODO this struct and others could be private I think - but is it necessary?  Not sure

type IPAddressStringFormatParameters struct {
	AddressStringFormatParameters

	allowPrefixesBeyondAddrSize, noPrefixLengthLeadingZeros bool
}

func (params *IPAddressStringFormatParameters) AllowsPrefixesBeyondAddressSize() bool {
	return params.allowPrefixesBeyondAddrSize
}

func (params *IPAddressStringFormatParameters) AllowsPrefixLengthLeadingZeros() bool {
	return !params.noPrefixLengthLeadingZeros
}

type IPAddressStringFormatParametersBuilder struct {
	AddressStringFormatParametersBuilder
	IPAddressStringFormatParameters
}

func (builder *IPAddressStringFormatParametersBuilder) toParams() *IPAddressStringFormatParameters {
	result := builder.IPAddressStringFormatParameters
	result.AddressStringFormatParameters = builder.AddressStringFormatParametersBuilder.AddressStringFormatParameters
	return &result
}

func (builder *IPAddressStringFormatParametersBuilder) allowPrefixesBeyondAddressSize(allow bool) {
	builder.allowPrefixesBeyondAddrSize = allow
}

func (builder *IPAddressStringFormatParametersBuilder) allowPrefixLengthLeadingZeros(allow bool) {
	builder.noPrefixLengthLeadingZeros = !allow
}

type IPv6AddressStringParameters struct {
	IPAddressStringFormatParameters

	noMixed, noZone, noBase85 bool
	network                   *IPv6AddressNetwork

	embeddedIPv4Options *IPAddressStringParameters // TODO use a default mixed params when nil, see getEmbeddedIPv4ParametersBuilder() on java side
}

func (params *IPv6AddressStringParameters) AllowsMixed() bool {
	return !params.noMixed
}

func (params *IPv6AddressStringParameters) AllowsZone() bool {
	return !params.noZone
}

func (params *IPv6AddressStringParameters) AllowsBase85() bool {
	return !params.noBase85
}

func (params *IPv6AddressStringParameters) GetNetwork() *IPv6AddressNetwork {
	if params.network == nil {
		return &DefaultIPv6Network
	}
	return params.network
}

type IPv6AddressStringParametersBuilder struct {
	//TODO why not make this anonoymous?  We did that with AddressStringFormatParametersBuilder
	// OHHH is it because of clashes with IPAddressStringFormatParametersBuilder?
	// Could be that, since there is a nested IPAddressStringFormatParameters in IPv6AddressStringParameters
	// and those values are the builder's values
	params IPv6AddressStringParameters

	IPAddressStringFormatParametersBuilder
}

func (builder *IPv6AddressStringParametersBuilder) ToParams() *IPv6AddressStringParameters {
	result := builder.params
	result.IPAddressStringFormatParameters = *builder.IPAddressStringFormatParametersBuilder.toParams()
	return &result
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

//TODO accessor for the embedded options builder

func (builder *IPv6AddressStringParametersBuilder) AllowBase85(allow bool) *IPv6AddressStringParametersBuilder {
	builder.params.noBase85 = !allow
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowZone(allow bool) *IPv6AddressStringParametersBuilder {
	// TODO also set the same property in the embedded ipv4 options
	builder.params.noZone = !allow
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) Allow_mixed_inet_aton(allow bool) *IPv6AddressStringParametersBuilder {
	// TODO set the property in the embedded ipv4 options
	if allow {
		builder.AllowMixed(allow)
	}
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowMixed(allow bool) *IPv6AddressStringParametersBuilder {
	builder.params.noMixed = !allow
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowWildcardedSeparator(allow bool) *IPv6AddressStringParametersBuilder {
	// TODO also set the same property in the embedded ipv4 options
	builder.allowWildcardedSeparator(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowLeadingZeros(allow bool) *IPv6AddressStringParametersBuilder {
	// TODO also set the same property in the embedded ipv4 options
	builder.allowLeadingZeros(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) AllowUnlimitedLeadingZeros(allow bool) *IPv6AddressStringParametersBuilder {
	// TODO also set the same property in the embedded ipv4 options
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *IPv6AddressStringParametersBuilder) SetRangeParameters(rangeParams *RangeParameters) *IPv6AddressStringParametersBuilder {
	// TODO also set the same property in the embedded ipv4 options
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

//TODO ipv4, model it after ipv6

//
//
//
type IPv4AddressStringParameters struct {
	IPAddressStringFormatParameters
}
