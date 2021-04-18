package ipaddr

//func convertMACParams(orig MACAddressStringParameters) *macAddressStringParameters {
//	if params, ok := orig.(*macAddressStringParameters); ok {
//		return params
//	}
//	origFormat := orig.GetFormatParameters()
//	formatRange := origFormat.GetRangeParameters()
//	paramsBuilder := MACAddressStringParametersBuilder{}
//	return paramsBuilder.
//		// general settings
//		SetAddressSize(orig.AddressSize()).
//		AllowDashed(orig.AllowsDashed()).
//		AllowSingleDashed(orig.AllowsSingleDashed()).
//		AllowColonDelimited(orig.AllowsColonDelimited()).
//		AllowDotted(orig.AllowsDotted()).
//		AllowSpaceDelimited(orig.AllowsSpaceDelimited()).
//		SetNetwork(orig.GetNetwork()).
//		AllowEmpty(orig.AllowsEmpty()).
//		AllowSingleSegment(orig.AllowsSingleSegment()).
//		AllowAll(orig.AllowsAll()).
//		//
//		// format parameters
//		GetFormatParametersBuilder().
//		AllowShortSegments(origFormat.AllowsShortSegments()).
//		AllowWildcardedSeparator(origFormat.AllowsWildcardedSeparator()).
//		AllowLeadingZeros(origFormat.AllowsLeadingZeros()).
//		AllowUnlimitedLeadingZeros(origFormat.AllowsUnlimitedLeadingZeros()).
//		//
//		// ranges
//		GetRangeParametersBuilder().
//		AllowWildcard(formatRange.AllowsWildcard()).
//		AllowRangeSeparator(formatRange.AllowsRangeSeparator()).
//		AllowReverseRange(formatRange.AllowsReverseRange()).
//		AllowInferredBoundary(formatRange.AllowsInferredBoundary()).
//		AllowSingleWildcard(formatRange.AllowsSingleWildcard()).
//		GetMACParentBuilder().
//		GetParentBuilder().
//		//
//		ToParams().(*macAddressStringParameters)
//}

type AddressSize string //TODO rename to MACAddressSize

const (
	MAC   AddressSize = "MAC"
	EUI64 AddressSize = "EUI64"
	ANY   AddressSize = ""
)

type MACAddressStringParameters interface {
	AddressStringParameters

	AddressSize() AddressSize
	AllowsDashed() bool
	AllowsSingleDashed() bool
	AllowsColonDelimited() bool
	AllowsDotted() bool
	AllowsSpaceDelimited() bool
	GetNetwork() *MACAddressNetwork //TODO remove, since we will no longer use address creators
	GetFormatParameters() MACAddressStringFormatParameters
}

var _ MACAddressStringParameters = &macAddressStringParameters{}

type MACAddressStringFormatParameters interface {
	AddressStringFormatParameters

	AllowsShortSegments() bool
}

var _ MACAddressStringFormatParameters = &macAddressStringFormatParameters{}

// ipAddressStringParameters has parameters for parsing IP address strings
// They are immutable and must be constructed using an IPAddressStringParametersBuilder
type macAddressStringParameters struct {
	addressStringParameters
	formatParams macAddressStringFormatParameters

	noAllowDashed,
	noAllowSingleDashed,
	noAllowColonDelimited,
	noAllowDotted,
	noAllowSpaceDelimited bool
	allAddresses AddressSize
	network      *MACAddressNetwork
}

func (params *macAddressStringParameters) AddressSize() AddressSize {
	return params.allAddresses
}

func (params *macAddressStringParameters) GetNetwork() *MACAddressNetwork {
	if params.network == nil {
		return &DefaultMACNetwork
	}
	return params.network
}

func (params *macAddressStringParameters) AllowsDashed() bool {
	return !params.noAllowDashed
}

func (params *macAddressStringParameters) AllowsSingleDashed() bool {
	return !params.noAllowSingleDashed
}

func (params *macAddressStringParameters) AllowsColonDelimited() bool {
	return !params.noAllowColonDelimited
}

func (params *macAddressStringParameters) AllowsDotted() bool {
	return !params.noAllowDotted
}

func (params *macAddressStringParameters) AllowsSpaceDelimited() bool {
	return !params.noAllowSpaceDelimited
}

func (params *macAddressStringParameters) GetFormatParameters() MACAddressStringFormatParameters {
	return &params.formatParams
}

// MACAddressStringParametersBuilder builds an ipAddressStringParameters
type MACAddressStringParametersBuilder struct {
	params macAddressStringParameters
	AddressStringParametersBuilder
	formatBuilder MACAddressStringFormatParametersBuilder
}

func ToMACAddressStringParamsBuilder(params MACAddressStringParameters) *MACAddressStringParametersBuilder {
	var result MACAddressStringParametersBuilder
	if p, ok := params.(*macAddressStringParameters); ok {
		result.params = *p
	} else {
		result.params = macAddressStringParameters{
			noAllowDashed:         !params.AllowsDashed(),
			noAllowSingleDashed:   !params.AllowsSingleDashed(),
			noAllowColonDelimited: !params.AllowsColonDelimited(),
			noAllowDotted:         !params.AllowsDotted(),
			noAllowSpaceDelimited: !params.AllowsSpaceDelimited(),
			allAddresses:          params.AddressSize(),
			network:               params.GetNetwork(),
		}
	}
	result.AddressStringParametersBuilder = *ToAddressStringParamsBuilder(params)
	result.formatBuilder = *ToMACAddressStringFormatParamsBuilder(params.GetFormatParameters())
	return &result
}

func (builder *MACAddressStringParametersBuilder) ToParams() MACAddressStringParameters {
	// We do not return a pointer to builder.params because that would make it possible to change a macAddressStringParameters
	// by continuing to use the same builder,
	// and we want immutable objects for thread-safety,
	// so we cannot allow it
	result := builder.params
	result.addressStringParameters = *builder.AddressStringParametersBuilder.ToParams().(*addressStringParameters)
	result.formatParams = *builder.formatBuilder.ToParams().(*macAddressStringFormatParameters)
	return &result
}

func (builder *MACAddressStringParametersBuilder) GetFormatParametersBuilder() (result *MACAddressStringFormatParametersBuilder) {
	result = &builder.formatBuilder
	result.parent = builder
	return
}

func (builder *MACAddressStringParametersBuilder) AllowEmpty(allow bool) *MACAddressStringParametersBuilder {
	builder.allowEmpty(allow)
	return builder
}

func (builder *MACAddressStringParametersBuilder) AllowSingleSegment(allow bool) *MACAddressStringParametersBuilder {
	builder.allowSingleSegment(allow)
	return builder
}

func (builder *MACAddressStringParametersBuilder) AllowAll(allow bool) *MACAddressStringParametersBuilder {
	builder.allowAll(allow)
	return builder
}

func (builder *MACAddressStringParametersBuilder) SetAddressSize(size AddressSize) *MACAddressStringParametersBuilder {
	builder.params.allAddresses = size
	return builder
}

func (builder *MACAddressStringParametersBuilder) SetNetwork(network *MACAddressNetwork) *MACAddressStringParametersBuilder {
	builder.params.network = network
	return builder
}

func (builder *MACAddressStringParametersBuilder) AllowDashed(allow bool) *MACAddressStringParametersBuilder {
	builder.params.noAllowDashed = !allow
	return builder
}

func (builder *MACAddressStringParametersBuilder) AllowSingleDashed(allow bool) *MACAddressStringParametersBuilder {
	builder.params.noAllowSingleDashed = !allow
	return builder
}

func (builder *MACAddressStringParametersBuilder) AllowColonDelimited(allow bool) *MACAddressStringParametersBuilder {
	builder.params.noAllowColonDelimited = !allow
	return builder
}

func (builder *MACAddressStringParametersBuilder) AllowDotted(allow bool) *MACAddressStringParametersBuilder {
	builder.params.noAllowDotted = !allow
	return builder
}

func (builder *MACAddressStringParametersBuilder) AllowSpaceDelimited(allow bool) *MACAddressStringParametersBuilder {
	builder.params.noAllowSpaceDelimited = !allow
	return builder
}

type macAddressStringFormatParameters struct {
	addressStringFormatParameters

	noShortSegments bool
}

func (params *macAddressStringFormatParameters) AllowsShortSegments() bool {
	return !params.noShortSegments
}

type MACAddressStringFormatParametersBuilder struct {
	// This is not anonymous since it clashes with AddressStringFormatParamsBuilder,
	// both have AddressStringFormatParameters
	// AddressStringFormatParamsBuilder takes precedence
	params macAddressStringFormatParameters

	AddressStringFormatParamsBuilder

	parent *MACAddressStringParametersBuilder
}

func ToMACAddressStringFormatParamsBuilder(params MACAddressStringFormatParameters) *MACAddressStringFormatParametersBuilder {
	var result MACAddressStringFormatParametersBuilder
	if p, ok := params.(*macAddressStringFormatParameters); ok {
		result.params = *p
	} else {
		result.params = macAddressStringFormatParameters{
			noShortSegments: !params.AllowsShortSegments(),
		}
	}
	result.AddressStringFormatParamsBuilder = *ToAddressStringFormatParamsBuilder(params)
	return &result
}

func (builder *MACAddressStringFormatParametersBuilder) GetParentBuilder() *MACAddressStringParametersBuilder {
	return builder.parent
}

func (builder *MACAddressStringFormatParametersBuilder) ToParams() MACAddressStringFormatParameters {
	result := &builder.params
	result.addressStringFormatParameters = *builder.AddressStringFormatParamsBuilder.ToParams().(*addressStringFormatParameters)
	return result
}

func (params *MACAddressStringFormatParametersBuilder) GetRangeParametersBuilder() *RangeParametersBuilder {
	result := &params.rangeParamsBuilder
	result.parent = params
	return result
}

func (builder *MACAddressStringFormatParametersBuilder) AllowWildcardedSeparator(allow bool) *MACAddressStringFormatParametersBuilder {
	builder.allowWildcardedSeparator(allow)
	return builder
}

func (builder *MACAddressStringFormatParametersBuilder) AllowLeadingZeros(allow bool) *MACAddressStringFormatParametersBuilder {
	builder.allowLeadingZeros(allow)
	return builder
}

func (builder *MACAddressStringFormatParametersBuilder) AllowUnlimitedLeadingZeros(allow bool) *MACAddressStringFormatParametersBuilder {
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *MACAddressStringFormatParametersBuilder) SetRangeParameters(rangeParams RangeParameters) *MACAddressStringFormatParametersBuilder {
	builder.setRangeParameters(rangeParams)
	return builder
}

func (builder *MACAddressStringFormatParametersBuilder) AllowShortSegments(allow bool) *MACAddressStringFormatParametersBuilder {
	builder.params.noShortSegments = !allow
	return builder
}
