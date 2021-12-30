package addrparam

type AddressStringFormatParams interface {
	AllowsWildcardedSeparator() bool
	AllowsLeadingZeros() bool
	AllowsUnlimitedLeadingZeros() bool

	// RangeParams describes whether ranges of values are allowed
	GetRangeParams() RangeParams
}

type AddressStringParams interface {
	AllowsEmpty() bool
	AllowsSingleSegment() bool

	// AllowsAll indicates if we allow the string of just the wildcard "*" to denote all addresses of all version.
	// If false, then for IP addresses we check the preferred version with GetPreferredVersion(), and then check AllowsWildcardedSeparator(),
	// to determine if the string represents all addresses of that version.
	AllowsAll() bool
}

type RangeParams interface {
	// whether '*' is allowed to denote segments covering all possible segment values
	AllowsWildcard() bool

	// whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
	AllowsRangeSeparator() bool

	// whether to allow a segment terminating with '_' characters, which represent any digit
	AllowsSingleWildcard() bool

	// whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1
	AllowsReverseRange() bool

	// whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value
	AllowsInferredBoundary() bool
}

//func AllowsNoRange(p RangeParams) bool {
//	return !(p.AllowsWildcard() || p.AllowsRangeSeparator() || p.AllowsSingleWildcard())
//}

var _ AddressStringFormatParams = &addressStringFormatParameters{}
var _ AddressStringParams = &addressStringParameters{}
var _ RangeParams = &rangeParameters{}

type rangeParameters struct {
	noWildcard, noValueRange, noReverseRange, noSingleWildcard, noInferredBoundary bool
}

var (
	NoRange RangeParams = &rangeParameters{
		noWildcard:         true,
		noValueRange:       true,
		noReverseRange:     true,
		noSingleWildcard:   true,
		noInferredBoundary: true,
	}

	// use this to support addresses like 1.*.3.4 or 1::*:3 or 1.2_.3.4 or 1::a__:3
	WildcardOnly RangeParams = &rangeParameters{
		noValueRange:   true,
		noReverseRange: true,
		//noSingleWildcard: true,
	}

	// use this to support addresses supported by DEFAULT_WILDCARD_OPTIONS and also addresses like 1.2-3.3.4 or 1:0-ff::
	WildcardAndRange RangeParams = &rangeParameters{}
)

// whether '*' is allowed to denote segments covering all possible segment values
func (builder *rangeParameters) AllowsWildcard() bool {
	return !builder.noWildcard
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
func (builder *rangeParameters) AllowsRangeSeparator() bool {
	return !builder.noValueRange
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1
func (builder *rangeParameters) AllowsReverseRange() bool {
	return !builder.noReverseRange
}

// whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value
func (builder *rangeParameters) AllowsInferredBoundary() bool {
	return !builder.noInferredBoundary
}

// whether to allow a segment terminating with '_' characters, which represent any digit
func (builder *rangeParameters) AllowsSingleWildcard() bool {
	return !builder.noSingleWildcard
}

type RangeParamsBuilder struct {
	rangeParameters
	parent interface{}
}

func (builder *RangeParamsBuilder) ToParams() RangeParams {
	return &builder.rangeParameters
}

func (builder *RangeParamsBuilder) Set(rangeParams RangeParams) *RangeParamsBuilder {
	if rp, ok := rangeParams.(*rangeParameters); ok {
		builder.rangeParameters = *rp
		//return &RangeParamsBuilder{rangeParameters: *rp}
	} else {
		builder.rangeParameters = rangeParameters{
			noWildcard:         !rangeParams.AllowsWildcard(),
			noValueRange:       !rangeParams.AllowsRangeSeparator(),
			noReverseRange:     !rangeParams.AllowsReverseRange(),
			noSingleWildcard:   !rangeParams.AllowsSingleWildcard(),
			noInferredBoundary: !rangeParams.AllowsInferredBoundary(),
		}
		//return &RangeParamsBuilder{rangeParameters: rangeParameters{
		//	noWildcard:         !rangeParams.AllowsWildcard(),
		//	noValueRange:       !rangeParams.AllowsRangeSeparator(),
		//	noReverseRange:     !rangeParams.AllowsReverseRange(),
		//	noSingleWildcard:   !rangeParams.AllowsSingleWildcard(),
		//	noInferredBoundary: !rangeParams.AllowsInferredBoundary(),
		//}}
	}
	return builder
}

//func ToRangeParamsBuilder(rangeParams RangeParams) *RangeParamsBuilder {
//	xxx
//	if rp, ok := rangeParams.(*rangeParameters); ok {
//		return &RangeParamsBuilder{rangeParameters: *rp}
//	} else {
//		return &RangeParamsBuilder{rangeParameters: rangeParameters{
//			noWildcard:         !rangeParams.AllowsWildcard(),
//			noValueRange:       !rangeParams.AllowsRangeSeparator(),
//			noReverseRange:     !rangeParams.AllowsReverseRange(),
//			noSingleWildcard:   !rangeParams.AllowsSingleWildcard(),
//			noInferredBoundary: !rangeParams.AllowsInferredBoundary(),
//		}}
//	}
//}

// If this builder was obtained by a call to IPv4AddressStringParamsBuilder.GetRangeParamsBuilder(), returns the IPv4AddressStringParamsBuilder
func (builder *RangeParamsBuilder) GetIPv4ParentBuilder() *IPv4AddressStringParamsBuilder {
	parent := builder.parent
	if p, ok := parent.(*IPv4AddressStringParamsBuilder); ok {
		return p
	}
	return nil
}

// If this builder was obtained by a call to IPv6AddressStringParamsBuilder.GetRangeParamsBuilder(), returns the IPv6AddressStringParamsBuilder
func (builder *RangeParamsBuilder) GetIPv6ParentBuilder() *IPv6AddressStringParamsBuilder {
	parent := builder.parent
	if p, ok := parent.(*IPv6AddressStringParamsBuilder); ok {
		return p
	}
	return nil
}

// If this builder was obtained by a call to IPv6AddressStringParamsBuilder.GetRangeParamsBuilder(), returns the IPv6AddressStringParamsBuilder
func (builder *RangeParamsBuilder) GetMACParentBuilder() *MACAddressStringFormatParamsBuilder {
	parent := builder.parent
	if p, ok := parent.(*MACAddressStringFormatParamsBuilder); ok {
		return p
	}
	return nil
}

// whether '*' is allowed to denote segments covering all possible segment values
func (builder *RangeParamsBuilder) AllowWildcard(allow bool) *RangeParamsBuilder {
	builder.noWildcard = !allow
	return builder
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
func (builder *RangeParamsBuilder) AllowRangeSeparator(allow bool) *RangeParamsBuilder {
	builder.noValueRange = !allow
	return builder
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1
func (builder *RangeParamsBuilder) AllowReverseRange(allow bool) *RangeParamsBuilder {
	builder.noReverseRange = !allow
	return builder
}

// whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value
func (builder *RangeParamsBuilder) AllowInferredBoundary(allow bool) *RangeParamsBuilder {
	builder.noInferredBoundary = !allow
	return builder
}

// whether to allow a segment terminating with '_' characters, which represent any digit
func (builder *RangeParamsBuilder) AllowSingleWildcard(allow bool) *RangeParamsBuilder {
	builder.noSingleWildcard = !allow
	return builder
}

type addressStringParameters struct {
	noEmpty, noAll, noSingleSegment bool
}

func (params *addressStringParameters) AllowsEmpty() bool {
	return !params.noEmpty
}

func (params *addressStringParameters) AllowsSingleSegment() bool {
	return !params.noSingleSegment
}

func (params *addressStringParameters) AllowsAll() bool {
	return !params.noAll
}

// AddressStringParamsBuilder builds an AddressStringParams
type AddressStringParamsBuilder struct {
	addressStringParameters
}

//func ToAddressStringParamsBuilder(params AddressStringParams) *AddressStringParamsBuilder {
//	xxx
//	var result AddressStringParamsBuilder
//	if p, ok := params.(*addressStringParameters); ok {
//		result.addressStringParameters = *p
//	} else {
//		result.addressStringParameters = addressStringParameters{
//			noEmpty:         !params.AllowsEmpty(),
//			noAll:           !params.AllowsAll(),
//			noSingleSegment: !params.AllowsSingleSegment(),
//		}
//	}
//	return &result
//}

func (builder *AddressStringParamsBuilder) set(params AddressStringParams) {
	//var result AddressStringParamsBuilder
	if p, ok := params.(*addressStringParameters); ok {
		builder.addressStringParameters = *p
	} else {
		builder.addressStringParameters = addressStringParameters{
			noEmpty:         !params.AllowsEmpty(),
			noAll:           !params.AllowsAll(),
			noSingleSegment: !params.AllowsSingleSegment(),
		}
	}
	//return &result
}

func (builder *AddressStringParamsBuilder) ToParams() AddressStringParams {
	return &builder.addressStringParameters
}

func (builder *AddressStringParamsBuilder) allowEmpty(allow bool) {
	builder.noEmpty = !allow
}

func (builder *AddressStringParamsBuilder) allowAll(allow bool) {
	builder.noAll = !allow
}

func (builder *AddressStringParamsBuilder) allowSingleSegment(allow bool) {
	builder.noSingleSegment = !allow
}

//
//
// AddressStringFormatParams are parameters specific to a given address type or version that is supplied
type addressStringFormatParameters struct {
	rangeParams rangeParameters

	noWildcardedSeparator, noLeadingZeros, noUnlimitedLeadingZeros bool
}

func (params *addressStringFormatParameters) AllowsWildcardedSeparator() bool {
	return !params.noWildcardedSeparator
}

func (params *addressStringFormatParameters) AllowsLeadingZeros() bool {
	return !params.noLeadingZeros
}

func (params *addressStringFormatParameters) AllowsUnlimitedLeadingZeros() bool {
	return !params.noUnlimitedLeadingZeros
}

func (params *addressStringFormatParameters) GetRangeParams() RangeParams {
	return &params.rangeParams
}

//
//
// AddressStringFormatParamsBuilder creates parameters for parsing a specific address type or address version
type AddressStringFormatParamsBuilder struct {
	addressStringFormatParameters

	rangeParamsBuilder RangeParamsBuilder
}

//func ToAddressStringFormatParamsBuilder(params AddressStringFormatParams) *AddressStringFormatParamsBuilder {
//	xx
//	var result AddressStringFormatParamsBuilder
//	if p, ok := params.(*addressStringFormatParameters); ok {
//		result.addressStringFormatParameters = *p
//	} else {
//		result.addressStringFormatParameters = addressStringFormatParameters{
//			noWildcardedSeparator:   !params.AllowsWildcardedSeparator(),
//			noLeadingZeros:          !params.AllowsLeadingZeros(),
//			noUnlimitedLeadingZeros: !params.AllowsUnlimitedLeadingZeros(),
//		}
//	}
//	result.rangeParamsBuilder = *ToRangeParamsBuilder(params.GetRangeParams())
//	return &result
//}

func (builder *AddressStringFormatParamsBuilder) ToParams() AddressStringFormatParams {
	result := &builder.addressStringFormatParameters
	result.rangeParams = *builder.rangeParamsBuilder.ToParams().(*rangeParameters)
	return result
}

func (builder *AddressStringFormatParamsBuilder) set(parms AddressStringFormatParams) {
	//var result AddressStringFormatParamsBuilder
	if p, ok := parms.(*addressStringFormatParameters); ok {
		builder.addressStringFormatParameters = *p
	} else {
		builder.addressStringFormatParameters = addressStringFormatParameters{
			noWildcardedSeparator:   !parms.AllowsWildcardedSeparator(),
			noLeadingZeros:          !parms.AllowsLeadingZeros(),
			noUnlimitedLeadingZeros: !parms.AllowsUnlimitedLeadingZeros(),
		}
	}
	//params.rangeParamsBuilder = *ToRangeParamsBuilder(parms.GetRangeParams())
	builder.rangeParamsBuilder.Set(parms.GetRangeParams())
	//return &result
}

func (builder *AddressStringFormatParamsBuilder) setRangeParameters(rangeParams RangeParams) {
	//params.rangeParamsBuilder = *ToRangeParamsBuilder(rangeParams)
	builder.rangeParamsBuilder.Set(rangeParams)
}

func (builder *AddressStringFormatParamsBuilder) GetRangeParamsBuilder() RangeParams {
	return &builder.rangeParamsBuilder
}

func (builder *AddressStringFormatParamsBuilder) allowWildcardedSeparator(allow bool) {
	builder.noWildcardedSeparator = !allow
}

func (builder *AddressStringFormatParamsBuilder) allowLeadingZeros(allow bool) {
	builder.noLeadingZeros = !allow
}

func (builder *AddressStringFormatParamsBuilder) allowUnlimitedLeadingZeros(allow bool) {
	builder.noUnlimitedLeadingZeros = !allow
}
