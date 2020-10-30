package ipaddr

type AddressStringFormatParameters interface {
	AllowsWildcardedSeparator() bool
	AllowsLeadingZeros() bool
	AllowsUnlimitedLeadingZeros() bool

	// RangeParameters describes whether ranges of values are allowed
	GetRangeParameters() RangeParameters
}

type AddressStringParameters interface {
	AllowsEmpty() bool
	AllowsSingleSegment() bool
	AllowsAll() bool
}

type RangeParameters interface {
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

	// returns true if no wildcards or range separators allowed
	IsNoRange() bool
}

var _ AddressStringFormatParameters = &addressStringFormatParameters{}
var _ AddressStringParameters = &addressStringParameters{}
var _ RangeParameters = &rangeParameters{}

type rangeParameters struct {
	noWildcard, noValueRange, noReverseRange, noSingleWildcard, noInferredBoundary bool
}

var ( //TODO rename, these stay public but not all capitals, MixedCase instead
	NO_RANGE RangeParameters = &rangeParameters{
		noWildcard:         true,
		noValueRange:       true,
		noReverseRange:     true,
		noSingleWildcard:   true,
		noInferredBoundary: true,
	}

	// use this to support addresses like 1.*.3.4 or 1::*:3 or 1.2_.3.4 or 1::a__:3
	WILDCARD_ONLY RangeParameters = &rangeParameters{
		noValueRange:     true,
		noReverseRange:   true,
		noSingleWildcard: true,
	}

	// use this to support addresses supported by DEFAULT_WILDCARD_OPTIONS and also addresses like 1.2-3.3.4 or 1:0-ff::
	WILDCARD_AND_RANGE RangeParameters = &rangeParameters{}
)

// whether no wildcards or range characters allowed
func (rp *rangeParameters) IsNoRange() bool {
	return rp.noWildcard && rp.noValueRange && rp.noSingleWildcard
}

// whether '*' is allowed to denote segments covering all possible segment values
func (rp *rangeParameters) AllowsWildcard() bool {
	return !rp.noWildcard
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
func (rp *rangeParameters) AllowsRangeSeparator() bool {
	return !rp.noValueRange
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1
func (rp *rangeParameters) AllowsReverseRange() bool {
	return !rp.noReverseRange
}

// whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value
func (rp *rangeParameters) AllowsInferredBoundary() bool {
	return !rp.noInferredBoundary
}

// whether to allow a segment terminating with '_' characters, which represent any digit
func (rp *rangeParameters) AllowsSingleWildcard() bool {
	return !rp.noSingleWildcard
}

type RangeParametersBuilder struct {
	rangeParameters
	parent interface{}
}

func (params *RangeParametersBuilder) ToParams() RangeParameters {
	return &params.rangeParameters
}

func ToRangeParamsBuilder(rangeParams RangeParameters) *RangeParametersBuilder {
	if rp, ok := rangeParams.(*rangeParameters); ok {
		return &RangeParametersBuilder{rangeParameters: *rp}
	} else {
		return &RangeParametersBuilder{rangeParameters: rangeParameters{
			noWildcard:         !rangeParams.AllowsWildcard(),
			noValueRange:       !rangeParams.AllowsRangeSeparator(),
			noReverseRange:     !rangeParams.AllowsReverseRange(),
			noSingleWildcard:   !rangeParams.AllowsSingleWildcard(),
			noInferredBoundary: !rangeParams.AllowsInferredBoundary(),
		}}
	}
}

// If this builder was obtained by a call to IPv4AddressStringParametersBuilder.GetRangeParametersBuilder(), returns the IPv4AddressStringParametersBuilder
func (rp *RangeParametersBuilder) GetIPv4ParentBuilder() *IPv4AddressStringParametersBuilder {
	parent := rp.parent
	if p, ok := parent.(*IPv4AddressStringParametersBuilder); ok {
		return p
	}
	return nil
}

// If this builder was obtained by a call to IPv6AddressStringParametersBuilder.GetRangeParametersBuilder(), returns the IPv6AddressStringParametersBuilder
func (rp *RangeParametersBuilder) GetIPv6ParentBuilder() *IPv6AddressStringParametersBuilder {
	parent := rp.parent
	if p, ok := parent.(*IPv6AddressStringParametersBuilder); ok {
		return p
	}
	return nil
}

// whether '*' is allowed to denote segments covering all possible segment values
func (rp *RangeParametersBuilder) AllowWildcard(allow bool) *RangeParametersBuilder {
	rp.noWildcard = !allow
	return rp
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
func (rp *RangeParametersBuilder) AllowRangeSeparator(allow bool) *RangeParametersBuilder {
	rp.noValueRange = !allow
	return rp
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1
func (rp *RangeParametersBuilder) AllowReverseRange(allow bool) *RangeParametersBuilder {
	rp.noReverseRange = !allow
	return rp
}

// whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value
func (rp *RangeParametersBuilder) AllowInferredBoundary(allow bool) *RangeParametersBuilder {
	rp.noInferredBoundary = !allow
	return rp
}

// whether to allow a segment terminating with '_' characters, which represent any digit
func (rp *RangeParametersBuilder) AllowSingleWildcard(allow bool) *RangeParametersBuilder {
	rp.noSingleWildcard = !allow
	return rp
}

//TODO need godocs comments for each param, copy over from Java

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

// AddressStringParametersBuilder builds an AddressStringParameters
type AddressStringParametersBuilder struct { // TODO rename to BuilderBase to match Java
	addressStringParameters
}

func ToAddressStringParamsBuilder(params AddressStringParameters) *AddressStringParametersBuilder {
	var result AddressStringParametersBuilder
	if p, ok := params.(*addressStringParameters); ok {
		result.addressStringParameters = *p
	} else {
		result.addressStringParameters = addressStringParameters{
			noEmpty:         !params.AllowsEmpty(),
			noAll:           !params.AllowsAll(),
			noSingleSegment: !params.AllowsSingleSegment(),
		}
	}
	return &result
}

func (builder *AddressStringParametersBuilder) ToParams() AddressStringParameters {
	return &builder.addressStringParameters
}

func (builder *AddressStringParametersBuilder) allowEmpty(allow bool) {
	builder.noEmpty = !allow
}

func (builder *AddressStringParametersBuilder) allowAll(allow bool) {
	builder.noAll = !allow
}

func (builder *AddressStringParametersBuilder) allowSingleSegment(allow bool) {
	builder.noSingleSegment = !allow
}

//
//
// AddressStringFormatParameters are parameters specific to a given address type or version that is supplied
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

func (params *addressStringFormatParameters) GetRangeParameters() RangeParameters {
	return &params.rangeParams
}

//
//
// AddressStringFormatParamsBuilder creates parameters for parsing a specific address type or address version
type AddressStringFormatParamsBuilder struct {
	addressStringFormatParameters

	rangeParamsBuilder RangeParametersBuilder
}

func ToAddressStringFormatParamsBuilder(params AddressStringFormatParameters) *AddressStringFormatParamsBuilder {
	var result AddressStringFormatParamsBuilder
	if p, ok := params.(*addressStringFormatParameters); ok {
		result.addressStringFormatParameters = *p
	} else {
		result.addressStringFormatParameters = addressStringFormatParameters{
			noWildcardedSeparator:   !params.AllowsWildcardedSeparator(),
			noLeadingZeros:          !params.AllowsLeadingZeros(),
			noUnlimitedLeadingZeros: !params.AllowsUnlimitedLeadingZeros(),
		}
	}
	result.rangeParamsBuilder = *ToRangeParamsBuilder(params.GetRangeParameters())
	return &result
}

func (params *AddressStringFormatParamsBuilder) ToParams() AddressStringFormatParameters {
	result := &params.addressStringFormatParameters
	result.rangeParams = *params.rangeParamsBuilder.ToParams().(*rangeParameters)
	return result
}

func (params *AddressStringFormatParamsBuilder) setRangeParameters(rangeParams RangeParameters) {
	params.rangeParamsBuilder = *ToRangeParamsBuilder(rangeParams)
}

func (params *AddressStringFormatParamsBuilder) GetRangeParametersBuilder() RangeParameters {
	return &params.rangeParamsBuilder
}

func (params *AddressStringFormatParamsBuilder) allowWildcardedSeparator(allow bool) {
	params.noWildcardedSeparator = !allow
}

func (params *AddressStringFormatParamsBuilder) allowLeadingZeros(allow bool) {
	params.noLeadingZeros = !allow
}

func (params *AddressStringFormatParamsBuilder) allowUnlimitedLeadingZeros(allow bool) {
	params.noUnlimitedLeadingZeros = !allow
}
