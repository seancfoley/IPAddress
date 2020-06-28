package ipaddr

type RangeParameters struct {
	noWildcard, noValueRange, noReverseRange, noSingleWildcard, noInferredBoundary bool
}

// whether no wildcards or range characters allowed
func (rp *RangeParameters) IsNoRange() bool {
	return rp.noWildcard && rp.noValueRange && rp.noSingleWildcard
}

// whether '*' is allowed to denote segments covering all possible segment values
func (rp *RangeParameters) AllowsWildcard() bool {
	return !rp.noWildcard
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
func (rp *RangeParameters) AllowsRangeSeparator() bool {
	return !rp.noValueRange
}

// whether '-' (or the expected range separator for the address) is allowed to denote a range from higher to lower, like 10-1
func (rp *RangeParameters) AllowsReverseRange() bool {
	return !rp.noReverseRange
}

// whether a missing range value before or after a '-' is allowed to denote the mininum or maximum potential value
func (rp *RangeParameters) AllowsInferredBoundary() bool {
	return !rp.noInferredBoundary
}

// whether to allow a segment terminating with '_' characters, which represent any digit
func (rp *RangeParameters) AllowsSingleWildcard() bool {
	return !rp.noSingleWildcard
}

func NewRangeParameters(allowWildcard, allowValueRange, allowReverse, allowInferred, allowSingleWildcard bool) RangeParameters {
	return RangeParameters{
		noWildcard:         !allowWildcard,
		noValueRange:       !allowValueRange,
		noReverseRange:     !allowReverse,
		noSingleWildcard:   !allowInferred,
		noInferredBoundary: !allowSingleWildcard,
	}
}

//TODO builder pattern?  Maybe instead something simpler?  Can we have fields that are changeable and then they are not?
// Copyin is one option (ie they are changeable but then we make our own copy)
// Copying from Builder type is another (Builder fields are public, result are not)
// I think each sub-builder can just return a pointer to its cojntents, then when consstructing the final, a copy
/* ie

var subBuilder *SubBuilder = bla()
var sub *Sub = bla.build() // this var might even be a field, but as a pointer
result := R {
	Sub: *sub,
}
return result;
*/

//TODO need godocs comments for each param, copy over from Java

//TODO does addressStringParameters need to be private?  Not sure
//AddressStringFormatParameters is not private - should it be?  Not sure
//Once again, a golang thing that does not apply to Java.  Did  make these classes public in Java?  Yes.
// Should I do the same here?  Probably.  Why not?  But it does seem that the builder class in here is useless on its own.
// You need to access it from IPAddressStringParametersBuilder.  Still, is there any harm in makint it possible to store that pointer to that builder?  No.

type addressStringParameters struct {
	noAllowEmpty, noAllowAll, noAllowSingleSegment bool
}

func (params *addressStringParameters) AllowsEmpty() bool {
	return !params.noAllowEmpty
}

func (params *addressStringParameters) AllowsSingleSegment() bool {
	return !params.noAllowSingleSegment
}

func (params *addressStringParameters) AllowsAll() bool {
	return !params.noAllowAll
}

// AddressStringParametersBuilder builds an AddressStringParameters
type addressStringParametersBuilderBase struct {
	addressStringParameters
}

func (builder *addressStringParametersBuilderBase) allowEmpty(allow bool) {
	builder.noAllowEmpty = !allow
}

func (builder *addressStringParametersBuilderBase) allowAll(allow bool) {
	builder.noAllowAll = !allow
}

func (builder *addressStringParametersBuilderBase) allowSingleSegment(allow bool) {
	builder.noAllowSingleSegment = !allow
}

// AddressStringFormatParameters are parameters specific to a given address type or version that is supplied
type AddressStringFormatParameters struct {
	rp *RangeParameters

	noWildcardedSeparator, noLeadingZeros, noUnlimitedLeadingZeros bool
}

func (params *AddressStringFormatParameters) AllowsWildcardedSeparator() bool {
	return !params.noWildcardedSeparator
}

func (params *AddressStringFormatParameters) AllowsLeadingZeros() bool {
	return !params.noLeadingZeros
}

func (params *AddressStringFormatParameters) AllowsUnlimitedLeadingZeros() bool {
	return !params.noUnlimitedLeadingZeros
}

type AddressStringFormatParametersBuilder struct {
	//TODO maybe make this not anonymous, because why make things more confusing by putting AllowsUnlimitedLeadingZeros() in here?
	////Not sure if it adds anything.  Maybe  it does.
	// I guess it fulfills the equivalent of the default value constants onn the java side
	AddressStringFormatParameters
}

func (params *AddressStringFormatParametersBuilder) allowWildcardedSeparator(allow bool) {
	params.noWildcardedSeparator = !allow
}

func (params *AddressStringFormatParametersBuilder) allowLeadingZeros(allow bool) {
	params.noLeadingZeros = !allow
}

func (params *AddressStringFormatParametersBuilder) allowUnlimitedLeadingZeros(allow bool) {
	params.noUnlimitedLeadingZeros = !allow
}

func (params *AddressStringFormatParametersBuilder) setRangeParameters(rangeParams *RangeParameters) {
	params.rp = rangeParams
}

var defaultRangeParams RangeParameters

func (params *AddressStringFormatParametersBuilder) GetRangeParameters() *RangeParameters {
	if params.rp == nil {
		params.rp = &defaultRangeParams
	}
	return params.rp
}
