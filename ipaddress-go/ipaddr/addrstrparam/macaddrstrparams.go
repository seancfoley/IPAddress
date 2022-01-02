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

//func convertMACParams(orig MACAddressStringParams) *macAddressStringParameters {
//	if params, ok := orig.(*macAddressStringParameters); ok {
//		return params
//	}
//	origFormat := orig.GetFormatParams()
//	formatRange := origFormat.GetRangeParams()
//	paramsBuilder := MACAddressStringParamsBuilder{}
//	return paramsBuilder.
//		// general settings
//		SetPreferredLen(orig.MACAddressLen()).
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
//		GetFormatParamsBuilder().
//		AllowShortSegments(origFormat.AllowsShortSegments()).
//		AllowWildcardedSeparator(origFormat.AllowsWildcardedSeparator()).
//		AllowLeadingZeros(origFormat.AllowsLeadingZeros()).
//		AllowUnlimitedLeadingZeros(origFormat.AllowsUnlimitedLeadingZeros()).
//		//
//		// ranges
//		GetRangeParamsBuilder().
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

type MACAddressLen string

const (
	MAC48Len          MACAddressLen = "MAC48"
	EUI64Len          MACAddressLen = "EUI64"
	UnspecifiedMACLen MACAddressLen = ""
)

func CopyMACAddressStringParams(orig MACAddressStringParams) MACAddressStringParams {
	if p, ok := orig.(*macAddressStringParameters); ok {
		return p
	}
	return new(MACAddressStringParamsBuilder).Set(orig).ToParams()
}

//func DefaultMACAddressStringParams() MACAddressStringParams {
//	xxx use builder instead xxx
//	return &macAddressStringParameters{}
//}

type MACAddressStringParams interface {
	AddressStringParams

	GetPreferredLen() MACAddressLen
	AllowsDashed() bool
	AllowsSingleDashed() bool
	AllowsColonDelimited() bool
	AllowsDotted() bool
	AllowsSpaceDelimited() bool
	GetFormatParams() MACAddressStringFormatParams
}

var _ MACAddressStringParams = &macAddressStringParameters{}

type MACAddressStringFormatParams interface {
	AddressStringFormatParams

	AllowsShortSegments() bool
}

//var _ MACAddressStringFormatParams = &macAddressStringFormatParameters{}

// ipAddressStringParameters has parameters for parsing IP address strings
// They are immutable and must be constructed using an IPAddressStringParamsBuilder
type macAddressStringParameters struct {
	addressStringParameters
	formatParams macAddressStringFormatParameters

	noAllowDashed,
	noAllowSingleDashed,
	noAllowColonDelimited,
	noAllowDotted,
	noAllowSpaceDelimited bool
	allAddresses MACAddressLen
	//network      *MACAddressNetwork
}

func (params *macAddressStringParameters) GetPreferredLen() MACAddressLen {
	return params.allAddresses
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

func (params *macAddressStringParameters) GetFormatParams() MACAddressStringFormatParams {
	return &params.formatParams
}

// MACAddressStringParamsBuilder builds a MACAddressStringParameters
type MACAddressStringParamsBuilder struct {
	params macAddressStringParameters
	AddressStringParamsBuilder
	formatBuilder MACAddressStringFormatParamsBuilder
}

func (builder *MACAddressStringParamsBuilder) ToParams() MACAddressStringParams {
	// We do not return a pointer to builder.params because that would make it possible to change a macAddressStringParameters
	// by continuing to use the same builder,
	// and we want immutable objects for thread-safety,
	// so we cannot allow it
	result := builder.params
	result.addressStringParameters = *builder.AddressStringParamsBuilder.ToParams().(*addressStringParameters)
	result.formatParams = *builder.formatBuilder.ToParams().(*macAddressStringFormatParameters)
	return &result
}

func (builder *MACAddressStringParamsBuilder) GetFormatParamsBuilder() (result *MACAddressStringFormatParamsBuilder) {
	result = &builder.formatBuilder
	result.parent = builder
	return
}

func (builder *MACAddressStringParamsBuilder) Set(params MACAddressStringParams) *MACAddressStringParamsBuilder {
	//xxx
	//var result MACAddressStringParamsBuilder
	if p, ok := params.(*macAddressStringParameters); ok {
		builder.params = *p
	} else {
		builder.params = macAddressStringParameters{
			noAllowDashed:         !params.AllowsDashed(),
			noAllowSingleDashed:   !params.AllowsSingleDashed(),
			noAllowColonDelimited: !params.AllowsColonDelimited(),
			noAllowDotted:         !params.AllowsDotted(),
			noAllowSpaceDelimited: !params.AllowsSpaceDelimited(),
			allAddresses:          params.GetPreferredLen(),
		}
	}
	//builder.AddressStringParamsBuilder = *ToAddressStringParamsBuilder(params)
	//builder.formatBuilder = *ToMACAddressStringFormatParamsBuilder(params.GetFormatParams())
	builder.AddressStringParamsBuilder.set(params)
	builder.formatBuilder.Set(params.GetFormatParams())
	return builder
}

func (builder *MACAddressStringParamsBuilder) AllowEmpty(allow bool) *MACAddressStringParamsBuilder {
	builder.allowEmpty(allow)
	return builder
}

func (builder *MACAddressStringParamsBuilder) AllowSingleSegment(allow bool) *MACAddressStringParamsBuilder {
	builder.allowSingleSegment(allow)
	return builder
}

func (builder *MACAddressStringParamsBuilder) AllowAll(allow bool) *MACAddressStringParamsBuilder {
	builder.allowAll(allow)
	return builder
}

func (builder *MACAddressStringParamsBuilder) SetPreferredLen(size MACAddressLen) *MACAddressStringParamsBuilder {
	builder.params.allAddresses = size
	return builder
}

//func (builder *MACAddressStringParamsBuilder) SetNetwork(network *MACAddressNetwork) *MACAddressStringParamsBuilder {
//	builder.params.network = network
//	return builder
//}

func (builder *MACAddressStringParamsBuilder) AllowDashed(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowDashed = !allow
	return builder
}

func (builder *MACAddressStringParamsBuilder) AllowSingleDashed(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowSingleDashed = !allow
	return builder
}

func (builder *MACAddressStringParamsBuilder) AllowColonDelimited(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowColonDelimited = !allow
	return builder
}

func (builder *MACAddressStringParamsBuilder) AllowDotted(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowDotted = !allow
	return builder
}

func (builder *MACAddressStringParamsBuilder) AllowSpaceDelimited(allow bool) *MACAddressStringParamsBuilder {
	builder.params.noAllowSpaceDelimited = !allow
	return builder
}

// these two are just for convenience
func (builder *MACAddressStringParamsBuilder) AllowWildcardedSeparator(allow bool) *MACAddressStringParamsBuilder {
	builder.GetFormatParamsBuilder().AllowWildcardedSeparator(allow)
	return builder
}

func (builder *MACAddressStringParamsBuilder) SetRangeParams(rangeParams RangeParams) *MACAddressStringParamsBuilder {
	builder.GetFormatParamsBuilder().SetRangeParams(rangeParams)
	return builder
}

type macAddressStringFormatParameters struct {
	addressStringFormatParameters

	noShortSegments bool
}

func (params *macAddressStringFormatParameters) AllowsShortSegments() bool {
	return !params.noShortSegments
}

type MACAddressStringFormatParamsBuilder struct {
	// This is not anonymous since it clashes with AddressStringFormatParamsBuilder,
	// both have AddressStringFormatParams
	// AddressStringFormatParamsBuilder takes precedence
	params macAddressStringFormatParameters

	AddressStringFormatParamsBuilder

	parent *MACAddressStringParamsBuilder
}

func (builder *MACAddressStringFormatParamsBuilder) GetParentBuilder() *MACAddressStringParamsBuilder {
	return builder.parent
}

func (builder *MACAddressStringFormatParamsBuilder) ToParams() MACAddressStringFormatParams {
	result := &builder.params
	result.addressStringFormatParameters = *builder.AddressStringFormatParamsBuilder.ToParams().(*addressStringFormatParameters)
	return result
}

func (builder *MACAddressStringFormatParamsBuilder) GetRangeParamsBuilder() *RangeParamsBuilder {
	result := &builder.rangeParamsBuilder
	result.parent = builder
	return result
}

func (builder *MACAddressStringFormatParamsBuilder) Set(parms MACAddressStringFormatParams) *MACAddressStringFormatParamsBuilder {
	if p, ok := parms.(*macAddressStringFormatParameters); ok {
		builder.params = *p
	} else {
		builder.params = macAddressStringFormatParameters{
			noShortSegments: !parms.AllowsShortSegments(),
		}
	}
	builder.AddressStringFormatParamsBuilder.set(parms)
	return builder
}

func (builder *MACAddressStringFormatParamsBuilder) AllowWildcardedSeparator(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.allowWildcardedSeparator(allow)
	return builder
}

func (builder *MACAddressStringFormatParamsBuilder) AllowLeadingZeros(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.allowLeadingZeros(allow)
	return builder
}

func (builder *MACAddressStringFormatParamsBuilder) AllowUnlimitedLeadingZeros(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.allowUnlimitedLeadingZeros(allow)
	return builder
}

func (builder *MACAddressStringFormatParamsBuilder) SetRangeParams(rangeParams RangeParams) *MACAddressStringFormatParamsBuilder {
	builder.setRangeParameters(rangeParams)
	return builder
}

func (builder *MACAddressStringFormatParamsBuilder) AllowShortSegments(allow bool) *MACAddressStringFormatParamsBuilder {
	builder.params.noShortSegments = !allow
	return builder
}
