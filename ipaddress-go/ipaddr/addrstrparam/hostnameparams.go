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

package addrstrparam

// CopyHostNameParams produces an immutable copy of the original HostNameParams.
func CopyHostNameParams(orig HostNameParams) HostNameParams {
	if p, ok := orig.(*hostNameParameters); ok {
		return p
	}
	return new(HostNameParamsBuilder).Set(orig).ToParams()
}

// HostNameParams provides parameters for parsing host name strings
type HostNameParams interface {
	// AllowsEmpty determines if an empty host string, when not a valid address, is considered valid.
	// The parser will first parse as an empty address, if allowed by the nested IPAddressStringParams.
	// Otherwise, it will be considered an empty host if this returns true, or an invalid host if it returns false.
	AllowsEmpty() bool

	// Indicates the version to prefer when resolving host names.
	GetPreferredVersion() IPVersion

	AllowsBracketedIPv4() bool
	AllowsBracketedIPv6() bool
	NormalizesToLowercase() bool
	AllowsIPAddress() bool
	AllowsPort() bool
	AllowsService() bool
	ExpectsPort() bool

	GetIPAddressParams() IPAddressStringParams
}

// hostNameParameters has parameters for parsing host name strings
// They are immutable and can be constructed using an HostNameParamsBuilder
type hostNameParameters struct {
	ipParams ipAddressStringParameters

	preferredVersion IPVersion

	noEmpty, noBracketedIPv4, noBracketedIPv6,
	noNormalizeToLower, noIPAddress, noPort, noService, expectPort bool
}

func (params *hostNameParameters) AllowsEmpty() bool {
	return !params.noEmpty
}

func (params *hostNameParameters) GetPreferredVersion() IPVersion {
	return params.preferredVersion
}

func (params *hostNameParameters) AllowsBracketedIPv4() bool {
	return !params.noBracketedIPv4
}

func (params *hostNameParameters) AllowsBracketedIPv6() bool {
	return !params.noBracketedIPv6
}

func (params *hostNameParameters) NormalizesToLowercase() bool {
	return !params.noNormalizeToLower
}

func (params *hostNameParameters) AllowsIPAddress() bool {
	return !params.noIPAddress
}

func (params *hostNameParameters) AllowsPort() bool {
	return !params.noPort
}

func (params *hostNameParameters) AllowsService() bool {
	return !params.noService
}

func (params *hostNameParameters) ExpectsPort() bool {
	return params.expectPort
}

func (params *hostNameParameters) GetIPAddressParams() IPAddressStringParams {
	return &params.ipParams
}

// HostNameParamsBuilder builds a HostNameParams
type HostNameParamsBuilder struct {
	hostNameParameters

	ipAddressBuilder IPAddressStringParamsBuilder
}

func (builder *HostNameParamsBuilder) ToParams() HostNameParams {
	// We do not return a pointer to builder.params because that would make it possible to change a ipAddressStringParameters
	// by continuing to use the same builder,
	// and we want immutable objects for thread-safety,
	// so we cannot allow it
	result := builder.hostNameParameters
	result.ipParams = *builder.ipAddressBuilder.ToParams().(*ipAddressStringParameters)
	return &result
}

func (builder *HostNameParamsBuilder) GetIPAddressParamsBuilder() (result *IPAddressStringParamsBuilder) {
	result = &builder.ipAddressBuilder
	result.parent = builder
	return
}

func (builder *HostNameParamsBuilder) Set(params HostNameParams) *HostNameParamsBuilder {
	if p, ok := params.(*hostNameParameters); ok {
		builder.hostNameParameters = *p
	} else {
		builder.hostNameParameters = hostNameParameters{
			preferredVersion:   params.GetPreferredVersion(),
			noEmpty:            !params.AllowsEmpty(),
			noBracketedIPv4:    !params.AllowsBracketedIPv4(),
			noBracketedIPv6:    !params.AllowsBracketedIPv6(),
			noNormalizeToLower: !params.NormalizesToLowercase(),
			noIPAddress:        !params.AllowsIPAddress(),
			noPort:             !params.AllowsPort(),
			noService:          !params.AllowsService(),
			expectPort:         params.ExpectsPort(),
		}
	}
	builder.SetIPAddressParams(params.GetIPAddressParams())
	return builder
}

func (builder *HostNameParamsBuilder) SetIPAddressParams(params IPAddressStringParams) *HostNameParamsBuilder {
	//builder.ipAddressBuilder = *ToIPAddressStringParamsBuilder(params)
	builder.ipAddressBuilder.Set(params)
	return builder
}

func (builder *HostNameParamsBuilder) AllowEmpty(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noEmpty = !allow
	return builder
}

func (builder *HostNameParamsBuilder) SetPreferredVersion(version IPVersion) *HostNameParamsBuilder {
	builder.hostNameParameters.preferredVersion = version
	return builder
}

func (builder *HostNameParamsBuilder) AllowBracketedIPv4(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noBracketedIPv4 = !allow
	return builder
}

func (builder *HostNameParamsBuilder) AllowBracketedIPv6(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noBracketedIPv6 = !allow
	return builder
}

func (builder *HostNameParamsBuilder) NormalizeToLowercase(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noNormalizeToLower = !allow
	return builder
}

func (builder *HostNameParamsBuilder) AllowIPAddress(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noIPAddress = !allow
	return builder
}

func (builder *HostNameParamsBuilder) AllowPort(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noPort = !allow
	return builder
}

func (builder *HostNameParamsBuilder) AllowService(allow bool) *HostNameParamsBuilder {
	builder.hostNameParameters.noService = !allow
	return builder
}

func (builder *HostNameParamsBuilder) ExpectPort(expect bool) *HostNameParamsBuilder {
	builder.hostNameParameters.expectPort = expect
	return builder
}
