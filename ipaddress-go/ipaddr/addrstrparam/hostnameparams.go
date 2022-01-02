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

//func convertHostParams(orig HostNameParams) *hostNameParameters {
//	if params, ok := orig.(*hostNameParameters); ok {
//		return params
//	}
//
//	paramsBuilder := HostNameParamsBuilder{}
//	return paramsBuilder.
//		// general settings
//		AllowIPAddress(orig.AllowsIPAddress()).
//		AllowBracketedIPv6(orig.AllowsBracketedIPv6()).
//		AllowBracketedIPv4(orig.AllowsBracketedIPv4()).
//		SetEmptyLoopback(orig.EmptyIsLoopback()).
//		AllowPort(orig.AllowsPort()).
//		AllowService(orig.AllowsService()).
//		ExpectPort(orig.ExpectsPort()).
//		AllowEmpty(orig.AllowsEmpty()).
//		NormalizeToLowercase(orig.NormalizesToLowercase()).
//		SetIPAddressParams(orig.GetIPAddressParams()).
//		//
//		ToParams().(*hostNameParameters)
//}

func CopyHostNameParams(orig HostNameParams) HostNameParams {
	if p, ok := orig.(*hostNameParameters); ok {
		return p
	}
	return new(HostNameParamsBuilder).Set(orig).ToParams()
}

//func DefaultHostNameParams() HostNameParams {
//	xxx use builder instead xxx
//	return &hostNameParameters{}
//}

type HostNameParams interface {
	// AllowsEmpty determines if an empty host string, when not a valid address, is considered valid.
	// The parser will first parse as an empty address, if allowed by the nested IPAddressStringParams.
	// Otherwise, it will be considered an empty host if this returns true, or an invalid host if it returns false.
	AllowsEmpty() bool

	//xxxx gotta defer to address on this xxx
	//EmptyStrParsedAs() EmptyStrOption

	// Indicates the version to prefer when resolving host names.
	GetPreferredVersion() IPVersion

	//EmptyIsLoopback() bool
	AllowsBracketedIPv4() bool
	AllowsBracketedIPv6() bool
	NormalizesToLowercase() bool
	AllowsIPAddress() bool
	AllowsPort() bool
	AllowsService() bool
	ExpectsPort() bool

	GetIPAddressParams() IPAddressStringParams

	//ToAddressOptionsBuilder() IPAddressStringParamsBuilder
}

// hostNameParameters has parameters for parsing IP address strings
// They are immutable and can be constructed using an HostNameParamsBuilder
type hostNameParameters struct {
	ipParams ipAddressStringParameters

	//emptyStringOption EmptyStrOption

	preferredVersion IPVersion

	noEmpty, noBracketedIPv4, noBracketedIPv6,
	noNormalizeToLower, noIPAddress, noPort, noService, expectPort bool
}

//func (params *hostNameParameters) ToAddressOptionsBuilder() IPAddressStringParamsBuilder {xxx no longer use this xxxx
//	return params.ipParams.ToBuilder()
//}

func (params *hostNameParameters) AllowsEmpty() bool {
	return !params.noEmpty
}

//func (params *hostNameParameters) EmptyStrParsedAs() EmptyStrOption {
//	return params.emptyStringOption
//}

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

//func (params *hostNameParameters) ToAddressOptionsBuilder() IPAddressStringParamsBuilder {xxx no longer use this xxxx
//	return params.ipParams.ToBuilder()
//}

//func ToIPAddressParametersBuilder(params HostNameParams) *IPAddressStringParamsBuilder {
//	return ToIPAddressStringParamsBuilder(params.GetIPAddressParams())
//}

//func ToHostNameParametersBuilder(params HostNameParams) *HostNameParamsBuilder {
//	var result HostNameParamsBuilder
//	if p, ok := params.(*hostNameParameters); ok {
//		result.hostNameParameters = *p
//	} else {
//		result.hostNameParameters = hostNameParameters{
//			emptyStringOption:  params.EmptyStrParsedAs(),
//			preferredVersion:   params.GetPreferredVersion(),
//			noEmpty:            !params.AllowsEmpty(),
//			noBracketedIPv4:    !params.AllowsBracketedIPv4(),
//			noBracketedIPv6:    !params.AllowsBracketedIPv6(),
//			noNormalizeToLower: !params.NormalizesToLowercase(),
//			noIPAddress:        !params.AllowsIPAddress(),
//			noPort:             !params.AllowsPort(),
//			noService:          !params.AllowsService(),
//			expectPort:         params.ExpectsPort(),
//		}
//	}
//	result.SetIPAddressParams(params.GetIPAddressParams())
//	return &result
//}

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
	//var result HostNameParamsBuilder
	if p, ok := params.(*hostNameParameters); ok {
		builder.hostNameParameters = *p
	} else {
		builder.hostNameParameters = hostNameParameters{
			//emptyStringOption:  params.EmptyStrParsedAs(),
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

//func (builder *HostNameParamsBuilder) SetEmptyLoopback(isLoopback bool) *HostNameParamsBuilder {
//	builder.hostNameParameters.emptyIsNotLoopback = !isLoopback
//	return builder
//}
//
//func (builder *HostNameParamsBuilder) ParseEmptyStrAs(option EmptyStrOption) *HostNameParamsBuilder {
//	builder.hostNameParameters.emptyStringOption = option
//	if option != NoAddressOption {
//		builder.AllowEmpty(true)
//	}
//	return builder
//}

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
