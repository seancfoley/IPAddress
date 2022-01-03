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

package addrerr

/*
Error hierarchy:

AddressError
	-IncompatibleAddressError
		- SizeMismatchError
	- HostIdentifierError
		- HostNameError
		- AddressStringError
	- AddressValueError

unused:
NetworkMismatchException
InconsistentPrefixException
AddressPositionException
AddressConversionException
PrefixLenException
*/

type AddressError interface {
	error

	// GetKey() allows users to implement their own i18n error messages.
	// The keys and mappings are listed in IPAddressResources.properties,
	// so users of this library need only provide translations and implement
	// their own method of i18n to incorporate those translations,
	// such as the method provided by golang.org/x/text
	GetKey() string
}

type HostIdentifierError interface {
	AddressError
}

type AddressStringError interface {
	HostIdentifierError
}

type HostNameError interface {
	HostIdentifierError

	GetAddrError() AddressError //returns the underlying address error, or nil
}

type IncompatibleAddressError interface {
	AddressError
}

type SizeMismatchError interface {
	IncompatibleAddressError
}

type PositionMismatchError interface {
	IncompatibleAddressError
}

type AddressValueError interface {
	AddressError
}
