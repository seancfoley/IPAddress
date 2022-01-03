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

package ipaddr

// ExtendedIdentifierString is a common interface for strings that identify hosts, namely IPAddressString, MACAddressString, and HostName
type ExtendedIdentifierString interface {
	HostIdentifierString

	// GetAddress returns the identified address or nil if none
	GetAddress() AddressType

	// GetAddress returns the identified address or an error
	ToAddress() (AddressType, error)

	// Unwrap returns the wrapped *IPAddressString, *MACAddressString or *HostName as an interface, HostIdentifierString
	Unwrap() HostIdentifierString
}

// WrappedIPAddressString wraps an IPAddressString to get an ExtendedIdentifierString
type WrappedIPAddressString struct {
	*IPAddressString
}

func (w WrappedIPAddressString) Unwrap() HostIdentifierString {
	res := w.IPAddressString
	if res == nil {
		return nil
	}
	return res
}

func (w WrappedIPAddressString) ToAddress() (AddressType, error) {
	return w.IPAddressString.ToAddress()
}

func (w WrappedIPAddressString) GetAddress() AddressType {
	return w.IPAddressString.GetAddress()
}

// WrappedMACAddressString wraps a MACAddressString to get an ExtendedIdentifierString
type WrappedMACAddressString struct {
	*MACAddressString
}

func (w WrappedMACAddressString) Unwrap() HostIdentifierString {
	res := w.MACAddressString
	if res == nil {
		return nil
	}
	return res
}

func (w WrappedMACAddressString) ToAddress() (AddressType, error) {
	return w.MACAddressString.ToAddress()
}

func (w WrappedMACAddressString) GetAddress() AddressType {
	return w.MACAddressString.GetAddress()
}

// WrappedIPAddressString wraps a HostName to get an ExtendedIdentifierString
type WrappedHostName struct {
	*HostName
}

func (w WrappedHostName) Unwrap() HostIdentifierString {
	res := w.HostName
	if res == nil {
		return nil
	}
	return res
}

func (w WrappedHostName) ToAddress() (AddressType, error) {
	return w.HostName.ToAddress()
}

func (w WrappedHostName) GetAddress() AddressType {
	return w.HostName.GetAddress()
}

var (
	_, _, _ ExtendedIdentifierString = WrappedIPAddressString{}, WrappedMACAddressString{}, WrappedHostName{}
)
