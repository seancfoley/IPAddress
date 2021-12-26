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

type MergedAddressError interface {
	AddressError
	GetMerged() AddressError
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
