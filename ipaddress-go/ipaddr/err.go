package ipaddr

import (
	"errors"
	"fmt"
	"strings"
)

/*
Error hierarchy:

AddressError
	- IncompatibleAddressError
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

	// GetKey() allows users to implement their own i18n messages.
	// The keys and mappings are listed in IPAddressResources.properties,
	// so users of this library need only provide translations and implement
	// their own method if i18n, such as that at provided by golang.org/x/text
	GetKey() string
}

type addressError struct {
	// key to look up the error message
	key string

	// the address
	str string
}

func (a *addressError) Error() string {
	return lookupStr("ipaddress.address.error") + " " + lookupStr(a.key)
}

// GetKey can be used to internationalize the error strings in the IPAddress library.
// The list of keys and their English translations are listed in IPAddressResources.properties.
// Use your own preferred method to map the key to your own translations.
// One such option is golang.org/x/text which provides language tags (https://pkg.go.dev/golang.org/x/text/language?utm_source=godoc#Tag),
// which can then be mapped to catalogs, each catalog a list of translations for the set of keys provided here.
// You can use the gotext tool to integrate those translations with your application.
func (a *addressError) GetKey() string {
	return a.key
}

type HostIdentifierError interface {
	AddressError
}

type AddressStringError interface {
	HostIdentifierError
}

type addressStringError struct {
	addressError
}

type addressStringNestedError struct {
	addressStringError
	nested AddressStringError
}

func (a *addressStringNestedError) Error() string {
	return a.addressError.Error() + ": " + a.nested.Error()
}

type addressStringIndexError struct {
	addressStringError

	// byte index location in string of the error
	index int
}

type HostNameError interface {
	HostIdentifierError

	GetAddrError() AddressError //returns the underlying address error, or nil
}

type hostNameError struct {
	addressError
}

func (a *hostNameError) GetAddrError() AddressError {
	return nil
}

func (a *hostNameError) Error() string {
	return lookupStr("ipaddress.host.error") + " " + lookupStr(a.key)
}

type hostNameNestedError struct {
	hostNameError
	nested error
}

type hostAddressNestedError struct {
	hostNameError
	nested AddressError
}

func (a *hostAddressNestedError) GetAddrError() AddressError {
	return a.nested
}

func (a *hostAddressNestedError) Error() string {
	return lookupStr("ipaddress.host.error") + " " + a.nested.Error()
}

type hostNameIndexError struct {
	hostNameError

	// byte index location in string of the error
	index int
}

type IncompatibleAddressError interface {
	AddressError
}

type incompatibleAddressError struct {
	addressError
}

type SizeMismatchError interface {
	IncompatibleAddressError
}

type sizeMismatchError struct {
	incompatibleAddressError
}

type AddressValueError interface {
	AddressError
}

type addressValueError struct {
	addressError

	// the value
	val int
}

type addressPositionError struct {
	addressValueError
}

type inconsistentPrefixError struct {
	addressValueError
}

///////////////////////////////////////////////

type wrappedErr struct {
	// root cause
	cause error

	// wrapper
	err error

	str string
}

func (wrappedErr *wrappedErr) Error() string {
	str := wrappedErr.str
	if len(str) > 0 {
		return str
	}
	str = wrappedErr.err.Error() + ": " + wrappedErr.cause.Error()
	wrappedErr.str = str
	return str
}

func newError(str string) error {
	return errors.New(str)
}

// Errorf returns a formatted error
func Errorf(format string, a ...interface{}) error {
	return errors.New(fmt.Sprintf(format, a...))
}

// WrapErrf wraps the given error, but only if it is not nil.
func WrapErrf(err error, format string, a ...interface{}) error {
	return wrapper(true, err, format, a...)
}

// WrapToErrf is like wrapErrf but always returns an error
func WrapToErrf(err error, format string, a ...interface{}) error {
	return wrapper(false, err, format, a...)
}

func wrapper(nilIfFirstNil bool, err error, format string, a ...interface{}) error {
	if err == nil {
		if nilIfFirstNil {
			return nil
		}
		return Errorf(format, a...)
	}
	return &wrappedErr{
		cause: err,
		err:   Errorf(format, a...),
	}
}

type mergedErr struct {
	mergedErrs []error
	str        string
}

func (merged *mergedErr) Error() (str string) {
	str = merged.str
	if len(str) > 0 {
		return
	}
	mergedErrs := merged.mergedErrs
	errLen := len(mergedErrs)
	strs := make([]string, errLen)
	totalLen := 0
	for i, err := range mergedErrs {
		str := err.Error()
		strs[i] = str
		totalLen += len(str)
	}
	format := strings.Builder{}
	format.Grow(totalLen + errLen*2)
	format.WriteString(strs[0])
	for _, str := range strs[1:] {
		format.WriteString(", ")
		format.WriteString(str)
	}
	str = format.String()
	merged.str = str
	return
}

// mergeErrs merges an existing error with a new one
func MergeErrs(err error, format string, a ...interface{}) error {
	newErr := Errorf(format, a...)
	if err == nil {
		return newErr
	}
	var merged []error
	if merge, isMergedErr := err.(*mergedErr); isMergedErr {
		merged = append(append([]error(nil), merge.mergedErrs...), newErr)
	} else {
		merged = []error{err, newErr}
	}
	return &mergedErr{mergedErrs: merged}
}

// mergeErrors merges multiple errors
func MergeAllErrs(errs ...error) error {
	var all []error
	allLen := len(errs)
	if allLen <= 1 {
		if allLen == 0 {
			return nil
		}
		return errs[0]
	}
	for _, err := range errs {
		if err != nil {
			if merge, isMergedErr := err.(*mergedErr); isMergedErr {
				all = append(all, merge.mergedErrs...)
			} else {
				all = append(all, err)
			}
		}
	}
	allLen = len(all)
	if allLen <= 1 {
		if allLen == 0 {
			return nil
		}
		return all[0]
	}
	return &mergedErr{mergedErrs: all}
}
