package ipaddr

import (
	"errors"
	"fmt"
	"strings"
)

//TODO add some dummy methods to X and x to ensure the hierarchy is enforced.  Since the interfaces have nothing in them, no way to know that right now.
/*

AddressException
	- IncompatibleAddressException
		- SizeMismatchException
	- HostIdentifierException
		- HostNameException
		- AddressStringException
	- AddressValueException
		- InconsistentPrefixException
		- AddressPositionException

unused:
NetworkMismatchException
AddressConversionException
PrefixLenException
*/

type AddressException interface {
	error

	// GetKey() allows users to implement their own i18n messages.
	// The keys and mappings are listed in IPAddressResources.properties,
	// so users of this library need only provide translations and implement
	// their own method if i18n, such as that at provided by golang.org/x/text
	GetKey() string
}

type addressException struct {
	// key to look up the error message
	key string

	// the address
	str string
}

func (a *addressException) Error() string {
	return lookupStr("ipaddress.address.error") + " " + lookupStr(a.key)
}

func (a *addressException) GetKey() string {
	return a.key
}

type HostIdentifierException interface {
	AddressException
}

type AddressStringException interface {
	HostIdentifierException
}

type addressStringException struct {
	addressException
}

type addressStringNestedErr struct {
	addressException
	nested AddressStringException
}

func (a *addressStringNestedErr) Error() string {
	return a.addressException.Error() + ": " + a.nested.Error()
}

type addressStringIndexErr struct {
	addressStringException

	// byte index location in string of the error
	index int
}

type HostNameException interface {
	HostIdentifierException

	GetAddrErr() AddressStringException //returns the underlying address error, or nil
}

type hostNameException struct {
	addressException
}

func (a *hostNameException) GetAddrErr() AddressStringException {
	return nil
}

func (a *hostNameException) Error() string {
	return lookupStr("ipaddress.host.error") + " " + lookupStr(a.key)
}

type hostNameNestedException struct {
	hostNameException
	nested error
}

type hostAddressNestedErr struct {
	hostNameException
	nested AddressStringException
}

func (a *hostAddressNestedErr) GetAddrErr() AddressStringException {
	return a.nested
}

func (a *hostAddressNestedErr) Error() string {
	return lookupStr("ipaddress.host.error") + " " + a.nested.Error()
}

type hostNameIndexErr struct {
	hostNameException

	// byte index location in string of the error
	index int
}

type IncompatibleAddressException interface {
	AddressException
}

type incompatibleAddressException struct {
	addressException
}

type SizeMismatchException interface {
	IncompatibleAddressException
}

type sizeMismatchException struct {
	incompatibleAddressException
}

type AddressValueException interface {
	AddressException
}

type addressValueException struct {
	addressException

	// the value
	val int
}

type addressPositionException struct {
	addressValueException
}

type inconsistentPrefixException struct {
	addressValueException
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
