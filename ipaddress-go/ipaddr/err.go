package ipaddr

import (
	"errors"
	"fmt"
	"strings"
)

//TODO xxxx we need a strict hierarchy xxx
//all of which end at the same structure xxx
// Then we will create our own catalog from properties file,
// and it will be associated with "en" label and that will be the fallback,
// and then to print an error we will create a printer: func NewPrinter(t language.Tag, opts ...Option) *Printer {
// message.Catalog(xxxthatxxx) which returns an option to pass in to NewPrinter
//
// BUT let's face it, why bother?  Just copy the code to read in the file, either that catalog code or
// https://stackoverflow.com/questions/40022861/parsing-values-from-property-file-in-golang/46860900
// Just return the key from the errors so others can i18n if they want, they can use whatever method they prefer,
// all they need is the keys and the original file
//
// BUT... you do need a tool to create the index... why?  Because goland deals with binaries and you do not want to lug around a properties file
// So that's why they did it that way

//TODO add some dummy methods to X and x to ensure the hierarchy is enforced.  Since the interfaces have nothing in them, no way to know that right now.
/*

IPAddressException
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

type IPAddressException interface { //TODO rename to AddressException
	error
}

type ipAddressException struct {
	// key to look up the error message
	key string

	// the address
	str string
}

func (a *ipAddressException) Error() string {
	//TODO i18n -
	return a.key
}

type HostIdentifierException interface {
	IPAddressException
}

type AddressStringException interface {
	HostIdentifierException
}

type addressStringException struct {
	ipAddressException
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
	ipAddressException
}

func (a *hostNameException) GetAddrErr() AddressStringException {
	return nil
}

type hostAddressErr struct {
	hostNameException //TODO in this case, the nested has the key, so need to figure this out
	nested            AddressStringException
}

func (a *hostAddressErr) GetAddrErr() AddressStringException {
	return a.nested
}

func (a *hostAddressErr) Error() string {
	return "ipaddress.host.error.invalid" + ": " + a.nested.Error()
}

type hostNameIndexErr struct {
	hostNameException

	// byte index location in string of the error
	index int
}

type IncompatibleAddressException interface {
	IPAddressException
}

type incompatibleAddressException struct {
	ipAddressException
}

type SizeMismatchException interface {
	IncompatibleAddressException
}

type sizeMismatchException struct {
	incompatibleAddressException
}

type AddressValueException interface {
	error
}

type addressValueException struct {
	ipAddressException

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
