package ipaddr

import (
	"errors"
	"fmt"
	"strings"
)

//TODO at the end of the day, not so sure there is any reason to have my own interfaces, unless they had methods in addition to Error()
//and as far as I know they do not, although I could potentially expose the parsed string or the string index or both.
// Maybe I resurrect HostIdentifierException and use it everywhere?  Since I don't need separate errors?

type AddressStringException interface {
	error
}

type IncompatibleAddressException interface {
	error
}

type HostNameException interface {
	error

	GetAddrErr() AddressStringException //returns the underlying address error, or nil
}

type hostAddressErr struct {
	nested AddressStringException
}

func (a *hostAddressErr) GetAddrErr() AddressStringException {
	return a.nested
}

func (a *hostAddressErr) Error() string {
	//TODO i18n -
	return "ipaddress.host.error.invalid" + ": " + a.nested.Error()
}

//TODO split into two types, one without index nested inside other with index
// first step is to convert the err = followed by return into a method call that returns nil, err
// then you will have two of those, and you can then do the switcheroo in there
type hostNameException struct {
	// the string being parsed
	str,

	// key to look up the error message
	key string
}

type hostNameIndexErr struct {
	hostNameException

	// byte index location in string of the error
	index int
}

func (a *hostNameException) GetAddrErr() AddressStringException {
	return nil
}

func (a *hostNameException) Error() string {
	//TODO i18n -
	return a.key
}

// TODO not so sure I need another exception type, but at the same time, distinguishing between errors would be nice

type addressException struct {
	// key to look up the error message
	key string
}

func (a *addressException) Error() string {
	//TODO i18n -
	return a.key
}

type incompatibleAddressException struct {
	// the value
	str,

	// key to look up the error message
	key string
}

func (a *incompatibleAddressException) Error() string {
	//TODO i18n -
	return a.key
}

// TODO xxxxx think about replacing interfaces above with these xxxx

//TODO split into two types, one without index nested inside other with index
type addressStringException struct {
	// the string being parsed
	str,

	// key to look up the error message
	key string
}

func (a *addressStringException) Error() string {
	//TODO i18n -
	return a.key
}

type AddressValueException interface {
	error
}

type addressValueException struct {
	// the value
	val int

	// key to look up the error message
	key string
}

func (a *addressValueException) Error() string {
	//TODO i18n -
	return a.key
}

type addressPositionException struct {
	// the value
	val int

	// key to look up the error message
	key string
}

func (a *addressPositionException) Error() string {
	//TODO i18n -
	return a.key
}

type inconsistentPrefixException struct {
	str,

	// key to look up the error message
	key string
}

func (a *inconsistentPrefixException) Error() string {
	//TODO i18n -
	return a.key
}

type prefixLenException struct {
	prefixLen BitCount

	// key to look up the error message
	key string
}

func (a *prefixLenException) Error() string {
	//TODO i18n -
	return a.key
}

type addressStringIndexErr struct {
	addressStringException

	// byte index location in string of the error
	index int
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
