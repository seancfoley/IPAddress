package ipaddr

import (
	"fmt"
	"strings"
)

type HostIdentifierException interface { //TODO a new name, without "Exception", but not til later
	error
}

type AddressStringException interface { //TODO a new name, without "Exception", but not til later
	HostIdentifierException
}

type IncompatibleAddressException interface { //TODO a new name, without "Exception", but not til later
	error
}

//TODO split into two types, one without index nested inside other with index
type addressStringException struct {
	// the string being parsed
	str,

	// key to look up the error message
	key string

	// byte index location in string of the error
	index int
}

func (a *addressStringException) Error() string {
	//TODO i18n -
	return a.key
}

type err string

func (err err) Error() string {
	return string(err)
}

type wrappedErr struct {
	// root cause
	cause error

	// wrapper
	err err

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

// Errorf returns a formatted error
func Errorf(format string, a ...interface{}) err {
	return err(fmt.Sprintf(format, a...))
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
