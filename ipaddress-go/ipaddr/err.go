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
}

func (wrappedErr *wrappedErr) Error() string {
	return wrappedErr.err.Error() + ": " + wrappedErr.cause.Error()
}

// errorf returns a formatted error
func errorf(format string, a ...interface{}) err {
	return err(fmt.Sprintf(format, a...))
}

// wrapErrf wraps the given error, but only if it is not nil.
func wrapErrf(err error, format string, a ...interface{}) error {
	return wrapper(true, err, format, a...)
}

// wrapToErrf is like wrapErrf but always returns an error
func wrapToErrf(err error, format string, a ...interface{}) error {
	return wrapper(false, err, format, a...)
}

func wrapper(nilIfFirstNil bool, err error, format string, a ...interface{}) error {
	if err == nil {
		if nilIfFirstNil {
			return nil
		}
		return errorf(format, a...)
	}
	return &wrappedErr{
		cause: err,
		err:   errorf(format, a...),
	}
}

type mergedErr struct {
	merged []interface{}
	format string
}

func (merged *mergedErr) Error() string {
	return fmt.Sprintf(merged.format, merged.merged...)
}

// mergeErrs merges an existing error with a new one
func mergeErrs(err error, format string, a ...interface{}) error {
	newErr := errorf(format, a...)
	if err == nil {
		return newErr
	}
	if merge, isMergedErr := err.(*mergedErr); isMergedErr {
		merge.merged = append(merge.merged, newErr)
		merge.format += ", %s"
		return merge
	}
	return &mergedErr{merged: []interface{}{err, newErr}, format: "%s, %s"}
}

// mergeErrors merges multiple errors
func mergeAllErrs(errs ...error) error {
	var all []interface{}
	for _, err := range errs {
		if err != nil {
			if merge, isMergedErr := err.(*mergedErr); isMergedErr {
				all = append(all, merge.merged...)
			} else {
				all = append(all, err)
			}
		}
	}
	allLen := len(all)
	if allLen == 0 {
		return nil
	}
	if allLen == 1 {
		return all[0].(error)
	}
	format := strings.Builder{}
	format.Grow(allLen * 4)
	format.WriteString("%s")
	allLen--
	for ; allLen >= 10; allLen -= 10 {
		format.WriteString(tenMerges)
	}
	format.WriteString(tenMerges[:allLen*4])
	return &mergedErr{merged: all, format: format.String()}
}

const tenMerges = ", %s, %s, %s, %s, %s, %s, %s, %s, %s, %s"
