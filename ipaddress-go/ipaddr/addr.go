package ipaddr

import "unsafe"

const (
	HexPrefix                  = "0x"
	OctalPrefix                = "0"
	RangeSeparator             = '-'
	AlternativeRangeSeparator  = '\u00bb'
	SegmentWildcard            = '*'
	AlternativeSegmentWildcard = '¿'
	SegmentSqlWildcard         = '%'
	SegmentSqlSingleWildcard   = '_'
)

//
//
//
type Address struct {
	section AddressSection
	zone    string
}

func (addr *Address) getBytes() []byte {
	return addr.section.getBytes()
}

func (addr *Address) hasNoDivisions() bool {
	return addr.section.hasNilDivisions()
}

func (addr *Address) ToIPAddress() *IPAddress {
	if addr == nil {
		return nil
	}
	if addr.section.matchesIPv4Address() || addr.section.matchesIPv6Address() {
		return (*IPAddress)(unsafe.Pointer(addr))
	}
	return nil
}

func (addr *Address) ToIPv6Address() *IPv6Address {
	if addr == nil {
		return nil
	}
	if addr.section.matchesIPv6Address() {
		return (*IPv6Address)(unsafe.Pointer(addr))
	}
	return nil
}

func (addr *Address) ToIPv4Address() *IPv4Address {
	if addr == nil {
		return nil
	}
	if addr.section.matchesIPv4Address() {
		return (*IPv4Address)(unsafe.Pointer(addr))
	}
	return nil
}

type addressInternal struct {
	Address
}

// EARLIER THOUGHTS, JUST KEEPING THEM AROUND IN CASE I FORGET THE REASONING,
// but now we decided to use pointers to IPAddress and not zero values with no pointers, pretty well everywhere
// One breakthrugh was realizing you could scale up and down using unsafe.Pointer, avoiding copying
// But we also decided we would make copying possible without losing cache values, by assigning a cache object on creation and pointing to it
// The rest would be immutable stuff

//xxx do we want to be like string, where the nil is an actual string? xxxx
//xxx a nil address? xxx
//xxx or like slice, which has a nil xxx
//xxxx I have already decided with the ToXXX() I would default to zero values xxxx
//xxxx maybe we do that everywhere?  Here too?
//xxxx toughie question
//xxxx time to answer it
//xxxx Well, even slice does not resort to pointers
//xxxx And I am not doing that in my address methods, am I?
//xxxx As a test, I should what happens with this:
/*
			package main

	import (
		"fmt"
		"reflect"
		"unsafe"
	)

	func main() {
		doit()
	}

	type Foo struct {
		x int
	}

	type FooInternal struct {
		Foo
	}

	type Bla struct {
		FooInternal
	}

	func doit() {
		var foo *Foo = &Foo{}
		foo.x = 4
		var bla *Bla = &Bla{FooInternal{*foo}} //creates a new pointer

		//var blaIllegal *Bla = (*Bla)(foo) // cannot convert foo (type *Foo) to type *Bla

		fmt.Printf("%p %p\n", foo, bla)

		fmt.Printf("%p %p\n", foo, &bla.Foo)

		blaLegal := (*Bla)(unsafe.Pointer(foo))
		fmt.Printf("%p %p %p %d\n", foo, blaLegal, &blaLegal.Foo, blaLegal.x)

		// 0xc000094010 0xc000094018
		// 0xc000094010 0xc000094018
		// 0xc000094010 0xc000094010 0xc000094010 4

		typ := reflect.TypeOf(Bla{})
		showType(typ)

		typ = reflect.TypeOf(FooInternal{})
		showType(typ)

		typ = reflect.TypeOf(Foo{})
		showType(typ)
	}

	func showType(typ reflect.Type) {
		fmt.Printf("Struct is %d bytes long\n", typ.Size())
		// We can run through the fields in the structure in order
		n := typ.NumField()
		for i := 0; i < n; i++ {
			field := typ.Field(i)
			fmt.Printf("%s at offset %v, size=%d, align=%d\n",
				field.Name, field.Offset, field.Type.Size(),
				field.Type.Align())
		}
	}
*/
//xxx OK, so that means, if you have a pointer receiver, there is no way to upscale and end up with the same pointer
//xxx So let us stick to avoiding pointers
//xxx Now, back to here
//xxx Does it make sense to use a pointer as a stand-in to mean "no address"
//xxx or should we use zero values?
//xxx I am starting to think perhaps a nil value would do here on these three
//xxx and then, what about the mask?  Pointer?
//Actually, maybe pointer, because in many ways it makes little sense that a parsing results in a zero value
//Or does it?
//OK, I think I like the way mask is done, it is like PrefixLen
//And I think maybe these should remain as is
//
// OK no, I think zero value should not be used in random situations
// And in fact why did we use it?  TO avoid an error.
// We do not have that here.
// SO just use a pointer.
