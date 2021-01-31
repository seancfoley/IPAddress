package main

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"net"

	//ip_addr_old "github.com/seancfoley/ipaddress/ipaddress-go/ipaddrold"
	//"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"

	//"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
)

func main() {
	//ipaddr.Test()

	//ipaddr.divFunc(nil)
	seg := ipaddr.IPv4AddressSegment{} //TODO Can we prevent this?  Possibly if we do copying when switching back and forth IPv6, or maybe we can have a default value?
	//According to this you can make the thing not exported and yet still have access to it?  https://stackoverflow.com/questions/37135193/how-to-set-default-values-in-go-structs
	//But then you have to write up all those methods
	//I guess the only solution is to use non-pointer
	//The rule is that WHENEVER you are inheriting a method, it must be a non-pointer.
	//If you have an interface field, in which case you are inheriting those methods but you must assign to the interface fro the methods to work,
	//then you must also override each such method

	seg.GetSegmentValue()

	//seg.getSplitSegments()
	//fmt.Printf("\n%v\n", seg.getDivisionValue())
	//fmt.Printf("%v\n", seg.GetSegmentValue())
	fmt.Printf("%v\n", seg.GetBitCount())
	fmt.Printf("%v\n", seg.GetByteCount())

	grouping := ipaddr.IPv4AddressSection{}
	grouping.GetSegmentCount()
	//grouping.hasNoDivisions()

	builder := ipaddr.IPAddressStringParametersBuilder{}
	params := builder.AllowAll(false).ToParams()
	fmt.Printf("%+v\n", params)

	//params := ipaddr.ipAddressStringParameters{}
	////fmt.Printf("%+v\n", params)
	//init := ipaddr.IPAddressStringParametersBuilder{}
	//params2 := init.AllowAll(false).ToParams()
	//params = *params2
	//_ = params
	////fmt.Printf("%+v\n", params)

	i := -1
	var b byte = byte(i)
	fmt.Printf("byte is %+v\n", b)

	var slc []int
	fmt.Printf("%+v\n", slc) // expecting []
	fmt.Printf("%v\n", slc)  // expecting []
	fmt.Printf("%s\n", slc)  // expecting []

	addr := ipaddr.IPv6Address{}
	fmt.Printf("%+v\n", addr)
	fmt.Printf("%+v\n", &addr)

	addr4 := ipaddr.IPv4Address{}
	fmt.Printf("%+v\n", addr4)
	addr2 := addr4.ToIPAddress()
	fmt.Printf("%+v\n", addr2)
	//fmt.Printf("%+v\n", &addr2)

	ipv4Prefixed := addr4.ToPrefixBlockLen(16)
	fmt.Printf("16 block is %+v\n", ipv4Prefixed)
	fmt.Printf("lower is %+v\n", ipv4Prefixed.GetLower())
	fmt.Printf("upper is %+v\n", ipv4Prefixed.GetUpper())
	fmt.Printf("lower is %+v\n", ipv4Prefixed.GetLower())
	fmt.Printf("upper is %+v\n", ipv4Prefixed.GetUpper())

	addr5 := ipaddr.IPAddress{} // expecting []
	fmt.Printf("%+v\n", addr5)
	addr5Upper := addr5.GetUpper()
	fmt.Printf("%+v\n", addr5Upper) // expecting []
	addr6 := addr5Upper.ToIPv4Address()
	fmt.Printf("%+v\n", addr6) // expecting <nil>

	addrSection := ipaddr.AddressSection{}
	fmt.Printf("%+v\n", addrSection) // expecting []

	ipAddrSection := ipaddr.IPAddressSection{}
	fmt.Printf("%+v\n", ipAddrSection) // expecting []

	ipv4AddrSection := ipaddr.IPv4AddressSection{}
	fmt.Printf("%+v\n", ipv4AddrSection) // expecting []

	//addrStr := ipaddr.IPAddressString{}
	addrStr := ipaddr.NewIPAddressString("1.2.3.4", nil)
	pAddr := addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	ipv4Prefixed2 := pAddr.ToPrefixBlockLen(19)
	fmt.Printf("19 block is %+v\n", ipv4Prefixed2)

	addrStr = ipaddr.NewIPAddressString("a:b:c:d:e:f:a:b", nil)
	pAddr = addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	addrStr = ipaddr.NewIPAddressString("a:b:c:d:e:f:a:b%eth0", nil)
	pAddr = addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	addrStr = ipaddr.NewIPAddressString("a:b:c:d:e:f:1.2.3.4", nil)
	pAddr = addrStr.GetAddress()
	fmt.Printf("%+v\n", *pAddr)
	fmt.Printf("%+v\n", pAddr)

	ipv4Addr, _ := ipaddr.NewIPv4AddressFromIP([]byte{1, 0, 1, 0})
	fmt.Printf("%+v\n", ipv4Addr)
	fmt.Printf("%+v\n", *ipv4Addr)

	ipv4Addr, ipv4Err := ipaddr.NewIPv4AddressFromIP([]byte{1, 1, 0, 1, 0})
	fmt.Printf("%+v %+v\n", ipv4Addr, ipv4Err)

	ipv6Addr, ipv6Err := ipaddr.NewIPv6AddressFromIP(net.IP{1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc, 1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc})
	fmt.Printf("%+v %+v\n", ipv6Addr, ipv6Err)
	fmt.Printf("%+v\n", *ipv6Addr)

	ipv6Prefixed := ipv6Addr.ToPrefixBlockLen(32)
	fmt.Printf("32 block is %+v\n", ipv6Prefixed)
	ipv6Prefixed = ipv6Addr.ToPrefixBlockLen(40)
	fmt.Printf("40 block is %+v\n", ipv6Prefixed)

	addrDown := ipv6Prefixed.ToAddress()
	fmt.Printf("addr down converted 40 block is %+v\n", addrDown)

	addrUp := addrDown.ToIPv6Address()
	fmt.Printf("addr up converted 40 block is %+v\n", addrUp)

	addrUpNil := addrDown.ToIPv4Address()
	fmt.Printf("addr up converted nil is %+v\n", addrUpNil)

	//ip := net.IP{1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc, 1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc}
	//foo(ip)
	//foo2(ip)
	//foo3(net.IPAddr{IP: ip})

	//bytes := []byte{1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc, 1, 0, 1, 0, 0xff, 0xa, 0xb, 0xc}
	//foo(bytes)
	//foo2(bytes)
	//foo3(net.IPAddr{IP: bytes})

	_ = getDoc()
}

//func foo(bytes []byte) {
//	fmt.Printf("%v\n", bytes)
//}
//func foo2(bytes net.IP) {
//	fmt.Printf("%v\n", bytes)
//}
//func foo3(bytes net.IPAddr) {
//	fmt.Printf("%v\n", bytes)
//}

// go install golang.org/x/tools/cmd/godoc
// cd /Users/scfoley@us.ibm.com/goworkspace/bin
// ./godoc -http=localhost:6060
// http://localhost:6060/pkg/github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/

// src/golang.org/x/tools/godoc/static/ has the templates, specifically godoc.html

// TODO gdb https://gist.github.com/danisfermi/17d6c0078a2fd4c6ee818c954d2de13c
func getDoc() error {
	// Create the AST by parsing src.
	fset := token.NewFileSet() // positions are relative to fset
	pkgs, err := parser.ParseDir(
		fset,
		//"/Users/scfoley@us.ibm.com/goworkspace/src/github.com/seancfoley/ipaddress/ipaddress-go/ipaddr",
		"/Users/scfoley/go/src/github.com/seancfoley/ipaddress/ipaddress-go/ipaddr",
		func(f os.FileInfo) bool { return true },
		parser.ParseComments)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return err
		//panic(err)
	}
	for keystr, valuePkg := range pkgs {
		pkage := doc.New(valuePkg, keystr, 0)
		//pkage := doc.New(valuePkg, keystr, doc.AllMethods)
		//pkage := doc.New(valuePkg, keystr, doc.AllDecls)
		//fmt.Printf("\n%+v", pkage)
		// Print the AST.
		//		ast.Print(fset, pkage)

		for _, t := range pkage.Types {
			fmt.Printf("\n%s", t.Name)
			for _, m := range t.Methods {
				//fmt.Printf("bool %v", doc.AllMethods&doc.AllMethods != 0)
				//https: //golang.org/src/go/doc/doc.go
				//https://golang.org/src/go/doc/reader.go sortedTypes sortedFuncs show how they are filtered
				fmt.Printf("\n%+v", m)
			}
		}
	}
	return nil
}
