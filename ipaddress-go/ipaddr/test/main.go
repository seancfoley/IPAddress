package main

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"

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

	seg.GetDivisionValue()

	//seg.getSplitSegments()
	//fmt.Printf("\n%v\n", seg.GetDivisionValue())
	//fmt.Printf("%v\n", seg.GetSegmentValue())
	fmt.Printf("%v\n", seg.GetBitCount())
	fmt.Printf("%v\n", seg.GetByteCount())

	grouping := ipaddr.IPv4AddressSection{}
	grouping.GetDivisionCount()
	//grouping.hasNoDivisions()

	addr := ipaddr.IPv6Address{}
	addr.ToAddress()
	getDoc()
}

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
