package main

import (
	"flag"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/test"
)

func main() {
	isLimitedPtr := flag.Bool("limited", false, "exclude caching and threading tests")
	flag.Parse()
	test.Test(*isLimitedPtr)
}
