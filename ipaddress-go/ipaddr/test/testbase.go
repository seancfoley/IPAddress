package main

import (
	"fmt"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
)

type failure struct {
	str string

	addr       *ipaddr.IPAddress
	addrStr    *ipaddr.IPAddressString
	macAddr    *ipaddr.MACAddress
	macAddrStr *ipaddr.MACAddressString
}

//TODO String() method for failure

func newIPAddrFailure(str string, addr *ipaddr.IPAddress) failure {
	return failure{
		str:  str,
		addr: addr,
	}
}

func newMACAddrFailure(str string, addr *ipaddr.MACAddress) failure {
	return failure{
		str:     str,
		macAddr: addr,
	}
}

func newMACFailure(str string, addrStr *ipaddr.MACAddressString) failure {
	return failure{
		str:        str,
		macAddrStr: addrStr,
	}
}
func newFailure(str string, addrStr *ipaddr.IPAddressString) failure {
	return failure{
		str:     str,
		addrStr: addrStr,
	}
}

type testInterface interface {
	// address creators
	createAddress(string) *ipaddr.IPAddressString

	//createInetAtonAddress(string) *ipaddr.IPAddressString

	createHost(string) *ipaddr.HostName

	createMACAddress(string) *ipaddr.MACAddressString

	// test failures
	addFailure(failure)

	// store test counts
	incrementTestCount()
}

var (
	hostOptions = new(ipaddr.HostNameParametersBuilder).
			AllowEmpty(false).
			ParseEmptyStrAs(ipaddr.NoAddress).
			NormalizeToLowercase(true).
			AllowPort(true).
			AllowService(true).
			AllowBracketedIPv6(true).
			AllowBracketedIPv4(true).
			GetIPAddressParametersBuilder(). //GetAddressOptionsBuilder().
			AllowPrefix(true).
			AllowMask(true).
			SetRangeParameters(ipaddr.NoRange).
			Allow_inet_aton(false).
			AllowEmpty(false).
			ParseEmptyStrAs(ipaddr.NoAddress).
			AllowAll(false).
		//allowPrefixOnly(true).
		AllowSingleSegment(false).
		GetIPv4AddressParametersBuilder().
		AllowLeadingZeros(true).
		AllowUnlimitedLeadingZeros(false).
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		AllowBinary(true).
		GetParentBuilder().
		GetIPv6AddressParametersBuilder().
		AllowLeadingZeros(true).
		AllowUnlimitedLeadingZeros(false).
		AllowPrefixLenLeadingZeros(true).
		AllowPrefixesBeyondAddressSize(false).
		AllowWildcardedSeparator(true).
		AllowMixed(true).
		AllowZone(true).
		AllowBinary(true).
		GetParentBuilder().GetParentBuilder().ToParams()

	//var addressOptions = ipaddr.ToIPAddressParametersBuilder(hostOptions).ToParams()
	addressOptions = new(ipaddr.IPAddressStringParametersBuilder).Set(hostOptions.GetIPAddressParameters()).ToParams()

	macAddressOptions = new(ipaddr.MACAddressStringParametersBuilder).
				AllowEmpty(false).
				AllowAll(false).
				GetFormatParametersBuilder().
				SetRangeParameters(ipaddr.NoRange).
				AllowLeadingZeros(true).
				AllowUnlimitedLeadingZeros(false).
				AllowWildcardedSeparator(true).
				AllowShortSegments(true).
				GetParentBuilder().
				ToParams()
)

type testAccumulator struct {
	counter  int64
	failures []failure
}

func (t *testAccumulator) addFailure(f failure) {
	t.failures = append(t.failures, f)
}

func (t *testAccumulator) incrementTestCount() {
	t.counter++
}

type addrTestAccumulator struct {
	testAccumulator
}

func (t *addrTestAccumulator) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, addressOptions)
}

func (t *addrTestAccumulator) createMACAddress(str string) *ipaddr.MACAddressString {
	return ipaddr.NewMACAddressStringParams(str, macAddressOptions)
}

func (t *addrTestAccumulator) createHost(str string) *ipaddr.HostName {
	return ipaddr.NewHostNameParams(str, hostOptions)
}

type rangedAddrTestAccumulator struct {
	addrTestAccumulator
}

var (
	wildcardAndRangeAddressOptions = new(ipaddr.IPAddressStringParametersBuilder).Set(addressOptions).AllowAll(true).SetRangeParameters(ipaddr.WildcardAndRange).ToParams()
	wildcardOnlyAddressOptions     = new(ipaddr.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParameters(ipaddr.WildcardOnly).ToParams()
	noRangeAddressOptions          = new(ipaddr.IPAddressStringParametersBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParameters(ipaddr.NoRange).ToParams()
)

func (t *rangedAddrTestAccumulator) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, wildcardAndRangeAddressOptions)
}

//func (t *rangedAddrTestAccumulator) createMACAddress(str string) *ipaddr.MACAddressString {
//	return ipaddr.NewMACAddressStringParams(str, xxxmacAddressOptions)
//}
//
//func (t *rangedAddrTestAccumulator) createHost(str string) *ipaddr.HostName {
//	return ipaddr.NewHostNameParams(str, xxhostOptionsxx)
//}

var defaultOptions = new(ipaddr.IPAddressStringParametersBuilder).ToParams()

type permissiveAddrTestAccumulator struct {
	rangedAddrTestAccumulator
}

func (t *permissiveAddrTestAccumulator) createAddress(str string) *ipaddr.IPAddressString {
	return ipaddr.NewIPAddressStringParams(str, defaultOptions)
}

//func (t *permissiveAddrTestAccumulator) createMACAddress(str string) *ipaddr.MACAddressString {
//	return ipaddr.NewMACAddressStringParams(str, xxxmacAddressOptions)
//}
//
//func (t *permissiveAddrTestAccumulator) createHost(str string) *ipaddr.HostName {
//	return ipaddr.NewHostNameParams(str, xxhostOptionsxx)
//}

func main() {
	var acc addrTestAccumulator
	tester := ipAddressTester{&acc}
	fmt.Println("Starting TestRunner")
	tester.run()
	fmt.Printf("TestRunner\ntest count: %d\nfail count:%d\n", acc.counter, len(acc.failures))
	if len(acc.failures) > 0 {
		fmt.Printf("%v\n", acc.failures)
	}
	fmt.Printf("Done: TestRunner\nDone in xxx milliseconds\n", acc.counter, len(acc.failures))
	//TODO create the testInterface impl, then create the ipAddressTester from it,
	// then call run on the ipAddresstester,
	// do the same for the macAddressTester
	/*
		TestRunner
		test count: 40278
		fail count: 0
		Done: TestRunner
		Done in 10845 milliseconds
	*/
}

type tester interface {
	run()
}

//
//type testBase struct {
//	testInterface
//}
