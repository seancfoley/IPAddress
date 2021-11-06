package test

import "github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"

type specialTypesTester struct {
	testBase
}

var (
	hostOptionsSpecial = new(ipaddr.HostNameParametersBuilder).AllowEmpty(true).ParseEmptyStrAs(ipaddr.LoopbackOption).GetIPAddressParametersBuilder().AllowEmpty(false).SetRangeParameters(ipaddr.WildcardOnly).AllowAll(true).GetParentBuilder().ToParams()

	addressOptionsSpecial = new(ipaddr.IPAddressStringParametersBuilder).Set(hostOptionsSpecial.GetIPAddressParameters()).AllowEmpty(true).ParseEmptyStrAs(ipaddr.LoopbackOption).ToParams()

	macOptionsSpecial = new(ipaddr.MACAddressStringParametersBuilder).Set(macAddressOptions).AllowEmpty(true).SetRangeParameters(ipaddr.WildcardOnly).AllowAll(true).ToParams()

	emptyAddressOptions = new(ipaddr.HostNameParametersBuilder).Set(hostOptions).GetIPAddressParametersBuilder().AllowEmpty(true).ParseEmptyStrAs(ipaddr.LoopbackOption).GetParentBuilder().ToParams()

	emptyAddressNoLoopbackOptions = new(ipaddr.HostNameParametersBuilder).Set(emptyAddressOptions).GetIPAddressParametersBuilder().ParseEmptyStrAs(ipaddr.NoAddressOption).GetParentBuilder().ToParams()
)

func (t specialTypesTester) run() {
	addressEmpty := t.createParamsHost("", emptyAddressOptions)
	t.hostLabelsHostTest(addressEmpty, []string{"127", "0", "0", "1"})
	addressEmpty2 := t.createParamsHost("", emptyAddressNoLoopbackOptions)
	t.hostLabelsHostTest(addressEmpty2, []string{})
	hostEmpty := t.createParamsHost("", hostOptionsSpecial)
	t.hostLabelsHostTest(hostEmpty, []string{})
}
