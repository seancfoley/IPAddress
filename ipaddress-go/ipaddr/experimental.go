package ipaddr

import (
	"fmt"
)

type xnonDupSeries interface {
	Get() int
}
type XDivSeries interface {
	xnonDupSeries
	getDiv() XDiv
}

type XSegSeries interface {
	xnonDupSeries
	getDiv() XIPv6Div

	//cannot override like we do with structs, cannot do this unless no duplicate methods
	//	DivSeries
	//	getDiv() IPv6Div
}

// cannot do this either
//func (ip SegSeries) getDiv() IPv6Div {
//	//ipDiv := ip.div
//	return IPv6Div{}
//}

type XDiv struct {
}

type XIPv6Div struct {
	XDiv
}

type xipinternal struct {
	div XDiv
}

func (ip xipinternal) getDiv() XDiv {
	return ip.div
}

func (ip xipinternal) Get() int {
	return 1
}

type XIP struct {
	xipinternal
	ipSpecific interface{}
}

func (ip XIP) toIPv6() XIPv6 {
	str := ip.ipSpecific.(string)
	return XIPv6{
		xipinternal: ip.xipinternal,
		zone:        str,
	}
}

type XIPv6 struct {
	xipinternal
	zone string //also stored as ipSpecific in IP
}

func (ip XIPv6) getDiv() XIPv6Div {
	ipDiv := ip.div
	return XIPv6Div{ipDiv}
}

func (ip XIPv6) toIP() XIP {
	//ip.ipinternal.ipSpecific = ip.zone //actually, maybe this would happen at construction?
	return XIP{
		xipinternal: ip.xipinternal,
		ipSpecific:  ip.zone,
	}
}

//So there ya have it.  Now we can also implement any old interface, like IPAddressSegmentSeries and IPAddressDivisionSeries.

//TODO try out creating a couple of the interfaces, maybe the above two, just need to see if we can "override" methods in interfaces too
//same as the way we override getDiv above
//TODO run godoc on this, see what happens

//TODO constructors?  Could be tricky figuring out how to map the constructor code.
//frankly, might have to just have a bunch of "NewIPv6" methods.  Actually, with the new structure that hides internal structure of IPs,
//the NewIPV6 methods should be fine

//godoc:  godoc -http ":8080"
//Or
//godoc -html github.com/seancfoley/ipaddress/ipaddress-go/ipaddr
//not sure how I'd be able to make it static along with the links, you end up with the href of src/target/filename.go
//Even if I did a mass substitution on the links I would still need to produce the formatted source file
//However, I suppose I could potentially automate it
//Basically, I'd have to run the tool, then I'd do a mass substitution on /src/target/ while at the same time following those links with the running server
//In fact, it would be like a file crawler

//AHA
/*
To generate static docs, just run this command:
godoc -http=localhost:8080 &
wget -r -np http://localhost:8080/pkg/
We're working on providing online docs for older versions of Go.

I haven't thought about using wget. Nice. For those interested in this trick, here are
some notes.
First, edit robots.txt in the go root directory, and remove "Disallow: /". Otherwise
only the index will be downloaded because wget respects robots.txt.
Then start godoc pointing to the project path:
godoc -path="/path/to/project" -http=:8080
And finally this a more complete command to get a working static docs, including static
files and with proper links:
wget -r -np -N -E -p -k http://localhost:8080/pkg/
-r  : download recursive
-np : don't ascend to the parent directory
-N  : don't retrieve files unless newer than local
-E  : add extension .html to html files (if they don't have)
-p  : download all necessary files for each page (css, js, images)
-k  : convert links to relative

https://github.com/golang/go/issues/2381

*/

func Test() {
	fmt.Printf("set up")

	ipv6 := XIPv6{
		xipinternal: xipinternal{
			div: XDiv{},
		},
		zone: "a zone",
	}
	ip := ipv6.toIP()
	xdivFunc(ip)
	xsegFunc(ipv6)

}

func xdivFunc(d XDivSeries) {}

func xsegFunc(d XSegSeries) {}
