/*
IPAddress is a library for handling IP addresses and subnets, both IPv4 and IPv6

Benefits of this Library

• Parsing of all host name and ipv4/ipv6 address formats in common usage plus some additional formats

• Parsing and representation of subnets, either those specified by network prefix length or those specified with ranges of segment values.

• Allow the separation of address parsing from host parsing.

• Allow control over which formats are allowed when parsing, whether IPv4/6, or subnets, or inet_aton formats, and so on.

• Produce all common address strings of different formats for a given IPv4 or IPv6 address and produce collections of such strings

• Support parsing of all common MAC Address formats in usage and produce all common MAC address strings of different formats

• Integration of MAC Address with IPv6 with standard conversions

• Integration of IPv4 Address with IPv6 through common address conversions

• Polymorphism is a key goal. The library maintains an address framework of interfaces that allow most library functionality to be independent of address type or version, whether IPv4, IPv6 or MAC. This allows for code which supports both IPv4 and IPv6 transparently.

• Thread-safety and immutability. The core types (host names, address strings, addresses, address sections, address segments, address ranges) are all immutable. They do not change their underlying value. For sharing amongst goroutines this is valuable.

• Address modifications, such as altering prefix lengths, masking, splitting into sections and segments, splitting into network and host sections, reconstituting from sections and segments

• Address operations and subnetting, such as obtaining the prefix block subnet for a prefixed address, iterating, spliterating or streaming through subnets, iterating through prefix blocks and other subnets, incrementing and decrementing addresses by integer values, reversing address bits for endianness or DNS lookup, set-subtracting subnets from other subnets, subnetting, intersections of subnets, merging subnets, checking containment of addresses in subnets, listing subnets covering a span of addresses

• Sorting and comparison of host names, addresses, address strings and subnets

• Integrate with the Go language primitive types and the standard library types net.IP, net.IPAddr, net.IPMask, net.IPNet, net.TCPAddr, net.UDPAddr, and big.Int.

• Making address manipulations easy, so you do not have to worry about longs/ints/shorts/bytes/bits, signed/unsigned, sign extension, ipv4/v6, masking, iterating, and other implementation details.

This library is similar in design to the Java IPAddress library,
mirroring the same functionality with a similar API,
despite the differences between the Java and Go languages,
such as the differences in error handling, the lack of inheritance in Go.

This library allows you to scale down from more specific types to more generic types,
and then to scale back up again.  You can only scale up to a specific version or address type if the lower level instance was originally derived from an instance of the more-specific type.
So, for instance, an IPv6Address can be converted to an IPAddress using ToIP(), or to an Address using ToAddressBase(), which can then be converted back to IPAddress or an IPv6Address using ToIPv6().
But if you wish to covert that IPv6Address to IPv4, you would need to use an implementation of IPv4AddressConverter.

Code Examples

For common use-cases, you may wish to go straight to the wiki code examples which cover a wide breadth of common use-cases: https://github.com/seancfoley/IPAddress/wiki/Code-Examples

Further Documentation

https://seancfoley.github.io/IPAddress/

Getting Started

Starting with address or subnet strings, or starting with host name strings:
*/
package ipaddr
