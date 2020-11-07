package ipaddr

// All IP address strings corresponds to exactly one of these types.
// In cases where there is no corresponding default IPAddress value (INVALID, ALL, and possibly EMPTY), these types can be used for comparison.
// EMPTY means a zero-length string (useful for validation, we can set validation to allow empty strings) that has no corresponding IPAddress value (validation options allow you to map empty to the loopback)
// INVALID means it is known that it is not any of the other allowed types (validation options can restrict the allowed types)
// ALL means it is wildcard(s) with no separators, like "*", which represents all addresses, whether IPv4, IPv6 or other, and thus has no corresponding IPAddress value
// These constants are ordered by address space size, from smallest to largest, and the ordering affects comparisons
type IPType int

func fromVersion(version IPVersion) IPType {
	switch version {
	case IPv4:
		return IPV4
	case IPv6:
		return IPV6
	default:
	}
	return UNINITIALIZED_TYPE
}

func (t IPType) isUnknown() bool {
	return t == UNINITIALIZED_TYPE
}

const (
	UNINITIALIZED_TYPE IPType = iota
	INVALID
	EMPTY
	IPV4
	IPV6
	PREFIX_ONLY
	ALL
)

//TODO rename later IPAddressProvider, IPType, and the IPType constants, all the creator classes, etc, so not public, also same for MACAddressProvider

type IPAddressProvider interface {
	getType() IPType

	isInvalid() bool
	isUninitialized() bool
	isProvidingEmpty() bool

	// TODO reinstate when you are ready to work on this
	//getProviderHostAddress() (IPAddress, IncompatibleAddressException)
	//getProviderAddress() (IPAddress, IncompatibleAddressException)
	//getVersionAddress(version IPVersion) (IPAddress, IncompatibleAddressException)
}

// if you have a type with 3 funcs, and 3 methods that defer to the funs
// then that is 4 decls, and then you can deine each of the 3 vars
// if you do a new type for each overridden method, that is 6 decls

type ipAddrProvider struct {
	ipType                                    IPType
	isInvalidVal, isUninitializedVal, isEmpty bool
}

func (p *ipAddrProvider) isInvalid() bool {
	return p.isInvalidVal
}

func (p *ipAddrProvider) isUninitialized() bool {
	return p.isUninitializedVal
}

func (p *ipAddrProvider) isProvidingEmpty() bool {
	return p.isEmpty
}

func (p *ipAddrProvider) getType() IPType {
	return p.ipType
}

var (
	INVALID_PROVIDER = &ipAddrProvider{isInvalidVal: true, ipType: INVALID}
	NO_TYPE_PROVIDER = &ipAddrProvider{isUninitializedVal: true, ipType: UNINITIALIZED_TYPE}
	EMPTY_PROVIDER   = &ipAddrProvider{isEmpty: true, ipType: EMPTY}
)

// TODO progress
// - Move towards address creation - need ipaddress provider types fleshed out, and in particular ParsedIPAddress
//	- parsedipaddress will need the start of the ip address creator interfaces
// - Then the mask stuff in parseQualifier can be done, which depends on address creation
// - then IPAddressString and HostName can be fleshed out
// - then you can link up the ip address creator interfaces with the address types
// - here you might start putting in validation tests that check for parsing errors
// - then you can do the string methods in the address sections and addresses and segments
// - the you can add validation tests that use strings, in fact not sure if I do that much, I have some that check the string methods thought

//TODO your provider types can be similar, you can have a base type that has all the methods that are "default" in Java
//With Java you added a lot of stuff to IPAddressProvider, here you can start with the basics, maybe you don't want to add the contains and prefixEquals and prefixContains shortcuts

//public interface IPAddressProvider extends Serializable {

//
//	IPAddressProvider.IPType getType();
//
//	IPAddress getProviderHostAddress() throws IncompatibleAddressException;
//
//	IPAddress getProviderAddress() throws IncompatibleAddressException;
//
//	IPAddress getProviderAddress(IPVersion version) throws IncompatibleAddressException;
//
//	default boolean isSequential() {
//		try {
//			IPAddress addr = getProviderAddress();
//			if(addr != null) {
//				return addr.isSequential();
//			}
//		} catch(IncompatibleAddressException e) {}
//		return false;
//	}
//
//	default IPAddressSeqRange getProviderSeqRange() {
//		IPAddress addr = getProviderAddress();
//		if(addr != null) {
//			return addr.toSequentialRange();
//		}
//		return null;
//	}
//
//	default IPAddress getProviderMask() {
//		return null;
//	}
//
//	default IPAddressDivisionSeries getDivisionGrouping() throws IncompatibleAddressException {
//		return getProviderAddress();
//	}
//
//	default int providerCompare(IPAddressProvider other) throws IncompatibleAddressException {
//		if(this == other) {
//			return 0;
//		}
//		IPAddress value = getProviderAddress();
//		if(value != null) {
//			IPAddress otherValue = other.getProviderAddress();
//			if(otherValue != null) {
//				return value.compareTo(otherValue);
//			}
//		}
//		IPType thisType = getType(), otherType = other.getType();
//		if(thisType == null) {
//			return otherType == null ? 0 : -1;
//		} else if(otherType == null) {
//			return 1;
//		}
//		return thisType.ordinal() - otherType.ordinal();
//	}
//
//	/**
//	 * When a value provider produces no value, equality and comparison are based on the enum IPType,
//	 * which can by null.
//	 * @param o
//	 * @return
//	 */
//	default boolean providerEquals(IPAddressProvider other) throws IncompatibleAddressException {
//		if(this == other) {
//			return true;
//		}
//		IPAddress value = getProviderAddress();
//		if(value != null) {
//			IPAddress otherValue = other.getProviderAddress();
//			if(otherValue != null) {
//				return value.equals(otherValue);
//			} else {
//				return false;
//			}
//		}
//		//this works with both null and also non-null since the type is an enum
//		return getType() == other.getType();
//	}
//
//	default int providerHashCode() throws IncompatibleAddressException {
//		IPAddress value = getProviderAddress();
//		if(value != null) {
//			return value.hashCode();
//		}
//		return Objects.hashCode(getType());
//	}
//
//	default IPVersion getProviderIPVersion() {
//		return null;
//	}
//
//	default boolean isProvidingIPAddress() {
//		return false;
//	}
//
//	default boolean isProvidingIPv4() {
//		return false;
//	}
//
//	default boolean isProvidingIPv6() {
//		return false;
//	}
//
//	default boolean isProvidingPrefixOnly() {
//		return false;
//	}
//
//	default boolean isProvidingAllAddresses() {
//		return false;
//	}
//
//	default boolean isProvidingEmpty() {
//		return false;
//	}
//
//	default boolean isProvidingMixedIPv6() {
//		return false;
//	}
//
//	default boolean isProvidingBase85IPv6() {
//		return false;
//	}
//
//	default Integer getProviderNetworkPrefixLength() {
//		return null;
//	}
//
//	default boolean isInvalid() {
//		return false;
//	}
//
//	default boolean isUninitialized() {
//		return false;
//	}
//
//	/**
//	 * An optimized contains that does not need to create address objects to return an answer.
//	 * Unconventional addresses may require that the address objects are created, in such cases null is returned.
//	 *
//	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean contains(IPAddressProvider other) {
//		return null;
//	}
//
//	/**
//	 * An optimized contains that does not need to fully parse the other address to return an answer.
//	 *
//	 * Unconventional addresses may require full parsing, in such cases null is returned.
//	 *
//	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean contains(String other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to fully parse the other address to return an answer.
//	 *
//	 * Unconventional addresses may require full parsing, in such cases null is returned.
//	 *
//	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixEquals(String other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixEquals(IPAddressProvider other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixContains(String other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixContains(IPAddressProvider other) {
//		return null;
//	}
//
//	/**
//	 * An optimized equality comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean parsedEquals(IPAddressProvider other) {
//		return null;
//	}
//
//	default boolean hasPrefixSeparator() {
//		return getProviderNetworkPrefixLength() != null;
//	}
