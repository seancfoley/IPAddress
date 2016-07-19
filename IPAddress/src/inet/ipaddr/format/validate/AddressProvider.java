package inet.ipaddr.format.validate;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Objects;

import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * Provides an address corresponding to a parsed string.
 * 
 * @author sfoley
 *
 */
public abstract class AddressProvider implements Serializable, Comparable<AddressProvider> {
	//All ip address strings corresponds to exactly one of these types.
	//In cases where there is no corresponding default IPAddress value (INVALID, ALL, and possibly EMPTY), these types can be used for comparison.
	//EMPTY means a zero-length string (useful for validation, we can set validation to allow empty strings) that has no corresponding IPAddress value (validation options allow you to map empty to the loopback)
	//INVALID means it is known that it is not any of the other allowed types (validation options can restrict the allowed types)
	//ALL means it is wildcard(s) with no separators, like "*", which represents all addresses, whether IPv4, IPv6 or other, and thus has no corresponding IPAddress value
	//this enum is ordered by address space size, from smallest to largest, and the ordering affects comparisons
	private enum IPType {
		INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL;
		
		static AddressProvider.IPType from(IPVersion version) {
			switch(version) {
				case IPV4:
					return IPV4;
				case IPV6:
					return IPV6;
				default:
					return null;
			}
		}
	}
	
	private static final long serialVersionUID = 1L;

	@SuppressWarnings("serial")
	public static final NullProvider INVALID_PROVIDER = new NullProvider(IPType.INVALID) {
		@Override
		public boolean isInvalid() {
			return true;
		}
	};
	
	@SuppressWarnings("serial")
	public static final NullProvider NO_TYPE_PROVIDER = new NullProvider(null) {
		@Override
		public boolean isUninitialized() {
			return true;
		}
	};
	
	@SuppressWarnings("serial")
	static final NullProvider EMPTY_PROVIDER = new NullProvider(IPType.EMPTY) {
		@Override
		public boolean isEmpty() {
			return true;
		}
	};
	
	static final AddressProvider LOOPBACK_CREATOR = new LoopbackCreator();
	
	static final AddressProvider ALL_ADDRESSES_CREATOR = new AllCreator(new ParsedAddressQualifier(), null, null);
	
	private AddressProvider() {}
	
	public abstract AddressProvider.IPType getType();
	
	public abstract IPAddress getAddress();
	
	public abstract IPAddress getAddress(IPVersion version);
	
	@Override
	public int hashCode() {
		IPAddress value = getAddress();
		if(value != null) {
			return value.hashCode();
		}
		return Objects.hashCode(getType());
	}
	
	@Override
	public int compareTo(AddressProvider other) {
		if(this == other) {
			return 0;
		}
		IPAddress value = getAddress();
		if(value != null) {
			IPAddress otherValue = other.getAddress();
			if(otherValue != null) {
				return value.compareTo(otherValue);
			}
		}
		IPType thisType = getType(), otherType = other.getType();
		if(thisType == null) {
			return otherType == null ? 0 : -1;
		} else if(otherType == null) {
			return 1;
		}
		return thisType.ordinal() - otherType.ordinal();
	}
	
	/**
	 * When a value provider produces no value, equality and comparison are based on the enum IPType,
	 * which can by null.
	 * @param o
	 * @return
	 */
	@Override
	public boolean equals(Object o) {
		if(this == o) {
			return true;
		}
		if(o instanceof AddressProvider) {
			AddressProvider other = (AddressProvider) o;
			IPAddress value = getAddress();
			if(value != null) {
				IPAddress otherValue = other.getAddress();
				if(otherValue != null) {
					return value.equals(otherValue);
				}
			}
			//this works with both null and also non-null since the type is an enum
			return getType() == other.getType();
		}
		return false;
	}
	
	public IPVersion getIPVersion() {
		return null;
	}
	
	public boolean isIPAddress() {
		return false;
	}
	
	public boolean isIPv4() {
		return false;
	}
	
	public boolean isIPv6() {
		return false;
	}
	
	public boolean isPrefixOnly() {
		return false;
	}
	
	public boolean isAllAddresses() {
		return false;
	}
	
	public boolean isEmpty() {
		return false;
	}
	
	public boolean isInvalid() {
		return false;
	}
	
	public boolean isUninitialized() {
		return false;
	}
	
	public boolean isMixedIPv6() {
		return false;
	}
	
	public Integer getNetworkPrefixLength() {
		return null;
	}
	
	public boolean isPrefixed() {
		return getNetworkPrefixLength() != null;
	}
	
	//for addresses that cannot produce an ipv4 or ipv6 value and has no prefix either
	private abstract static class NullProvider extends AddressProvider {
		private static final long serialVersionUID = 1L;
		private IPType type;
		
		public NullProvider(AddressProvider.IPType type) {
			this.type = type;
		}
		
		@Override
		public AddressProvider.IPType getType() {
			return type;
		}
		
		@Override
		public IPAddress getAddress() {
			return null;
		}
		
		@Override
		public IPAddress getAddress(IPVersion version) {
			return null;
		}
	};
	
	/**
	 * Wraps an IPAddress for IPAddressString in the cases where no parsing is provided, the address exists already
	 * @param value
	 * @return
	 */
	public static AddressProvider getProviderFor(IPAddress address) {
		return new CachedAddressProvider(address);
	}
	
	//constructor where we already have a value
	private static class CachedAddressProvider extends AddressProvider {
		private static final long serialVersionUID = 1L;
		IPAddress value;
		
		CachedAddressProvider() {}
		
		private CachedAddressProvider(IPAddress value) {
			this.value = value;
		}
		
		@Override
		public IPVersion getIPVersion() {
			return value.getIPVersion();
		}
		
		@Override
		public AddressProvider.IPType getType() {
			return IPType.from(getIPVersion());
		}
		
		@Override
		public boolean isIPAddress() {
			return true;
		}
		
		@Override
		public boolean isIPv4() {
			return value.isIPv4();
		}
		
		@Override
		public boolean isIPv6() {
			return value.isIPv6();
		}
		
		@Override
		public IPAddress getAddress()  {
			return value;
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			return value.getNetworkPrefixLength();
		}
		
		@Override
		public IPAddress getAddress(IPVersion version) {
			IPVersion thisVersion = getIPVersion();
			if(!version.equals(thisVersion)) {
				return null;
			}
			return getAddress();
		}
	}
	
	private static abstract class CachedAddressCreator extends CachedAddressProvider {
		private static final long serialVersionUID = 1L;

		@Override
		public IPAddress getAddress(IPVersion version) {
			getAddress();
			return super.getAddress(version);
		}
		
		@Override
		public IPAddress getAddress()  {
			IPAddress val = value;
			if(val == null) {
				synchronized(this) {
					val = value;
					if(val == null) {
						value = val = createAddress();
					}
				}
			}
			return val;
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			getAddress();
			return super.getNetworkPrefixLength();
		}
		
		abstract IPAddress createAddress();
	}
	
	static class ParsedAddressProvider extends CachedAddressCreator {
		private static final long serialVersionUID = 1L;
		private ParsedAddress parseResult;
		private IPVersion version;
		boolean isMixedIPv6;
		
		ParsedAddressProvider(ParsedAddress parseResult) {
			this.parseResult = parseResult;
			this.version = parseResult.getIPVersion();
			this.isMixedIPv6 = parseResult.isMixedIPv6();
		}
	
		@Override
		public boolean isMixedIPv6() {
			return isMixedIPv6;
		}
		
		@Override
		public IPVersion getIPVersion() {
			return version;
		}
		
		@Override
		public boolean isIPv4() {
			return getIPVersion().isIPv4();
		}
		
		@Override
		public boolean isIPv6() {
			return getIPVersion().isIPv6();
		}
		
		@Override
		IPAddress createAddress() {
			IPAddress result = parseResult.createAddress();
			parseResult = null;
			return result;
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			ParsedAddress parsedAddress = parseResult;//getting this as a local makes it thread-safe
			if(parsedAddress != null) {
				return parsedAddress.getNetworkPrefixLength();
			}
			return super.getNetworkPrefixLength();
		}
		
		@Override
		public boolean isPrefixed() {
			ParsedAddress parsedAddress = parseResult;//getting this as a local makes it thread-safe
			if(parsedAddress != null) {
				return parsedAddress.isPrefixed();
			}
			return super.isPrefixed();
		}
	}
	
	static abstract class VersionedAddressCreator extends CachedAddressCreator {
		private static final long serialVersionUID = 1L;
		IPAddress versionedValues[];
		
		private IPAddress checkResult(IPVersion version, int index) {
			IPAddress result = versionedValues[index];
			if(result == null) {
				versionedValues[index] = result = createVersionedAddress(version);
			}
			return result;
		}
		
		@Override
		public IPAddress getAddress(IPVersion version) {
			int index = version.ordinal();
			IPAddress result;
			if(versionedValues == null) {
				synchronized(this) {
					if(versionedValues == null) {
						versionedValues = new IPAddress[IPVersion.values().length];
						versionedValues[index] = result = createVersionedAddress(version);
					} else {
						result = checkResult(version, index);
					}
				}
			} else {
				result = versionedValues[index];
				if(result == null) {
					synchronized(this) {
						result = checkResult(version, index);
					}
				}
			}
			return result;
		}
	
		abstract IPAddress createVersionedAddress(IPVersion version);
	}
	
	private static abstract class AdjustedAddressCreator extends VersionedAddressCreator {
		private static final long serialVersionUID = 1L;
		protected final IPVersion adjustedVersion;
		protected final ParsedAddressQualifier qualifier;
		
		AdjustedAddressCreator(ParsedAddressQualifier qualifier) {
			this(qualifier, null);
		}
		
		AdjustedAddressCreator(ParsedAddressQualifier qualifier, IPVersion adjustedVersion) {
			this.qualifier = qualifier;
			this.adjustedVersion = adjustedVersion;
		}
		
		@Override
		public boolean isIPAddress() {
			return adjustedVersion != null;
		}
		
		@Override
		public boolean isIPv4() {
			return isIPAddress() && adjustedVersion.isIPv4();
		}
		
		@Override
		public boolean isIPv6() {
			return isIPAddress() && adjustedVersion.isIPv6();
		}
		
		@Override
		public IPVersion getIPVersion() {
			return adjustedVersion;
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			if(qualifier == null) {
				return null;
			}
			return qualifier.getNetworkPrefixLength();
		}
		
		@Override
		public IPAddress getAddress()  {
			if(adjustedVersion == null) {
				return null;
			}
			return super.getAddress();
		}
	}
	
	static class MaskCreator extends AdjustedAddressCreator {
		private static final long serialVersionUID = 1L;
		
		MaskCreator(ParsedAddressQualifier qualifier) {
			super(qualifier);
		}
		
		MaskCreator(ParsedAddressQualifier qualifier, IPVersion adjustedVersion) {
			super(qualifier, adjustedVersion);
		}
		
		@Override
		public int hashCode() {
			if(adjustedVersion == null) {
				return getNetworkPrefixLength();
			}
			return getAdjustedValue().hashCode();
		}
		
		@Override
		public boolean equals(Object o) {
			if(o == this) {
				return true;
			}
			if(o instanceof AddressProvider) {
				AddressProvider valueProvider = (AddressProvider) o;
				if(adjustedVersion == null) {
					if(valueProvider.getType() == IPType.PREFIX_ONLY) {//both are PREFIX_ONLY
						return valueProvider.getNetworkPrefixLength() == getNetworkPrefixLength();
					}
					return false;
				}
				return super.equals(valueProvider);
			}
			return false;
		}
		
		@Override
		public int compareTo(AddressProvider other) {
			if(this == other) {
				return 0;
			}
			if(adjustedVersion == null) {
				if(other.getType() == IPType.PREFIX_ONLY) {//both are PREFIX_ONLY
					return other.getNetworkPrefixLength() - getNetworkPrefixLength();
				}
				return IPType.PREFIX_ONLY.ordinal() - other.getType().ordinal();
			}
			IPAddress otherValue = other.getAddress();
			if(otherValue != null) {
				return getAddress().compareTo(otherValue);
			}
			return IPType.from(adjustedVersion).ordinal() - other.getType().ordinal();
		}

		private IPAddress createVersionedMask(IPVersion version, int bits) {
			IPAddressNetwork network = IPAddress.network(version);
			return network.getNetworkMask(bits, true);
		}
		
		@Override
		IPAddress createVersionedAddress(IPVersion version) {
			return createVersionedMask(version, getNetworkPrefixLength());
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			return qualifier.getNetworkPrefixLength();
		}

		@Override
		public AddressProvider.IPType getType() {
			if(adjustedVersion != null) {
				return IPType.from(adjustedVersion);
			}
			return IPType.PREFIX_ONLY;
		}
		
		@Override
		public boolean isPrefixOnly() {
			return adjustedVersion == null;
		}
		
		@Override
		public IPAddress getAddress()  {
			if(adjustedVersion == null) {
				return null;
			}
			return getAdjustedValue();
		}
		
		private IPAddress getAdjustedValue()  {
			if(value == null) {
				value = createAddress();
			}
			return value;
		}
		
		@Override
		IPAddress createAddress() {
			return createVersionedMask(adjustedVersion, getNetworkPrefixLength());
		}
	}
	
	static class LoopbackCreator extends VersionedAddressCreator {
		private static final long serialVersionUID = 1L;
		private final String zone;
		
		LoopbackCreator() {
			this(null);
		}

		LoopbackCreator(String zone) {
			this.zone = zone;
		}
		
		@Override
		public AddressProvider.IPType getType() {
			return IPType.from(getIPVersion());
		}
		
		@Override
		public boolean isIPAddress() {
			return true;
		}
		
		@Override
		public boolean isIPv4() {
			return getAddress().isIPv4();
		}
		
		@Override
		public boolean isIPv6() {
			return getAddress().isIPv6();
		}
		
		@Override
		IPAddress createVersionedAddress(IPVersion version) {
			if(value != null && version.equals(value.getIPVersion())) {
				return value;
			}
			IPAddress address = IPAddress.getLoopback(version);
			if(zone != null && zone.length() > 0 && version.isIPv6()) {
				return IPv6Address.from(address.getBytes(), zone);
			}
			return address;
		}
		
		@Override
		IPAddress createAddress() {
			InetAddress loopback = InetAddress.getLoopbackAddress();
			byte bytes[] = loopback.getAddress();
			if(zone != null && zone.length() > 0 && bytes.length == IPv6Address.BYTE_COUNT) {
				return IPv6Address.from(bytes, zone);
			}
			return IPAddress.from(bytes);
		}
		
		@Override
		public IPVersion getIPVersion() {
			return getAddress().getIPVersion();	
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			return null;
		}
	}
	
	static class AllCreator extends AdjustedAddressCreator {
		private static final long serialVersionUID = 1L;
		IPAddressString fromString;
		HostName fromHost;

		AllCreator(ParsedAddressQualifier qualifier, HostName fromHost, IPAddressString fromString) {
			super(qualifier);
			this.fromString = fromString;
			this.fromHost = fromHost;
		}
		
		AllCreator(ParsedAddressQualifier qualifier, IPVersion adjustedVersion, HostName fromHost, IPAddressString fromString) {
			super(qualifier, adjustedVersion);
			this.fromString = fromString;
			this.fromHost = fromHost;
		}
		
		@Override
		IPAddress createVersionedAddress(IPVersion version) {
			return ParsedAddress.createAllAddress(version, qualifier, fromHost, fromString);
		}

		@Override
		public AddressProvider.IPType getType() {
			if(adjustedVersion != null) {
				return IPType.from(adjustedVersion);
			}
			return IPType.ALL;
		}
		
		@Override
		public boolean isAllAddresses() {
			return adjustedVersion == null;
		}
		
		@Override
		public int hashCode() {
			if(adjustedVersion == null) {
				return IPAddressString.ALL_ADDRESSES.toString().hashCode();
			}
			return super.hashCode();
		}
		
		@Override
		IPAddress createAddress() {
			return ParsedAddress.createAllAddress(adjustedVersion, qualifier, fromHost, fromString);
		}
	}
}