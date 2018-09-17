/*
 * Copyright 2016-2018 Sean C Foley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     or at
 *     https://github.com/seancfoley/IPAddress/blob/master/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package inet.ipaddr.format.validate;

import java.io.Serializable;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Objects;

import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.format.validate.ParsedIPAddress.CachedIPAddresses;

/**
 * Provides an address corresponding to a parsed string.
 * 
 * @author sfoley
 *
 */
public interface IPAddressProvider extends Serializable {
	//All IP address strings corresponds to exactly one of these types.
	//In cases where there is no corresponding default IPAddress value (INVALID, ALL, and possibly EMPTY), these types can be used for comparison.
	//EMPTY means a zero-length string (useful for validation, we can set validation to allow empty strings) that has no corresponding IPAddress value (validation options allow you to map empty to the loopback)
	//INVALID means it is known that it is not any of the other allowed types (validation options can restrict the allowed types)
	//ALL means it is wildcard(s) with no separators, like "*", which represents all addresses, whether IPv4, IPv6 or other, and thus has no corresponding IPAddress value
	//this enum is ordered by address space size, from smallest to largest, and the ordering affects comparisons
	enum IPType {
		INVALID, EMPTY, IPV4, IPV6, PREFIX_ONLY, ALL;
		
		static IPAddressProvider.IPType from(IPVersion version) {
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
		public boolean isProvidingEmpty() {
			return true;
		}
	};
	
	IPAddressProvider.IPType getType();
	
	IPAddress getProviderHostAddress();
	
	IPAddress getProviderAddress();
	
	IPAddress getProviderAddress(IPVersion version);
	
	default int providerCompare(IPAddressProvider other) {
		if(this == other) {
			return 0;
		}
		IPAddress value = getProviderAddress();
		if(value != null) {
			IPAddress otherValue = other.getProviderAddress();
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
	default boolean equalsProvider(IPAddressProvider other) {
		if(this == other) {
			return true;
		}
		IPAddress value = getProviderAddress();
		if(value != null) {
			IPAddress otherValue = other.getProviderAddress();
			if(otherValue != null) {
				return value.equals(otherValue);
			}
		}
		//this works with both null and also non-null since the type is an enum
		return getType() == other.getType();
	}
	
	default int providerHashCode() {
		IPAddress value = getProviderAddress();
		if(value != null) {
			return value.hashCode();
		}
		return Objects.hashCode(getType());
	}

	default IPVersion getProviderIPVersion() {
		return null;
	}
	
	default boolean isProvidingIPAddress() {
		return false;
	}
	
	default boolean isProvidingIPv4() {
		return false;
	}
	
	default boolean isProvidingIPv6() {
		return false;
	}
	
	default boolean isProvidingPrefixOnly() {
		return false;
	}
	
	default boolean isProvidingAllAddresses() {
		return false;
	}
	
	default boolean isProvidingEmpty() {
		return false;
	}
	
	default boolean isProvidingMixedIPv6() {
		return false;
	}
	
	default boolean isProvidingBase85IPv6() {
		return false;
	}
	
	default Integer getProviderNetworkPrefixLength() {
		return null;
	}

	default boolean isInvalid() {
		return false;
	}
	
	default boolean isUninitialized() {
		return false;
	}
	
	/**
	 * An optimized contains that does not need to create address objects to return an answer.
	 * Unconventional addresses may require that the address objects are created, in such cases null is returned.
	 * 
	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
	 * 
	 * @param other
	 * @return
	 */
	default Boolean contains(IPAddressProvider other) {
		return null;
	}

	/**
	 * An optimized contains that does not need to fully parse the other address to return an answer.
	 * 
	 * Unconventional addresses may require full parsing, in such cases null is returned.
	 * 
	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
	 * 
	 * @param other
	 * @return
	 */
	default Boolean contains(String other) {
		return null;
	}
	
	/**
	 * An optimized prefix comparison that does not need to fully parse the other address to return an answer.
	 * 
	 * Unconventional addresses may require full parsing, in such cases null is returned.
	 * 
	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
	 * 
	 * @param other
	 * @return
	 */
	default Boolean prefixEquals(String other) {
		return null;
	}

	/**
	 * An optimized prefix comparison that does not need to create addresses to return an answer.
	 * 
	 * Unconventional addresses may require the address objects, in such cases null is returned.
	 * 
	 * @param other
	 * @return
	 */
	default Boolean prefixEquals(IPAddressProvider other) {
		return null;
	}
	
	/**
	 * An optimized equality comparison that does not need to create addresses to return an answer.
	 * 
	 * Unconventional addresses may require the address objects, in such cases null is returned.
	 * 
	 * @param other
	 * @return
	 */
	default Boolean parsedEquals(IPAddressProvider other) {
		return null;
	}
	
	default boolean hasPrefixSeparator() {
		return getProviderNetworkPrefixLength() != null;
	}
	
	/**
	 * If the address was created by parsing, this provides the parameters used when creating the address.
	 * 
	 * @return the parameters used to create the address, or null if no such parameters were used.
	 */
	default IPAddressStringParameters getParameters() {
		return null;
	}
	
	//for addresses that cannot produce an ipv4 or ipv6 value and has no prefix either
	abstract static class NullProvider implements IPAddressProvider {
		private static final long serialVersionUID = 4L;
		private IPType type;
		
		public NullProvider(IPAddressProvider.IPType type) {
			this.type = type;
		}
		
		@Override
		public IPAddressProvider.IPType getType() {
			return type;
		}
		
		@Override
		public IPAddress getProviderHostAddress() {
			return null;
		}
		
		@Override
		public IPAddress getProviderAddress() {
			return null;
		}
		
		@Override
		public IPAddress getProviderAddress(IPVersion version) {
			return null;
		}
		
		@Override
		public int providerHashCode() {
			return Objects.hashCode(getType());
		}
		
		/**
		 * When a value provider produces no value, equality and comparison are based on the enum IPType,
		 * which can be null.
		 * @param o
		 * @return
		 */
		@Override
		public boolean equalsProvider(IPAddressProvider o) {
			if(this == o) {
				return true;
			}
			if(o instanceof NullProvider) {
				NullProvider other = (NullProvider) o;
				//this works with both null and also non-null since the type is an enum
				return getType() == other.getType();
			}
			return false;
		}
		
		@Override
		public String toString() {
			return String.valueOf(getType());
		}
	};
	
	/**
	 * Wraps an IPAddress for IPAddressString in the cases where no parsing is provided, the address exists already
	 * @param value
	 * @return
	 */
	public static IPAddressProvider getProviderFor(IPAddress address, IPAddress hostAddress) {
		return new CachedAddressProvider(address, hostAddress);
	}
	
	//constructor where we already have a value
	static class CachedAddressProvider implements IPAddressProvider {
		private static final long serialVersionUID = 4L;
		CachedIPAddresses<?> values;
		
		CachedAddressProvider() {}
		
		private CachedAddressProvider(IPAddress address, IPAddress hostAddress) {
			this.values = new CachedIPAddresses<IPAddress>(address, hostAddress);
		}
		
		@Override
		public IPVersion getProviderIPVersion() {
			return getProviderAddress().getIPVersion();
		}
		
		@Override
		public IPAddressProvider.IPType getType() {
			return IPType.from(getProviderIPVersion());
		}
		
		@Override
		public boolean isProvidingIPAddress() {
			return true;
		}
		
		@Override
		public boolean isProvidingIPv4() {
			return getProviderAddress().isIPv4();
		}
		
		@Override
		public boolean isProvidingIPv6() {
			return getProviderAddress().isIPv6();
		}
		
		@Override
		public IPAddress getProviderHostAddress()  {
			return values.getHostAddress();
		}
		
		@Override
		public IPAddress getProviderAddress()  {
			return values.getAddress();
		}
		
		@Override
		public Integer getProviderNetworkPrefixLength() {
			return getProviderAddress().getNetworkPrefixLength();
		}
		
		@Override
		public IPAddress getProviderAddress(IPVersion version) {
			IPVersion thisVersion = getProviderIPVersion();
			if(!version.equals(thisVersion)) {
				return null;
			}
			return getProviderAddress();
		}
		
		@Override
		public String toString() {
			return String.valueOf(getProviderAddress());
		}
	}
	
	static abstract class CachedAddressCreator extends CachedAddressProvider {
		private static final long serialVersionUID = 4L;

		@Override
		public IPAddress getProviderAddress(IPVersion version) {
			getProviderAddress();
			return super.getProviderAddress(version);
		}
		
		private CachedIPAddresses<?> getCachedAddresses()  {
			CachedIPAddresses<?> val = values;
			if(val == null) {
				synchronized(this) {
					val = values;
					if(val == null) {
						values = val = createAddresses();
					}
				}
			}
			return val;
		}
		
		@Override
		public IPAddress getProviderHostAddress()  {
			return getCachedAddresses().getHostAddress();
		}
		
		@Override
		public IPAddress getProviderAddress()  {
			return getCachedAddresses().getAddress();
		}
		
		@Override
		public Integer getProviderNetworkPrefixLength() {
			getProviderAddress();
			return super.getProviderNetworkPrefixLength();
		}
		
		abstract CachedIPAddresses<?> createAddresses();
	}
	
	static abstract class VersionedAddressCreator extends CachedAddressCreator {
		private static final long serialVersionUID = 4L;
		IPAddress versionedValues[];
		protected final IPAddressStringParameters options;
		
		VersionedAddressCreator(IPAddressStringParameters options) {
			this.options = options;
		}
		
		@Override
		public IPAddressStringParameters getParameters() {
			return options;
		}
		
		private IPAddress checkResult(IPVersion version, int index) {
			IPAddress result = versionedValues[index];
			if(result == null) {
				versionedValues[index] = result = createVersionedAddress(version);
			}
			return result;
		}
		
		@Override
		public IPAddress getProviderAddress(IPVersion version) {
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
	
	static abstract class AdjustedAddressCreator extends VersionedAddressCreator {
		private static final long serialVersionUID = 4L;
		protected final IPVersion adjustedVersion;
		protected final Integer networkPrefixLength;
		
		AdjustedAddressCreator(Integer networkPrefixLength, IPAddressStringParameters options) {
			this(networkPrefixLength, null, options);
		}
		
		AdjustedAddressCreator(Integer networkPrefixLength, IPVersion adjustedVersion, IPAddressStringParameters options) {
			super(options);
			this.networkPrefixLength = networkPrefixLength;
			this.adjustedVersion = adjustedVersion;
		}
		
		@Override
		public boolean isProvidingIPAddress() {
			return adjustedVersion != null;
		}
		
		@Override
		public boolean isProvidingIPv4() {
			return isProvidingIPAddress() && adjustedVersion.isIPv4();
		}
		
		@Override
		public boolean isProvidingIPv6() {
			return isProvidingIPAddress() && adjustedVersion.isIPv6();
		}
		
		@Override
		public IPVersion getProviderIPVersion() {
			return adjustedVersion;
		}
		
		@Override
		public Integer getProviderNetworkPrefixLength() {
			return networkPrefixLength;
		}
		
		@Override
		public IPAddress getProviderAddress()  {
			if(adjustedVersion == null) {
				return null;
			}
			return super.getProviderAddress();
		}
		
		@Override
		public IPAddress getProviderHostAddress()  {
			if(adjustedVersion == null) {
				return null;
			}
			return super.getProviderHostAddress();
		}
	}
	
	static class MaskCreator extends AdjustedAddressCreator {
		private static final long serialVersionUID = 4L;
		
		MaskCreator(Integer networkPrefixLength, IPAddressStringParameters options) {
			super(networkPrefixLength, options);
		}
		
		MaskCreator(Integer networkPrefixLength, IPVersion adjustedVersion, IPAddressStringParameters options) {
			super(networkPrefixLength, adjustedVersion, options);
		}
		
		@Override
		public int providerHashCode() {
			if(adjustedVersion == null) {
				return getProviderNetworkPrefixLength();
			}
			return getProviderAddress().hashCode();
		}
		
		@Override
		public boolean equalsProvider(IPAddressProvider valueProvider) {
			if(valueProvider == this) {
				return true;
			}
			if(adjustedVersion == null) {
				if(valueProvider.getType() == IPType.PREFIX_ONLY) {//both are PREFIX_ONLY
					return valueProvider.getProviderNetworkPrefixLength().intValue() == getProviderNetworkPrefixLength().intValue();
				}
				return false;
			}
			return super.equalsProvider(valueProvider);
		}
		
		@Override
		public int providerCompare(IPAddressProvider other) {
			if(this == other) {
				return 0;
			}
			if(adjustedVersion == null) {
				if(other.getType() == IPType.PREFIX_ONLY) {//both are PREFIX_ONLY
					return other.getProviderNetworkPrefixLength().intValue() - getProviderNetworkPrefixLength().intValue();
				}
				return IPType.PREFIX_ONLY.ordinal() - other.getType().ordinal();
			}
			IPAddress otherValue = other.getProviderAddress();
			if(otherValue != null) {
				return getProviderAddress().compareTo(otherValue);
			}
			return IPType.from(adjustedVersion).ordinal() - other.getType().ordinal();
		}

		private IPAddress createVersionedMask(IPVersion version, int bits, boolean withPrefixLength) {
			IPAddressNetwork<?, ?, ?, ?, ?> network = version.isIPv4() ? options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
			return network.getNetworkMask(bits, withPrefixLength);
		}
		
		@Override
		IPAddress createVersionedAddress(IPVersion version) {
			return createVersionedMask(version, getProviderNetworkPrefixLength(), true);
		}
		
		@Override
		public IPAddressProvider.IPType getType() {
			if(adjustedVersion != null) {
				return IPType.from(adjustedVersion);
			}
			return IPType.PREFIX_ONLY;
		}
		
		@Override
		public boolean isProvidingPrefixOnly() {
			return adjustedVersion == null;
		}
		
		@Override
		CachedIPAddresses<?> createAddresses() {
			return new CachedIPAddresses<IPAddress>(
					createVersionedMask(adjustedVersion, getProviderNetworkPrefixLength(), true),
					createVersionedMask(adjustedVersion, getProviderNetworkPrefixLength(), false));
		}
	}
	
	static class LoopbackCreator extends VersionedAddressCreator {
		private static final long serialVersionUID = 4L;
		private final CharSequence zone;
		
		LoopbackCreator(IPAddressStringParameters options) {
			this(null, options);
		}

		LoopbackCreator(CharSequence zone, IPAddressStringParameters options) {
			super(options);
			this.zone = zone;
		}
		
		@Override
		public IPAddressProvider.IPType getType() {
			return IPType.from(getProviderIPVersion());
		}
		
		@Override
		public boolean isProvidingIPAddress() {
			return true;
		}
		
		@Override
		public boolean isProvidingIPv4() {
			return getProviderAddress().isIPv4();
		}
		
		@Override
		public boolean isProvidingIPv6() {
			return getProviderAddress().isIPv6();
		}
		
		@Override
		IPAddress createVersionedAddress(IPVersion version) {
			if(values != null && version.equals(values.getAddress().getIPVersion())) {
				return values.getAddress();
			}
			IPAddressNetwork<? extends IPAddress, ?, ?, ?, ?> network = version.isIPv4() ? options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
			IPAddress address = network.getLoopback();
			if(zone != null && zone.length() > 0 && version.isIPv6()) {
				ParsedAddressCreator<? extends IPAddress, ?, ?, ?> addressCreator = network.getAddressCreator();
				return addressCreator.createAddressInternal(address.getBytes(), zone);
			}
			return address;
		}
		
		@Override
		CachedIPAddresses<IPAddress> createAddresses() {
			InetAddress loopback = InetAddress.getLoopbackAddress();
			boolean isIPv6 = loopback instanceof Inet6Address;
			IPAddress result;
			if(zone != null && zone.length() > 0 && isIPv6) {
				ParsedAddressCreator<? extends IPAddress, ?, ?, ?> addressCreator = options.getIPv6Parameters().getNetwork().getAddressCreator();
				result = addressCreator.createAddressInternal(loopback.getAddress(), zone);
			} else if(isIPv6) {
				result = options.getIPv6Parameters().getNetwork().getLoopback();
			} else {
				result = options.getIPv4Parameters().getNetwork().getLoopback();
			}
			return new CachedIPAddresses<IPAddress>(result);
		}
		
		@Override
		public IPVersion getProviderIPVersion() {
			return getProviderAddress().getIPVersion();	
		}
		
		@Override
		public Integer getProviderNetworkPrefixLength() {
			return null;
		}
	}
	
	static class AllCreator extends AdjustedAddressCreator {
		private static final long serialVersionUID = 4L;
		HostIdentifierString originator;
		ParsedHostIdentifierStringQualifier qualifier;
		
		AllCreator(ParsedHostIdentifierStringQualifier qualifier, HostIdentifierString originator, IPAddressStringParameters options) {
			super(qualifier.getNetworkPrefixLength(), options);
			this.originator = originator;
			this.qualifier = qualifier;
		}
		
		AllCreator(ParsedHostIdentifierStringQualifier qualifier, IPVersion adjustedVersion, HostIdentifierString originator, IPAddressStringParameters options) {
			super(qualifier.getNetworkPrefixLength(), adjustedVersion, options);
			this.originator = originator;
			this.qualifier = qualifier;
		}
		
		@Override
		IPAddress createVersionedAddress(IPVersion version) {
			return ParsedIPAddress.createAllAddress(version, qualifier, originator, options);
		}

		@Override
		public IPAddressProvider.IPType getType() {
			if(adjustedVersion != null) {
				return IPType.from(adjustedVersion);
			}
			return IPType.ALL;
		}
		
		@Override
		public Boolean contains(IPAddressProvider otherProvider) {
			if(otherProvider.isInvalid()) {
				return Boolean.FALSE;
			} else if(adjustedVersion == null) {
				return Boolean.TRUE;
			}
			return adjustedVersion == otherProvider.getProviderIPVersion();
		}
		
		@Override
		public boolean isProvidingAllAddresses() {
			return adjustedVersion == null;
		}
		
		@Override
		public int providerHashCode() {
			if(adjustedVersion == null) {
				return IPAddress.SEGMENT_WILDCARD_STR.hashCode();
			}
			return super.hashCode();
		}
		
		@Override
		CachedIPAddresses<?> createAddresses() {
			return new CachedIPAddresses<IPAddress>(ParsedIPAddress.createAllAddress(adjustedVersion, qualifier, originator, options));
		}
	}
}
