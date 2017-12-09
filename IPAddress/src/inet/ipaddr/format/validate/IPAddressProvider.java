/*
 * Copyright 2017 Sean C Foley
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
import inet.ipaddr.format.validate.ParsedIPAddress.IPAddresses;

/**
 * Provides an address corresponding to a parsed string.
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressProvider implements Serializable, Comparable<IPAddressProvider> {
	//All IP address strings corresponds to exactly one of these types.
	//In cases where there is no corresponding default IPAddress value (INVALID, ALL, and possibly EMPTY), these types can be used for comparison.
	//EMPTY means a zero-length string (useful for validation, we can set validation to allow empty strings) that has no corresponding IPAddress value (validation options allow you to map empty to the loopback)
	//INVALID means it is known that it is not any of the other allowed types (validation options can restrict the allowed types)
	//ALL means it is wildcard(s) with no separators, like "*", which represents all addresses, whether IPv4, IPv6 or other, and thus has no corresponding IPAddress value
	//this enum is ordered by address space size, from smallest to largest, and the ordering affects comparisons
	private enum IPType {
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
	
	private static final long serialVersionUID = 4L;

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
	
	private IPAddressProvider() {}
	
	public abstract IPAddressProvider.IPType getType();
	
	public abstract IPAddress getHostAddress();
	
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
	public int compareTo(IPAddressProvider other) {
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
		if(o instanceof IPAddressProvider) {
			IPAddressProvider other = (IPAddressProvider) o;
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
	
	public boolean isBase85IPv6() {
		return false;
	}
	
	public Integer getNetworkPrefixLength() {
		return null;
	}
	
	public boolean isPrefixed() {
		return getNetworkPrefixLength() != null;
	}
	
	/**
	 * If the address was created by parsing, this provides the parameters used when creating the address.
	 * 
	 * @return the parameters used to create the address, or null if no such parameters were used.
	 */
	public IPAddressStringParameters getParameters() {
		return null;
	}
	
	@Override
	public String toString() {
		return String.valueOf(getAddress());
	}
	
	//for addresses that cannot produce an ipv4 or ipv6 value and has no prefix either
	private abstract static class NullProvider extends IPAddressProvider {
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
		public IPAddress getHostAddress() {
			return null;
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
	public static IPAddressProvider getProviderFor(IPAddress address, IPAddress hostAddress) {
		return new CachedAddressProvider(address, hostAddress);
	}
	
	//constructor where we already have a value
	private static class CachedAddressProvider extends IPAddressProvider {
		private static final long serialVersionUID = 4L;
		CachedIPAddresses<?> values;
		
		CachedAddressProvider() {}
		
		private CachedAddressProvider(IPAddress address, IPAddress hostAddress) {
			this.values = new CachedIPAddresses<IPAddress>(address, hostAddress);
		}
		
		@Override
		public IPVersion getIPVersion() {
			return getAddress().getIPVersion();
		}
		
		@Override
		public IPAddressProvider.IPType getType() {
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
		public IPAddress getHostAddress()  {
			return values.getHostAddress();
		}
		
		@Override
		public IPAddress getAddress()  {
			return values.getAddress();
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			return getAddress().getNetworkPrefixLength();
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
		private static final long serialVersionUID = 4L;

		@Override
		public IPAddress getAddress(IPVersion version) {
			getAddress();
			return super.getAddress(version);
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
		public IPAddress getHostAddress()  {
			return getCachedAddresses().getHostAddress();
		}
		
		@Override
		public IPAddress getAddress()  {
			return getCachedAddresses().getAddress();
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			getAddress();
			return super.getNetworkPrefixLength();
		}
		
		abstract CachedIPAddresses<?> createAddresses();
	}
	
	static class ParsedAddressProvider extends CachedAddressCreator {
		private static final long serialVersionUID = 4L;
		private ParsedIPAddress parseResult;
		private IPVersion version;
		boolean isMixedIPv6;
		boolean isBase85IPv6;
		
		ParsedAddressProvider(ParsedIPAddress parseResult) {
			this.parseResult = parseResult;
			this.version = parseResult.getIPVersion();
			this.isMixedIPv6 = parseResult.isMixedIPv6();
			this.isBase85IPv6 = parseResult.isBase85IPv6();
		}
	
		@Override
		public boolean isMixedIPv6() {
			return isMixedIPv6;
		}
		
		@Override
		public boolean isBase85IPv6() {
			return isBase85IPv6;
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
		IPAddresses<?,?> createAddresses() {
			IPAddresses<?,?> result = parseResult.createAddresses();
			parseResult = null;
			return result;
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			ParsedIPAddress parsedAddress = parseResult;//getting this as a local makes it thread-safe
			if(parsedAddress != null) {
				return parsedAddress.getNetworkPrefixLength();
			}
			return super.getNetworkPrefixLength();
		}
		
		@Override
		public boolean isPrefixed() {
			ParsedIPAddress parsedAddress = parseResult;//getting this as a local makes it thread-safe
			if(parsedAddress != null) {
				return parsedAddress.isPrefixed();
			}
			return super.isPrefixed();
		}
		
		@Override
		public IPAddressStringParameters getParameters() {
			return parseResult.options;
		}
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
		private static final long serialVersionUID = 4L;
		protected final IPVersion adjustedVersion;
		protected final ParsedHostIdentifierStringQualifier qualifier;
		
		AdjustedAddressCreator(ParsedHostIdentifierStringQualifier qualifier, IPAddressStringParameters options) {
			this(qualifier, null, options);
		}
		
		AdjustedAddressCreator(ParsedHostIdentifierStringQualifier qualifier, IPVersion adjustedVersion, IPAddressStringParameters options) {
			super(options);
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
		
		@Override
		public IPAddress getHostAddress()  {
			if(adjustedVersion == null) {
				return null;
			}
			return super.getHostAddress();
		}
	}
	
	static class MaskCreator extends AdjustedAddressCreator {
		private static final long serialVersionUID = 4L;
		
		MaskCreator(ParsedHostIdentifierStringQualifier qualifier, IPAddressStringParameters options) {
			super(qualifier, options);
		}
		
		MaskCreator(ParsedHostIdentifierStringQualifier qualifier, IPVersion adjustedVersion, IPAddressStringParameters options) {
			super(qualifier, adjustedVersion, options);
		}
		
		@Override
		public int hashCode() {
			if(adjustedVersion == null) {
				return getNetworkPrefixLength();
			}
			return getAddress().hashCode();
		}
		
		@Override
		public boolean equals(Object o) {
			if(o == this) {
				return true;
			}
			if(o instanceof IPAddressProvider) {
				IPAddressProvider valueProvider = (IPAddressProvider) o;
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
		public int compareTo(IPAddressProvider other) {
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

		private IPAddress createVersionedMask(IPVersion version, int bits, boolean withPrefixLength) {
			IPAddressNetwork<?, ?, ?, ?, ?> network = version.isIPv4() ? options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
			return network.getNetworkMask(bits, withPrefixLength);
		}
		
		@Override
		IPAddress createVersionedAddress(IPVersion version) {
			return createVersionedMask(version, getNetworkPrefixLength(), true);
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			return qualifier.getNetworkPrefixLength();
		}

		@Override
		public IPAddressProvider.IPType getType() {
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
		CachedIPAddresses<?> createAddresses() {
			return new CachedIPAddresses<IPAddress>(
					createVersionedMask(adjustedVersion, getNetworkPrefixLength(), true),
					createVersionedMask(adjustedVersion, getNetworkPrefixLength(), false));
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
		public IPVersion getIPVersion() {
			return getAddress().getIPVersion();	
		}
		
		@Override
		public Integer getNetworkPrefixLength() {
			return null;
		}
	}
	
	static class AllCreator extends AdjustedAddressCreator {
		private static final long serialVersionUID = 4L;
		HostIdentifierString originator;
		
		AllCreator(ParsedHostIdentifierStringQualifier qualifier, HostIdentifierString originator, IPAddressStringParameters options) {
			super(qualifier, options);
			this.originator = originator;
		}
		
		AllCreator(ParsedHostIdentifierStringQualifier qualifier, IPVersion adjustedVersion, HostIdentifierString originator, IPAddressStringParameters options) {
			super(qualifier, adjustedVersion, options);
			this.originator = originator;
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
		public boolean isAllAddresses() {
			return adjustedVersion == null;
		}
		
		@Override
		public int hashCode() {
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
