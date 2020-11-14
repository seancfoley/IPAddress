package ipaddr

//TODO your provider types can be similar, you can have a base type that has all the methods that are "default" in Java
//With Java you added a lot of stuff to IPAddressProvider, here you can start with the basics, maybe you don't want to add the contains and prefixEquals and prefixContains shortcuts
//TODO this is your first big test with virtual methods, where you are in the lower type and you are calling the virtual method into the higher
// that is the one thing that go does not allow, you can override in go as long as you are calling from higher type
//
// 1. one way around it is the use of interfaces, where you pass things down on construction of higher type,
// providing a pathway back into the higher type
// in fact, that is sort of clever, a lower type has an interface pointing to itself, but that interface can be substituted
//
// 2. it's clecer but easy to get confused with that, another technique is function pointers
//
// 3. another way is a dup method of same name in higher type that calls down to the lower, so lower does not have to call up
// Kinda like overriding and works fine when calling from the higher
// Sub has x(), Base has x(), sub x calls Base x
//	This one is natural
//
// both 1,2 require "New" methods, 3 does not

//type CachedAddressProvider struct {
//	ipAddrProvider
//}

//constructor where we already have a value
//static class CachedAddressProvider implements IPAddressProvider {
//	private static final long serialVersionUID = 4L;
//	CachedIPAddresses<?> values;
//
//	CachedAddressProvider() {}
//
//	private CachedAddressProvider(IPAddress address, IPAddress hostAddress) {
//		this.values = new CachedIPAddresses<IPAddress>(address, hostAddress);
//	}
//
//	@Override
//	public IPVersion getProviderIPVersion() {
//		return getProviderAddress().getIPVersion();
//	}
//
//	@Override
//	public IPAddressProvider.IPType getType() {
//		return IPType.from(getProviderIPVersion());
//	}
//
//	@Override
//	public boolean isProvidingIPAddress() {
//		return true;
//	}
//
//	@Override
//	public boolean isProvidingIPv4() {
//		return getProviderAddress().isIPv4();
//	}
//
//	@Override
//	public boolean isProvidingIPv6() {
//		return getProviderAddress().isIPv6();
//	}
//
//	@Override
//	public IPAddress getProviderHostAddress()  {
//		return values.getHostAddress();
//	}
//
//	@Override
//	public IPAddress getProviderAddress()  {
//		return values.getAddress();
//	}
//
//	@Override
//	public Integer getProviderNetworkPrefixLength() {
//		return getProviderAddress().getNetworkPrefixLength();
//	}
//
//	@Override
//	public IPAddress getProviderAddress(IPVersion version) {
//		IPVersion thisVersion = getProviderIPVersion();
//		if(!version.equals(thisVersion)) {
//			return null;
//		}
//		return getProviderAddress();
//	}
//
//	@Override
//	public String toString() {
//		return String.valueOf(getProviderAddress());
//	}
//}

//type CachedAddressCreator struct {
//	CachedAddressProvider
//}

//static abstract class CachedAddressCreator extends CachedAddressProvider {
//	private static final long serialVersionUID = 4L;
//
//	@Override
//	public IPAddress getProviderAddress(IPVersion version) {
//		getProviderAddress();
//		return super.getProviderAddress(version);
//	}
//
//	private CachedIPAddresses<?> getCachedAddresses()  {
//		CachedIPAddresses<?> val = values;
//		if(val == null) {
//			synchronized(this) {
//				val = values;
//				if(val == null) {
//					values = val = createAddresses();
//				}
//			}
//		}
//		return val;
//	}
//
//	@Override
//	public IPAddress getProviderHostAddress()  {
//		return getCachedAddresses().getHostAddress();
//	}
//
//	@Override
//	public IPAddress getProviderAddress()  {
//		return getCachedAddresses().getAddress();
//	}
//
//	@Override
//	public Integer getProviderNetworkPrefixLength() {
//		getProviderAddress();
//		return super.getProviderNetworkPrefixLength();
//	}
//
//	abstract CachedIPAddresses<?> createAddresses();
//}

//type VersionedAddressCreator struct {
//	ipAddrProvider
//	parameters IPAddressStringParameters
//}

//static abstract class VersionedAddressCreator extends CachedAddressCreator {
//		private static final long serialVersionUID = 4L;
//		IPAddress versionedValues[];
//		protected final IPAddressStringParameters options;
//
//		VersionedAddressCreator(IPAddressStringParameters options) {
//			this.options = options;
//		}
//
//		@Override
//		public IPAddressStringParameters getParameters() {
//			return options;
//		}
//
//		private IPAddress checkResult(IPVersion version, int index) {
//			IPAddress result = versionedValues[index];
//			if(result == null) {
//				versionedValues[index] = result = createVersionedAddress(version);
//			}
//			return result;
//		}
//
//		@Override
//		public IPAddress getProviderAddress(IPVersion version) {
//			int index = version.ordinal();
//			IPAddress result;
//			if(versionedValues == null) {
//				synchronized(this) {
//					if(versionedValues == null) {
//						versionedValues = new IPAddress[IPVersion.values().length];
//						versionedValues[index] = result = createVersionedAddress(version);
//					} else {
//						result = checkResult(version, index);
//					}
//				}
//			} else {
//				result = versionedValues[index];
//				if(result == null) {
//					synchronized(this) {
//						result = checkResult(version, index);
//					}
//				}
//			}
//			return result;
//		}
//
//		abstract IPAddress createVersionedAddress(IPVersion version);
//	}
//
//type AdjustedAddressCreator struct {
//	VersionedAddressCreator
//
//	adjustedVersion     IPVersion
//	networkPrefixLength PrefixLen
//}
//
//static abstract class AdjustedAddressCreator extends VersionedAddressCreator {
//	private static final long serialVersionUID = 4L;
//	protected final IPVersion adjustedVersion;
//	protected final Integer networkPrefixLength;
//
//	AdjustedAddressCreator(Integer networkPrefixLength, IPAddressStringParameters options) {
//		this(networkPrefixLength, null, options);
//	}
//
//	AdjustedAddressCreator(Integer networkPrefixLength, IPVersion adjustedVersion, IPAddressStringParameters options) {
//		super(options);
//		this.networkPrefixLength = networkPrefixLength;
//		this.adjustedVersion = adjustedVersion;
//	}
//
//	@Override
//	public boolean isProvidingIPAddress() {
//		return adjustedVersion != null;
//	}
//
//	@Override
//	public boolean isProvidingIPv4() {
//		return isProvidingIPAddress() && adjustedVersion.isIPv4();
//	}
//
//	@Override
//	public boolean isProvidingIPv6() {
//		return isProvidingIPAddress() && adjustedVersion.isIPv6();
//	}
//
//	@Override
//	public IPVersion getProviderIPVersion() {
//		return adjustedVersion;
//	}
//
//	@Override
//	public Integer getProviderNetworkPrefixLength() {
//		return networkPrefixLength;
//	}
//
//	@Override
//	public IPAddress getProviderAddress()  {
//		if(adjustedVersion == null) {
//			return null;
//		}
//		return super.getProviderAddress();
//	}
//
//	@Override
//	public IPAddress getProviderHostAddress()  {
//		if(adjustedVersion == null) {
//			return null;
//		}
//		return super.getProviderHostAddress();
//	}
//}

//static class MaskCreator extends AdjustedAddressCreator {
//
//
//		MaskCreator(Integer networkPrefixLength, IPAddressStringParameters options) {
//			super(networkPrefixLength, options);
//		}
//
//		MaskCreator(Integer networkPrefixLength, IPVersion adjustedVersion, IPAddressStringParameters options) {
//			super(networkPrefixLength, adjustedVersion, options);
//		}
//
//		@Override
//		public int providerHashCode() {
//			if(adjustedVersion == null) {
//				return getProviderNetworkPrefixLength();
//			}
//			return getProviderAddress().hashCode();
//		}
//
//		@Override
//		public boolean providerEquals(IPAddressProvider valueProvider) {
//			if(valueProvider == this) {
//				return true;
//			}
//			if(adjustedVersion == null) {
//				if(valueProvider.getType() == IPType.PREFIX_ONLY) {//both are PREFIX_ONLY
//					return valueProvider.getProviderNetworkPrefixLength().intValue() == getProviderNetworkPrefixLength().intValue();
//				}
//				return false;
//			}
//			return super.providerEquals(valueProvider);
//		}
//
//		@Override
//		public int providerCompare(IPAddressProvider other) throws IncompatibleAddressException {
//			if(this == other) {
//				return 0;
//			}
//			if(adjustedVersion == null) {
//				if(other.getType() == IPType.PREFIX_ONLY) {//both are PREFIX_ONLY
//					return other.getProviderNetworkPrefixLength().intValue() - getProviderNetworkPrefixLength().intValue();
//				}
//				return IPType.PREFIX_ONLY.ordinal() - other.getType().ordinal();
//			}
//			IPAddress otherValue = other.getProviderAddress();
//			if(otherValue != null) {
//				return getProviderAddress().compareTo(otherValue);
//			}
//			return IPType.from(adjustedVersion).ordinal() - other.getType().ordinal();
//		}
//
//		private IPAddress createVersionedMask(IPVersion version, int bits, boolean withPrefixLength) {
//			IPAddressNetwork<?, ?, ?, ?, ?> network = version.isIPv4() ? options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
//			return withPrefixLength ? network.getNetworkAddress(bits) : network.getNetworkMask(bits, false);
//		}
//
//		@Override
//		IPAddress createVersionedAddress(IPVersion version) {
//			return createVersionedMask(version, getProviderNetworkPrefixLength(), true);
//		}
//
//		@Override
//		public IPAddressProvider.IPType getType() {
//			if(adjustedVersion != null) {
//				return IPType.from(adjustedVersion);
//			}
//			return IPType.PREFIX_ONLY;
//		}
//
//		@Override
//		public boolean isProvidingPrefixOnly() {
//			return adjustedVersion == null;
//		}
//
//		@Override
//		CachedIPAddresses<?> createAddresses() {
//			return new CachedIPAddresses<IPAddress>(
//					createVersionedMask(adjustedVersion, getProviderNetworkPrefixLength(), true),
//					createVersionedMask(adjustedVersion, getProviderNetworkPrefixLength(), false));
//		}
//	}
//
//type LoopbackCreator struct {
//	VersionedAddressCreator
//}

//static class LoopbackCreator extends VersionedAddressCreator {
//		private static final long serialVersionUID = 4L;
//		private final CharSequence zone;
//
//		LoopbackCreator(IPAddressStringParameters options) {
//			this(null, options);
//		}
//
//		LoopbackCreator(CharSequence zone, IPAddressStringParameters options) {
//			super(options);
//			this.zone = zone;
//		}
//
//		@Override
//		public IPAddressProvider.IPType getType() {
//			return IPType.from(getProviderIPVersion());
//		}
//
//		@Override
//		public boolean isProvidingIPAddress() {
//			return true;
//		}
//
//		@Override
//		public boolean isProvidingIPv4() {
//			return getProviderAddress().isIPv4();
//		}
//
//		@Override
//		public boolean isProvidingIPv6() {
//			return getProviderAddress().isIPv6();
//		}
//
//		@Override
//		IPAddress createVersionedAddress(IPVersion version) {
//			if(values != null && version.equals(values.getAddress().getIPVersion())) {
//				return values.getAddress();
//			}
//			IPAddressNetwork<? extends IPAddress, ?, ?, ?, ?> network = version.isIPv4() ? options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
//			IPAddress address = network.getLoopback();
//			if(zone != null && zone.length() > 0 && version.isIPv6()) {
//				ParsedAddressCreator<? extends IPAddress, ?, ?, ?> addressCreator = network.getAddressCreator();
//				return addressCreator.createAddressInternal(address.getBytes(), zone);
//			}
//			return address;
//		}
//
//		@Override
//		CachedIPAddresses<IPAddress> createAddresses() {
//			InetAddress loopback = InetAddress.getLoopbackAddress();
//			boolean isIPv6 = loopback instanceof Inet6Address;
//			IPAddress result;
//			if(zone != null && zone.length() > 0 && isIPv6) {
//				ParsedAddressCreator<? extends IPAddress, ?, ?, ?> addressCreator = options.getIPv6Parameters().getNetwork().getAddressCreator();
//				result = addressCreator.createAddressInternal(loopback.getAddress(), zone);
//			} else if(isIPv6) {
//				result = options.getIPv6Parameters().getNetwork().getLoopback();
//			} else {
//				result = options.getIPv4Parameters().getNetwork().getLoopback();
//			}
//			return new CachedIPAddresses<IPAddress>(result);
//		}
//
//		@Override
//		public IPVersion getProviderIPVersion() {
//			return getProviderAddress().getIPVersion();
//		}
//
//		@Override
//		public Integer getProviderNetworkPrefixLength() {
//			return null;
//		}
//	}

//type AllCreator struct {
//	AdjustedAddressCreator
//
//	originator HostIdentifierString
//	qualifier  ParsedHostIdentifierStringQualifier //TODO copy the original to here
//}
//
//func (all *AllCreator) getType() IPType {
//	if !all.adjustedVersion.isUnknown() {
//		return fromVersion(all.adjustedVersion)
//	}
//	return ALL
//}

//static class AllCreator extends AdjustedAddressCreator {
//	private static final long serialVersionUID = 4L;
//	HostIdentifierString originator;
//	ParsedHostIdentifierStringQualifier qualifier;
//
//	AllCreator(ParsedHostIdentifierStringQualifier qualifier, HostIdentifierString originator, IPAddressStringParameters options) {
//		super(qualifier.getEquivalentPrefixLength(), options);
//		this.originator = originator;
//		this.qualifier = qualifier;
//	}
//
//	AllCreator(ParsedHostIdentifierStringQualifier qualifier, IPVersion adjustedVersion, HostIdentifierString originator, IPAddressStringParameters options) {
//		super(qualifier.getEquivalentPrefixLength(), adjustedVersion, options);
//		this.originator = originator;
//		this.qualifier = qualifier;
//	}
//
//	@Override
//	IPAddress createVersionedAddress(IPVersion version) {
//		return ParsedIPAddress.createAllAddress(version, qualifier, originator, options);
//	}
//
//	@Override
//	public IPAddressProvider.IPType getType() {
//		if(adjustedVersion != null) {
//			return IPType.from(adjustedVersion);
//		}
//		return IPType.ALL;
//	}
//
//	@Override
//	public Boolean contains(IPAddressProvider otherProvider) {
//		if(otherProvider.isInvalid()) {
//			return Boolean.FALSE;
//		} else if(adjustedVersion == null) {
//			return Boolean.TRUE;
//		}
//		return adjustedVersion == otherProvider.getProviderIPVersion();
//	}
//
//	@Override
//	public boolean isProvidingAllAddresses() {
//		return adjustedVersion == null;
//	}
//
//	@Override
//	public int providerHashCode() {
//		if(adjustedVersion == null) {
//			return IPAddress.SEGMENT_WILDCARD_STR.hashCode();
//		}
//		return super.hashCode();
//	}
//
//	@Override
//	CachedIPAddresses<?> createAddresses() {
//		if(qualifier.equals(ParsedHost.NO_QUALIFIER)) {
//			return new CachedIPAddresses<IPAddress>(ParsedIPAddress.createAllAddress(adjustedVersion, qualifier, originator, options));
//		}
//		return new CachedIPAddresses<IPAddress>(ParsedIPAddress.createAllAddress(adjustedVersion, qualifier, originator, options),
//				ParsedIPAddress.createAllAddress(adjustedVersion, qualifier.getZone() != null ? new ParsedHostIdentifierStringQualifier(qualifier.getZone()) : ParsedHost.NO_QUALIFIER, originator, options));
//	}
//
//	@Override
//	public IPAddress getProviderMask() {
//		return qualifier.getMaskLower();
//	}
//
//	@Override
//	public IPAddressSeqRange getProviderSeqRange() {
//		if(isProvidingAllAddresses()) {
//			return null;
//		}
//		IPAddress mask = getProviderMask();
//		if(mask != null && mask.getBlockMaskPrefixLength(true) == null) {
//			// we must apply the mask
//			IPAddress all = ParsedIPAddress.createAllAddress(adjustedVersion, ParsedHost.NO_QUALIFIER, null, options);
//			IPAddress upper = all.getUpper().mask(mask);
//			IPAddress lower = all.getLower();
//			return lower.toSequentialRange(upper);
//		}
//		return super.getProviderSeqRange();
//	}
//
//	@Override
//	public boolean isSequential() {
//		return !isProvidingAllAddresses();
//	}
//
//	@Override
//	public IPAddressDivisionSeries getDivisionGrouping() throws IncompatibleAddressException {
//		if(isProvidingAllAddresses()) {
//			return null;
//		}
//		IPAddressNetwork<?, ?, ?, ?, ?> network = adjustedVersion.isIPv4() ?
//				options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
//		IPAddress mask = getProviderMask();
//		if(mask != null && mask.getBlockMaskPrefixLength(true) == null) {
//			// there is a mask
//			Integer hostMaskPrefixLen = mask.getBlockMaskPrefixLength(false);
//			if(hostMaskPrefixLen == null) { // not a host mask
//				throw new IncompatibleAddressException(getProviderAddress(), mask, "ipaddress.error.maskMismatch");
//			}
//			IPAddress hostMask = network.getHostMask(hostMaskPrefixLen);
//			return hostMask.toPrefixBlock();
//		}
//		IPAddressDivisionSeries grouping;
//		if(adjustedVersion.isIPv4()) {
//			grouping = new IPAddressDivisionGrouping(new IPAddressBitsDivision[] {
//						new IPAddressBitsDivision(0, IPv4Address.MAX_VALUE, IPv4Address.BIT_COUNT, IPv4Address.DEFAULT_TEXTUAL_RADIX, network, qualifier.getEquivalentPrefixLength())
//					}, network);
//		} else if(adjustedVersion.isIPv6()) {
//			byte upperBytes[] = new byte[16];
//			Arrays.fill(upperBytes, (byte) 0xff);
//			grouping = new IPAddressLargeDivisionGrouping(new IPAddressLargeDivision[] {new IPAddressLargeDivision(new byte[IPv6Address.BYTE_COUNT], upperBytes, IPv6Address.BIT_COUNT, IPv6Address.DEFAULT_TEXTUAL_RADIX, network, qualifier.getEquivalentPrefixLength())}, network);
//		} else {
//			grouping = null;
//		}
//		return grouping;
//	}
//}
