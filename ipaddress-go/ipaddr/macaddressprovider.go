package ipaddr

type MACAddressProvider interface {
	//getAddress() MACAddress
}

type MACAddressEmptyProvider struct{}

var macAddressEmptyProvider = MACAddressEmptyProvider{}

type MACAddressAllProvider struct {
	validationOptions MACAddressStringParameters
}

var macAddressDefaultAllProvider = &MACAddressAllProvider{defaultMACAddrParameters}

//public interface MACAddressProvider extends Serializable {
//
//	@SuppressWarnings("serial")
//	static final MACAddressProvider EMPTY_PROVIDER = new MACAddressProvider() {
//
//		@Override
//		public MACAddress getAddress() {
//			return null;
//		}
//
//		@Override
//		public String toString() {
//			return "null";
//		}
//	};
//
//	static final class ParsedMACAddressProvider implements MACAddressProvider {
//
//		private static final long serialVersionUID = 4L;
//
//		private ParsedMACAddress parsedAddress;
//		private MACAddress address;
//
//		public ParsedMACAddressProvider(MACAddress address) {
//			this.address = address;
//		}
//
//		@Override
//		public MACAddress getAddress() {
//			if(parsedAddress != null) {
//				synchronized(this) {
//					if(parsedAddress != null) {
//						address = parsedAddress.createAddress();
//						parsedAddress = null;
//					}
//				}
//			}
//			return address;
//		}
//
//		@Override
//		public String toString() {
//			return String.valueOf(getAddress());
//		}
//
//	}
//
//	MACAddress getAddress();
//
//	public static MACAddressProvider getAllProvider(MACAddressStringParameters validationOptions) {
//		MACAddressNetwork network = validationOptions.getNetwork();
//		AddressSize allAddresses = validationOptions.addressSize;
//		MACAddressCreator creator = network.getAddressCreator();
//		MACAddressSegment allRangeSegment = creator.createRangeSegment(0, MACAddress.MAX_VALUE_PER_SEGMENT);
//		MACAddressSegment segments[] = creator.createSegmentArray(allAddresses == AddressSize.EUI64 ?
//			MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT :
//			MACAddress.MEDIA_ACCESS_CONTROL_SEGMENT_COUNT);
//		Arrays.fill(segments, allRangeSegment);
//		return new MACAddressProvider() {
//
//			private static final long serialVersionUID = 4L;
//
//			@Override
//			public MACAddress getAddress() {
//				ParsedAddressCreator<MACAddress, MACAddressSection, MACAddressSection, MACAddressSegment> parsedCreator = creator;
//				MACAddressSection section = parsedCreator.createSectionInternal(segments);
//				return creator.createAddress(section);
//			}
//
//			@Override
//			public String toString() {
//				return String.valueOf(getAddress());
//			}
//		};
//	}
//}
