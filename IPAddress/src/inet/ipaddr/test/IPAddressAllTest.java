package inet.ipaddr.test;

import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;

public class IPAddressAllTest extends IPAddressRangeTest {
	
	private static final IPAddressStringParameters DEFAULT_OPTIONS = new IPAddressStringParameters.Builder().toParams();
	
	IPAddressAllTest(AddressCreator creator) {
		super(creator);
	}
	
	@Override
	protected IPAddressString createInetAtonAddress(String x) {
		return createAddress(x);
	}
	
	@Override
	protected IPAddressString createAddress(String x) {
		return createAddress(x, DEFAULT_OPTIONS);
	}

	@Override
	boolean isLenient() {
		return true;
	}
	
	@Override
	void runTest() {
		super.runTest();
	}
}
