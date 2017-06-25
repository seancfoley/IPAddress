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

package inet.ipaddr.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;

import inet.ipaddr.HostName;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.test.IPAddressTest.HostKey;
import inet.ipaddr.test.IPAddressTest.IPAddressKey;
import inet.ipaddr.test.IPAddressTest.IPAddressStringKey;

public class TestRunner extends TestBase implements AddressCreator {
	
	public static void main(String args[]) {
		TestRunner testRunner = new TestRunner();
		for(int i=0; i<args.length; i++) {
			String arg = args[i];
			if(arg.equalsIgnoreCase("fast")) {
				HostTest.runDNS = false;
				testRunner.fullTest = false;
			} else if(arg.equalsIgnoreCase("limited")) {
				HostTest.runDNS = false;
				testRunner.limited = true;
			} else if(arg.equalsIgnoreCase("performance")) {
				HostTest.runDNS = false;
				testRunner.performance = true;
			}
		}
		testRunner.runTest();
	}

	private static interface Creator<K, V> {
		V create(K k);
	}
	
	private Creator<HostKey, HostName> hostCreator = new Creator<HostKey, HostName>() {
		@Override
		public HostName create(HostKey hostKey) {
			if(hostKey.options == null) {
				return new HostName(hostKey.keyString, TestBase.HOST_OPTIONS);
			}
			return new HostName(hostKey.keyString, hostKey.options);
		}
	};
	
	private Creator<IPAddressStringKey, IPAddressString> ipAddressStringCreator = new Creator<IPAddressStringKey, IPAddressString>() {
		@Override
		public IPAddressString create(IPAddressStringKey addressStringKey) {
			if(addressStringKey.options == null) {
				return new IPAddressString(addressStringKey.keyString, TestBase.ADDRESS_OPTIONS);
			}
			return new IPAddressString(addressStringKey.keyString, addressStringKey.options);
		}
	};
	
	private Creator<IPAddressKey, IPAddress> ipAddressCreator = new Creator<IPAddressKey, IPAddress>() {
		@Override
		public IPAddress create(IPAddressKey addressKey) {
			if(addressKey.bytes.length == 4) {
				return new IPv4Address(addressKey.bytes);
			}
			return new IPv6Address(addressKey.bytes);
		}
	};
	
	static boolean DEBUG_CACHE;
	
	private static class Cache implements Serializable {

		private static final long serialVersionUID = 1L;
		
		ConcurrentHashMap<IPAddressStringKey, IPAddressString> cachingIPStringMap = new ConcurrentHashMap<IPAddressStringKey, IPAddressString>();
		ConcurrentHashMap<IPAddressKey, IPAddress> cachingIPMap = new ConcurrentHashMap<IPAddressKey, IPAddress>();
		ConcurrentHashMap<HostKey, HostName> cachingHostMap = new ConcurrentHashMap<HostKey, HostName>();
		
		private static <K, V> V getFromMap(Map<K, V> map, K key, Creator<K, V> creator) {
			V result = map.get(key);
			if(result == null) {
				synchronized(map) {
					result = map.get(key);
					if(result == null) {
						result = creator.create(key);
						map.put(key, result);
					} else {
						if(DEBUG_CACHE)
							System.out.println("reusing " + result);
					}
				}
			} else {
				if(DEBUG_CACHE)
					System.out.println("reusing " + result);
			}
			return result;
		}
		
		IPAddress getFromAddressMap(IPAddressKey key, Creator<IPAddressKey, IPAddress> addressCreator) {
			return getFromMap(cachingIPMap, key, addressCreator);
		}
		
		IPAddressString getFromAddressStringMap(IPAddressStringKey key, Creator<IPAddressStringKey, IPAddressString> addressStringCreator) {
			return getFromMap(cachingIPStringMap, key, addressStringCreator);
		}
		
		HostName getFromHostMap(HostKey key, Creator<HostKey, HostName> hostCreator) {
			return getFromMap(cachingHostMap, key, hostCreator);
		}
		
		void clear() {
			cachingIPStringMap.clear();
			cachingIPMap.clear();
			cachingHostMap.clear();
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof Cache) {
				Cache other = (Cache) o;
				return cachingIPStringMap.equals(other.cachingIPStringMap) &&
						cachingIPMap.equals(other.cachingIPMap) && 
						cachingHostMap.equals(other.cachingHostMap);
			}
			return false;
		}
		
		@Override
		public String toString() {
			return "IPAddressString count: " + cachingIPStringMap.size() + "; IPAddress count: " + cachingIPMap.size() + "; Host count: " + cachingHostMap.size() + "; ";
		}
	}
	
	public Cache serialize(Cache input) throws IOException, ClassNotFoundException {
		EfficientByteArrayOuputStream outmine = new EfficientByteArrayOuputStream();
		ObjectOutput outputmine = new ObjectOutputStream(outmine);
		outputmine.writeObject(input);
		outputmine.close();
		List<? extends byte[]> bytesmine = outmine.getBytes();
		EfficientByteArrayInputStream inmine = new EfficientByteArrayInputStream(bytesmine);
		//System.out.println("total is " + outmine.getCount());
		try (ObjectInput inputmine = new ObjectInputStream(inmine)) {
			return (Cache) inputmine.readObject();
		}
	}
	
	public static class EfficientByteArrayOuputStream extends OutputStream {
		public static final int BOUNDARY_SIZE = 1024;
		final LinkedList<byte[]> streamList = new LinkedList<byte[]>();
		private int currentCount;
		
		public EfficientByteArrayOuputStream() {
			add();
		}
		
		List<? extends byte[]> getBytes() {
			ArrayList<byte[]> result = new ArrayList<byte[]>(streamList);
			int lastIndex = result.size() - 1;
			if(currentCount < BOUNDARY_SIZE) {
				byte last[] = streamList.getLast();
				last = Arrays.copyOf(last, currentCount);
				result.add(lastIndex, last);
			}
			return result;
		}
		
		byte[] toByteArray() {
			byte result[] = new byte[getCount()];
			int current = 0;
			for(int i = 0; i < streamList.size() - 1; i++, current += BOUNDARY_SIZE) {
				byte bytes[] = streamList.get(i);
				System.arraycopy(bytes, 0, result, current, BOUNDARY_SIZE);
			}
			byte last[] = streamList.getLast();
			System.arraycopy(last, 0, result, current, currentCount);
			return result;
		}
		
		int getCount() {
			int total = 0;
			for(byte bytes[] : streamList) {
				total += bytes.length;
			}
			total -= (BOUNDARY_SIZE - currentCount);
			return total;
		}
		
		private byte[] add() {
			byte toAdd[] = new byte[BOUNDARY_SIZE];
			streamList.add(toAdd);
			currentCount = 0;
			return toAdd;
		}
		
		@Override
		public void write(int b) throws IOException {
			byte current[];
			if(currentCount == BOUNDARY_SIZE) {
				current = add();
			} else {
				current = streamList.getLast();
			}
			current[currentCount++] = (byte) b;
		}

	    @Override
		public void write(byte b[], int off, int len) throws IOException {
	    	byte current[] = streamList.getLast();
	    	while(currentCount + len > BOUNDARY_SIZE) {
		    	int toWrite = BOUNDARY_SIZE - currentCount;
		    	System.arraycopy(b, off, current, currentCount, toWrite);
		    	len -= toWrite;
		    	off += toWrite;
		    	current = add();
		    }
	    	System.arraycopy(b, off, current, currentCount, len);
	    	currentCount += len;
	    }
	}
	
	public static class EfficientByteArrayInputStream extends InputStream {
		private LinkedList<byte[]> streamList;
		private int currentCount;
		private int totalRead;
		
		EfficientByteArrayInputStream(List<? extends byte[]> initial) {
			streamList = new LinkedList<byte[]>(initial);
		}
		
		@Override
		public int read() throws IOException {
			if(streamList.isEmpty()) {
				return -1;
			}
			byte current[] = streamList.getFirst();
			int result = current[currentCount++];
			if(currentCount == current.length) {
				remove();
			}
			totalRead++;
			return result;
		}
		
		void remove() {
			currentCount = 0;
			streamList.removeFirst();
		}

	    @Override
		public int read(byte b[], int off, int len) throws IOException {
	    	int originalLen = len;
	    	if(streamList.isEmpty()) {
				return -1;
			}
	    	byte current[] = streamList.getFirst();
	    	while(currentCount + len >= current.length) {
	    		int bytes = current.length - currentCount;
	    		System.arraycopy(current, currentCount, b, off, bytes);
	    		len -= bytes;
	    		off += bytes;
	    		remove();
	    		if(streamList.isEmpty()) {
	    			return originalLen - len;
	    		}
	    		current = streamList.getFirst();
	    	}
	    	System.arraycopy(current, currentCount, b, off, len);
	    	currentCount += len;
	    	totalRead += len;
	    	return originalLen;
	    }
	    
	    int getBytesRead() {
	    	return totalRead;
	    }
	}
	
	private Cache cache = new Cache();
	private boolean CACHING = false; //set to true to share the same address and host objects among all tests
	boolean fullTest = true;//set this to false to exclude slow-running tests
	boolean limited = false;//set this to true to exclude caching and threading tests
	boolean performance = false;//set this to true to run performance tests
	
	TestRunner() {
		super(null);
	}
	
	@Override
	void runTest() {
		showMessage("Starting " + getClass().getSimpleName());
		//long startTime = System.currentTimeMillis();
		long startTime = System.nanoTime();
		
		runPerf(startTime);
		
		//final Failures failures = new Failures();
		failures.add(testAll());
		
		if(!limited) {
		
			//now set the caching and do it again
			CACHING = true;
			failures.add(testAll());
			failures.add(testAll());
	
			//now multi-threaded with the caching
			Thread threads[] = runInThreads(10, new Runnable() {
				@Override
				public void run() {
					failures.add(testAll());
				}
			});

			try {
				for(Thread thread : threads) {
					thread.join();
				}
				
				//now use caching but start with a fresh cache, to test synchronization better
				cache.clear();
				
				threads = runInThreads(10, new Runnable() {
					@Override
					public void run() {
						failures.add(testAll());
					}
				});
				Thread threads2[] = runInThreads(5, new Runnable() {
					@Override
					public void run() {
						failures.add(testAll());
					}
				});
				for(Thread thread : threads) {
					thread.join();
				}
				for(Thread thread : threads2) {
					thread.join();
				}
			} catch(InterruptedException e) {
				e.printStackTrace();
			}
			
			try {
				Cache oldCache = cache;
				cache = serialize(oldCache);
				//DEBUG_CACHE = true;
				if(!oldCache.equals(cache)) {
					failures.numTested++;
					failures.failures.add(new Failure("serialized cache mismatch"));
					System.out.println(oldCache.equals(cache));
				}
				failures.add(testAll());
			} catch(IOException | ClassNotFoundException e) {
				failures.numTested++;
				failures.failures.add(new Failure(e.toString()));
			}
			runPerf(System.nanoTime());
		}
		report();
		showMessage("Done in " + (System.nanoTime() - startTime)/1000000 + " milliseconds");
	}

	private void runPerf(long startTime) {
		if(performance) {
			long perfStartTime = startTime;
			for(int i = 0; i < 10; i++) {
				failures.add(testAll());
				//long endTime = System.currentTimeMillis();
				long endTime = System.nanoTime();
				long totalTime = endTime - perfStartTime;
				perf.addTime(totalTime);
				perfStartTime = endTime;
			}
		}
	}
	
	Thread[] runInThreads(int numThreads, final Runnable runnable) {
		Thread threads[] = new Thread[numThreads];
		final CyclicBarrier barrier = new CyclicBarrier(numThreads);
		for(int i = 0; i < numThreads; i++) {
			Thread thread = new Thread() {
				@Override
				public void run() {
					try {
						barrier.await();
						runnable.run();
					} catch (InterruptedException | BrokenBarrierException e) {
						e.printStackTrace();
					}
				}
			};
			threads[i] = thread;
			thread.start();
		}
		return threads;
	}
	
	public Failures testAll() {
		Failures failures = new Failures();
		TestBase tests[] = new TestBase[] {
				new SpecialTypesTest(this),
				new IPAddressTest(this),
				new HostTest(this),
				new IPAddressRangeTest(this),
				new IPAddressAllTest(this),
				new HostRangeTest(this)};
		for(TestBase test : tests) {
			test.fullTest = fullTest;
			test.runTest();
			failures.add(test.failures);
		}
		return failures;
	}
	
	@Override
	public HostName createHost(HostKey key) {
		if(CACHING) {
			return cache.getFromHostMap(key, hostCreator);
		}
		return hostCreator.create(key);
	}
	
	@Override
	public IPAddressString createAddress(IPAddressStringKey key) {
		if(CACHING) {
			return cache.getFromAddressStringMap(key, ipAddressStringCreator);
		}
		return ipAddressStringCreator.create(key);
	}
	
	@Override
	public IPAddress createAddress(byte bytes[]) {
		IPAddressKey key = new IPAddressKey(bytes);
		if(CACHING) {
			return cache.getFromAddressMap(key, ipAddressCreator);
		}
		return ipAddressCreator.create(key);
	}
}
