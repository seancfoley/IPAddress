# IPAddress
Java library for handling IP addresses and subnets, both IPv4 and IPv6

IP address and network manipulations, CIDR, operations, iterations, containment checks, longest prefix match, subnetting, and data structures, with polymorphic code 

[View Project Page](https://seancfoley.github.io/IPAddress/)

[View Code Examples](https://github.com/seancfoley/IPAddress/wiki/Code-Examples)

[View Javadoc](https://seancfoley.github.io/IPAddress/IPAddress/apidocs/)

[In the Maven Central Repository](https://repo1.maven.org/maven2/com/github/seancfoley/ipaddress/), packaged as an OSGI bundle, packaged as a [Linux Fedora rpm](http://rpmfind.net/linux/rpm2html/search.php?query=ipaddress), in [Apache Archiva on Wikimedia](https://archiva.wikimedia.org/#artifact/com.github.seancfoley/ipaddress)
- Maven group id: com.github.seancfoley
- Maven artifact id: [ipaddress](https://search.maven.org/search?q=ipaddress)
- Maven versions: [2.0.2](https://search.maven.org/artifact/com.github.seancfoley/ipaddress/2.0.2/jar), [3.0.0](https://search.maven.org/artifact/com.github.seancfoley/ipaddress/3.0.0/jar), [4.3.3](https://search.maven.org/artifact/com.github.seancfoley/ipaddress/4.3.3/jar), [5.3.4](https://search.maven.org/artifact/com.github.seancfoley/ipaddress/5.3.4/jar) 
- Latest Maven version: [![Maven Central](https://img.shields.io/maven-central/v/com.github.seancfoley/ipaddress.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22com.github.seancfoley%22%20AND%20a:%22ipaddress%22)
- OSGI bundle since version 5.3.1: com.github.seancfoley.ipaddress

![Java](https://github.com/seancfoley/IPAddress/blob/gh-pages/images/java_logo.png?raw=true) ![Kotlin](https://github.com/seancfoley/IPAddress/blob/gh-pages/images/kotlin_logo.png?raw=true)![Go](https://github.com/seancfoley/IPAddress/blob/gh-pages/images/go_logo.png?raw=true) ![Scala](https://github.com/seancfoley/IPAddress/blob/gh-pages/images/scala.png?raw=true)![Groovy](https://github.com/seancfoley/IPAddress/blob/gh-pages/images/groovy.png?raw=true)![Clojure](https://github.com/seancfoley/IPAddress/blob/gh-pages/images/clojure.png?raw=true)

As a [Java](https://www.oracle.com/java/) library, it is also interoperable with [Kotlin](https://kotlinlang.org/), [Scala](https://scala-lang.org/), [Groovy](http://www.groovy-lang.org/) and [Clojure](https://clojure.org/)

Available as a [Go](https://go.dev/) library from the [ipaddress-go repository](https://github.com/seancfoley/ipaddress-go)

[Integrate into Development: Intellij, Android, and Eclipse](https://github.com/seancfoley/IPAddress/wiki/Development-IDEs)

[Make your IPv4 App work with IPv6](https://seancfoley.github.io/IPAddress/ipaddress.html#make-your-ipv4-app-work-with-ipv6)

Version | Notes         |
------- | ------------- |
[1.0.1](https://github.com/seancfoley/IPAddress/releases/tag/v1.0.1) | Requires Java 6 or higher |
[2.0.2](https://github.com/seancfoley/IPAddress/releases/tag/v2.0.2) | Requires Java 8 or higher |
[3.0.0](https://github.com/seancfoley/IPAddress/releases/tag/v3.0.0) | Requires Java 8 or higher, features MAC address support, EUI-48 and EUI-64 MAC integration with IPv6, new address framework, new IP string formats parsed and produced, and other additions |
[4.3.3](https://github.com/seancfoley/IPAddress/releases/tag/v4.3.3) | Requires Java 8 or higher.  Features new prefix length handling.  IPv4-network/IPv6-subnet-router-anycast/zero-host addresses are interpreted as the prefix block subnet, while other prefixed addresses are individual addresses. There exists the option to preserve the version 3 behaviour.  Version 4.2.0 has additional methods for managing prefix blocks.  Version 4.3 features improved parsing performance and a change to increment(long) behaviour for subnets. |
**[Latest Version 5.3.4](https://github.com/seancfoley/IPAddress/releases/tag/v5.3.4)** | Requires Java 8 or higher.  Compatible with Android using Android API level 24 or higher.  The code is compiled with Java 8 but provides a Java 9 compiled module-info.class file for those using the Java Platform Module System (JPMS).  You may need (or wish) to [delete the module-info](https://github.com/seancfoley/IPAddress/issues/16#issuecomment-452425235), which can be done [with gradle](https://github.com/seancfoley/IPAddress/issues/16#issuecomment-452564690), when using Android, other Java 8 environments, or Java version 9 and up [environments](https://community.developer.atlassian.com/t/random-resourceconfig-instance-does-not-contain-any-root-resource-classes-exceptions-in-jira-7-and-some-early-jira-8-versions/33897) that do not [properly support modules](https://ecosystem.atlassian.net/browse/AMPS-1509). Since [Android Studio 3.3, deleting the module-info is no longer necessary](https://issuetracker.google.com/issues/77587908#comment16).  Version 5 features the addition of IPAddress sequential range classes IP\*AddressSeqRange, the reorganization of classes and interfaces in inet.ipaddr.format package to standard, large, and string subpackages, enhanced address block splitting and merging functionality, the improved parsing performance introduced with version 4.3.0, Java 8 stream and spliterator methods, additional parsing options, address tries, and associative address tries.  Other enhancements are listed on the releases page for [5.0.0](https://github.com/seancfoley/IPAddress/releases/tag/v5.0.0), [5.1.0](https://github.com/seancfoley/IPAddress/releases/tag/v5.1.0), [5.2.0](https://github.com/seancfoley/IPAddress/releases/tag/v5.2.0) and [5.3.0](https://github.com/seancfoley/IPAddress/releases/tag/v5.3.0)


## Getting Started

## Java

starting with address or subnet strings
```java
String ipv6Str = "::/64";
String ipv4Str = "1.2.255.4/255.255.0.0";
try {
	IPAddress ipv6Address = new IPAddressString(ipv6Str).toAddress();
	IPAddress ipv4Address = new IPAddressString(ipv4Str).toAddress();
        // use addresses
} catch (AddressStringException e) {
	String msg = e.getMessage();//detailed message indicating improper string format
	// handle improperly formatted address string
}
```
starting with host name strings
```java
String hostPortStr = "[a:b:c:d:e:f:a:b]:8080";
String hostServiceStr = "a.b.com:service";
String hostAddressStr = "1.2.3.4";
String dnsStr = "a.b.com";
try {
	HostName host = new HostName(hostPortStr);
	InetSocketAddress socketAddress = host.asInetSocketAddress();
	// use socket address
	        
	host = new HostName(hostServiceStr);
	socketAddress = host.asInetSocketAddress(
		service -> service.equals("service") ? 100 : null);
	// use socket address
	        
	host = new HostName(hostAddressStr);
	IPAddress address = host.asAddress(); // does not resolve
	// use address
	        
	host = new HostName(dnsStr);
	address = host.toAddress(); // resolves if necessary
	// use address
	        
} catch (HostNameException | UnknownHostException e) {
	String msg = e.getMessage();
	// handle improperly formatted host name or address string
}
```
## Kotlin

starting with address or subnet strings, using exceptions for invalid formats
```kotlin
val ipv6Str = "a:b:c:d::a:b/64"
try {
	val ipv6AddressStr = IPAddressString(ipv6Str)
	val ipv6Addr = ipv6AddressStr.toAddress()
	// use address
	println(ipv6Addr) // a:b:c:d::a:b/64
} catch(e: AddressStringException) {
	// handle improperly formatted address string
	println(e.message)
}
```
 starting with address or subnet strings, using nullable types and safe calls to handle invalid or unexpected formats
```kotlin
val ipv6v4Str = "a:b:c:d:e:f:1.2.3.4/112"
val ipv6v4AddressStr = IPAddressString(ipv6v4Str)
val ipAddr: IPAddress? = ipv6v4AddressStr.address
println(ipAddr) // a:b:c:d:e:f:102:304/112

val ipv4Addr = ipAddr?.toIPv6()?.embeddedIPv4Address
println(ipv4Addr) // 1.2.3.4/16
```
## Scala

starting with address strings, using exceptions for invalid formats
```scala
import scala.util.{Failure, Success, Try}

val addressStr = new IPAddressString("a:b:c:d::/64")
Try(addressStr.toAddress) match {
    case Success(userInfo) =>
        // use address
    case Failure(exception: AddressStringException) =>
        // handle improperly formatted address string
}
```
## Groovy

starting with address or subnet strings, using exceptions for invalid formats
```groovy
def addressStr = new IPAddressString('a:b:c:d:e:f:1.2.3.4')
try {
    def address = addressStr.toAddress()
    // use address
} catch (AddressStringException e) {
    // handle improperly formatted address string
}
```
starting with address or subnet strings, checking for null for invalid formats
```groovy
def subnetStr = new IPAddressString('108.30-31.*.*')
def subnet = subnetStr.getAddress()
if(subnet != null) {
    // use address
}
```
