## Python实现网络数据包的捕获
### 使用pypcap进行抓取数据包

``` python
import pcap
sniffer = pcap.pcap(name=None, promisc=True, immediate=True)
sniffer.setfilter('ip src host 221.192.237.140')
```
1.导入pypcap包
2.调用pcap.pcap()方法创建一个捕获器sniffer。参数列表如下：
```
- name         -- name of a network interface or dumpfile to open,or None to open the first available up interface
- snaplen      -- maximum number of bytes to capture for each packet
- promisc      -- boolean to specify promiscuous mode sniffing
- timeout_ms   -- requests for the next packet will return None if the timeout (in milliseconds) is reached and no packets were received (Default: no timeout)
- immediate    -- disable buffering, if possible
```

3.调用sniffer的setfilter()方法传入一个具有指定语法的字符串创建一个过滤器。字符串规定语法如下：

```
语法：	 |Protocol	|Direction  |Host(s)   |Value  |Logical Operations  |Other expression
例子：	 |tcp	 	|dst	 	|10.1.1.1  |80	   |and	 	            |tcp dst 10.2.2.2 3128

Protocol（协议）:
可能的值: ether, fddi, ip, arp, rarp, decnet, lat, sca, moprc, mopdl, tcp and udp.
如果没有特别指明是什么协议，则默认使用所有支持的协议。 

Direction（方向）:
可能的值: src, dst, src and dst, src or dst
如果没有特别指明来源或目的地，则默认使用 \"src or dst\" 作为关键字。
例如，\"host 10.2.2.2\"与\"src or dst host 10.2.2.2\"是一样的。 

Host(s):
可能的值： net, port, host, portrange.
如果没有指定此值，则默认使用\"host\"关键字。
例如，\"src 10.1.1.1\"与\"src host 10.1.1.1\"相同。 

Logical Operations（逻辑运算）:
可能的值：not, and, or.
否(\"not\")具有最高的优先级。或(\"or\")和与(\"and\")具有相同的优先级，运算时从左至右进行。
例如，
\"not tcp port 3128 and tcp port 23\"与\"(not tcp port 3128) and tcp port 23\"相同。
\"not tcp port 3128 and tcp port 23\"与\"not (tcp port 3128 and tcp port 23)\"不同。
 

例子：
tcp dst port 3128
显示目的TCP端口为3128的封包。

ip src host 10.1.1.1
显示来源IP地址为10.1.1.1的封包。

host 10.1.2.3
显示目的或来源IP地址为10.1.2.3的封包。

src portrange 2000-2500
显示来源为UDP或TCP，并且端口号在2000至2500范围内的封包。

not imcp
显示除了icmp以外的所有封包。（icmp通常被ping工具使用）

src host 10.7.2.12 and not dst net 10.200.0.0/16
显示来源IP地址为10.7.2.12，但目的地不是10.200.0.0/16的封包。

(src host 10.4.1.12 or src net 10.6.0.0/16) and tcp dst portrange 200-10000 and dst net 10.0.0.0/8
显示来源IP为10.4.1.12或者来源网络为10.6.0.0/16，目的地TCP端口号在200至10000之间，并且目的位于网络10.0.0.0/8内的所有封包。

 
注意事项：
当使用关键字作为值时，需使用反斜杠“\\”。
\"ether proto \\ip\" (与关键字\"ip\"相同).
这样写将会以IP协议作为目标。
\"ip proto \\icmp\" (与关键字\"icmp\"相同).
这样写将会以ping工具常用的icmp作为目标。 
可以在\"ip\"或\"ether\"后面使用\"multicast\"及\"broadcast\"关键字。
当您想排除广播请求时，\"no broadcast\"就会非常有用。
```

### 使用dpkt进行解包
在实现之前先导入包：
```python
import dpkt
from dpkt.compat import compat_ord
import datetime
import socket
```
-------
```python
"""
Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
"""
def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)
```
-------

```python
"""
Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
"""
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
```
-------

```python
"""
Print out information about each packet in a pcap
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
"""

def print_packets(pcap):
        # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

```

### 输出抓到的数据包

```python
print_packets(sniffer)
```
-------
```
/usr/local/bin/python3.6 /Users/zhongwentao/Documents/GitHub/Python-Program/抓包程序/main.py
Timestamp:  2019-05-15 03:06:32.018921
Ethernet Frame:  70:3d:15:06:42:01 98:01:a7:af:32:b1 2048
IP: 221.192.237.140 -> 10.91.91.210   (len=84 ttl=122 DF=0 MF=0 offset=0)

Timestamp:  2019-05-15 03:06:33.021467
Ethernet Frame:  70:3d:15:06:42:01 98:01:a7:af:32:b1 2048
IP: 221.192.237.140 -> 10.91.91.210   (len=84 ttl=122 DF=0 MF=0 offset=0)

Timestamp:  2019-05-15 03:06:34.027671
Ethernet Frame:  70:3d:15:06:42:01 98:01:a7:af:32:b1 2048
IP: 221.192.237.140 -> 10.91.91.210   (len=84 ttl=122 DF=0 MF=0 offset=0)

Timestamp:  2019-05-15 03:06:35.027662
Ethernet Frame:  70:3d:15:06:42:01 98:01:a7:af:32:b1 2048
IP: 221.192.237.140 -> 10.91.91.210   (len=84 ttl=122 DF=0 MF=0 offset=0)
```





