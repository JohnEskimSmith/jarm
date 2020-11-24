# JARM  
  
Please read the initial [JARM blog post](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a) for more information.
  
JARM is an active Transport Layer Security (TLS) server fingerprinting tool.  
  
JARM fingerprints can be used to:
- Quickly verify that all servers in a group have the same TLS configuration.
- Group disparate servers on the internet by configuration, identifying that a server may belong to Google vs. Salesforce vs. Apple, for example.
- Identify default applications or infrastructure.
- Identify malware command and control infrastructure and other malicious servers on the Internet.
  
JARM support is being added to:  
[SecurityTrails](https://securitytrails.com/)  
[Shodan](http://shodan.io/)  
[BinaryEdge](https://www.binaryedge.io/)  
  
### Run JARM
`python3 jarm.py [-h] [-i INPUT] [-p PORT] [-v] [-V] [-o OUTPUT] [domain/IP]`  
Example:  
`% python3 jarm.py www.salesforce.com`  
`Domain: www.salesforce.com`  
`Resolved IP: 23.50.225.123`  
`JARM: 2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5`  
  
### Batch run JARM on a large list at speed
`./jarm.sh <list> <output_file>`  
Example:  
`% ./jarm.sh alexa500.txt jarm_alexa_500.csv`  
  
### Example Output  
| Domain | JARM |
| --- | --- |
| salesforce.com | `2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5` |
| force.com | `2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5` |
| google.com | `27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d` |
| youtube.com | `27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d` |
| gmail.com | `27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d` |
| facebook.com | `27d27d27d29d27d1dc41d43d00041d741011a7be03d7498e0df05581db08a9` |
| instagram.com | `27d27d27d29d27d1dc41d43d00041d741011a7be03d7498e0df05581db08a9` |
| oculus.com | `29d29d20d29d29d21c41d43d00041d741011a7be03d7498e0df05581db08a9` |  

### Run JARM asyncio version
`python3 jarm_async.py [-h] [--stdin] [-t str [str ...]] [-f str] [-o str] [--json] [--csv] [-s int] [--queue-sleep int] [-tconnect int] [-tread int] [-tresolver int] [-p int] [--filter-jarm str]
                     [--filter-cipher-tls str] [--show-only-success] [--show-statistics]`
                     
Targets: ipv4, ipv4:port, fqdn like youtube.com, facebook.com, google.com:443, network CIDR notation 
like 173.194.221.0/24 or with port 173.194.221.0/24:443

#####You can set source targets in 3 ways:

A. Argument --stdin. Read targets from /dev/stdin

```
cat alexa500.txt | python3 jarm_async.py --stdin
```

```
zmap 173.194.0.0/16 -B 10M -q -v 1 -p 443 -P1 | python3 jarm_async.py --stdin
```

B. Argument -t(--targets). Read targets from arguments

```
python3 jarm_async.py -t google.com youtube.com 173.194.221.0/24:443 --show-only-success --show-statistics
```

```json
{"duration":7.12016,"valid targets":258,"success":92,"fails":166}
```
###### results (some of the successfuls), output format json (default):

```json
{"ip":"173.194.73.93",
   "port":443,
   "hostname":"youtube.com",
   "data":{
      "jarm":{
         "ipaddress":{
            "jarm":"29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba",
            "cipher_tls":"29d3fd00029d29d21c42d43d00041d",
            "sha256_of_tls_ext":"f48f145f65c66577d0b01ecea881c1ba",
            "len":62
         },
         "hostname":{
            "jarm":"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
            "cipher_tls":"27d40d40d29d40d1dc42d43d00041d",
            "sha256_of_tls_ext":"4689ee210389f4f6b4b5b1b93f92252d",
            "len":62
         },
         "status":"success"
      }
   }
}
```
```json
{
   "ip":"173.194.221.180",
   "port":443,
   "data":{
      "jarm":{
         "ipaddress":{
            "jarm":"29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba",
            "cipher_tls":"29d3fd00029d29d21c42d43d00041d",
            "sha256_of_tls_ext":"f48f145f65c66577d0b01ecea881c1ba",
            "len":62
         },
         "status":"success"
      }
   }
}
```
C. Argument -f(--input-file). Read targets from file
 ```
python3 jarm_async.py -f alexa500.txt --csv
```
###### results (some of the successfuls), output format csv:
```
216.105.38.13,sourceforge.net,443,ipaddress,28d28d28d00028d00028d28d28d28d13c6918ce7b872cc0f0b93a8b36eb5f0,28d28d28d00028d00028d28d28d28d,13c6918ce7b872cc0f0b93a8b36eb5f0,62
216.105.38.13,sourceforge.net,443,hostname,28d28d28d00028d00028d28d28d28d9264f676a44e3d351f05cdbb4541c85e,28d28d28d00028d00028d28d28d28d,9264f676a44e3d351f05cdbb4541c85e,62
```
```json
{
   "duration":36.053758,
   "valid targets":500,
   "success":449,
   "fails":51
}
```
 
#####Results saves to stdout or to file -o (--output-file), statistics always output to stdout.

Output format for records of 2 types: json(default) or csv. JSON format very useful for sending(saving) records to MongoDB, 
Elasticsearch and other. CSV - is a simple format for saving to files.

Format JSON, examples:
```json
{
   "ip":"173.194.221.91",
   "port":443,
   "hostname":"youtube.com",
   "data":{
      "jarm":{
         "ipaddress":{
            "jarm":"29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba",
            "cipher_tls":"29d3fd00029d29d21c42d43d00041d",
            "sha256_of_tls_ext":"f48f145f65c66577d0b01ecea881c1ba",
            "len":62
         },
         "hostname":{
            "jarm":"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
            "cipher_tls":"27d40d40d29d40d1dc42d43d00041d",
            "sha256_of_tls_ext":"4689ee210389f4f6b4b5b1b93f92252d",
            "len":62
         },
         "status":"success"
      }
   }
}
```
Keys 'ipaddress' and 'hostname' in nest field 'data' means that: packets were sent containing both hostname(youtube.com) 
and ipaddress(resolved youtube.com). And calculate JARM for 2 types of packets.
```json
{
   "ip":"82.192.95.175",
   "port":443,
   "hostname":"habr.ru",
   "data":{
      "jarm":{
         "any":{
            "jarm":"15d2ad16d29d29d00015d2ad15d29de87e6567d901388794cb6a875a1928aa",
            "cipher_tls":"15d2ad16d29d29d00015d2ad15d29d",
            "sha256_of_tls_ext":"e87e6567d901388794cb6a875a1928aa",
            "len":62
         },
         "status":"success"
      }
   }
}
```
Key 'any' in nest field 'data' means that: packets were sent containing both hostname(habr.ru) 
and ipaddress(resolved habr.ru). JARM is calculated  for 2 types of packets, and JARM with ipaddress == JARM with hostname.

Format CSV(--csv), examples:

```
173.194.73.101,google.com,443,ipaddress,29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba,29d3fd00029d29d21c42d43d00041d,f48f145f65c66577d0b01ecea881c1ba,62
173.194.73.101,google.com,443,hostname,27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d,27d40d40d29d40d1dc42d43d00041d,4689ee210389f4f6b4b5b1b93f92252d,62
173.194.221.190,youtube.com,443,ipaddress,29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba,29d3fd00029d29d21c42d43d00041d,f48f145f65c66577d0b01ecea881c1ba,62
173.194.221.190,youtube.com,443,hostname,27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d,27d40d40d29d40d1dc42d43d00041d,4689ee210389f4f6b4b5b1b93f92252d,62
```
Fields order:

###### ip,hostname,port,type_record,jarm,cipher_tls,sha256_of_tls_ext,len_jarm

where: type_record in ['any', 'hostname', 'ipaddress'], cipher_tls = jarm[:30], sha256_of_tls_ext = jarm[30:]

##### Error results
```json
{
   "port":443,
   "data":{
      "jarm":{
         "status":"unknown-error",
         "error":"hostname not resolves to IPv4"
      }
   },
   "hostname":"some-unusual-domain.xyz"
}
```

##### Filter results
Arguments: 

`--show-only-success`

Show(save) records only with field 'status' == 'success'

`--filter-jarm=29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba`

Show(save) records only with values of fields 'data.any.jarm' or 'data.hostname.jarm' or 'data.ipaddress.jarm' == value

`--filter-cipher-tls=29d3fd00029d29d21c42d43d00041d`

Like --filter-jarm, but about 'data.[any, hostname, ipaddress].cipher_tls' == value

Note to the arugment: -p(--port). Port in target record, takes priority over option.

_To improve the quality and quantity of responses(result records), it may be necessary to select different time delays(timeouts)._

### How JARM Works
  
Before learning how JARM works, it’s important to understand how TLS works. TLS and its predecessor, SSL, are used to encrypt communication for both common applications like Internet browsers, to keep your data secure, and malware, so it can hide in the noise. To initiate a TLS session, a client will send a TLS Client Hello message following the TCP 3-way handshake. This packet and the way in which it is generated is dependent on packages and methods used when building the client application. The server, if accepting TLS connections, will respond with a TLS Server Hello packet.  
  
TLS servers formulate their Server Hello packet based on the details received in the TLS Client Hello packet. The manner in which the Server Hello is formulated for any given Client Hello can vary based on how the application or server was built, including:  
- Operating system
- Operating system version
- Libraries used
- Versions of those libraries used
- The order in which the libraries were called
- Custom configuration
  
All of these factors lead to each TLS Server responding in a unique way. The combinations of factors make it unlikely that servers deployed by different organizations will have the same response.  
  
JARM works by actively sending 10 TLS Client Hello packets to a target TLS server and capturing specific attributes of the TLS Server Hello responses. The aggregated TLS server responses are then hashed in a specific way to produce the JARM fingerprint.  
  
This is not the first time we’ve worked with TLS fingerprinting. In 2017 we developed [JA3/S](https://github.com/salesforce/ja3), a passive TLS client/server fingerprinting method now found on most network security tools. But where JA3/S is passive, fingerprinting clients and servers by listening to network traffic, JARM is an active server fingerprinting scanner. You can find out more about TLS negotiation and JA3/S passive fingerprinting [here](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967).  
  
The 10 TLS Client Hello packets in JARM have been specially crafted to pull out unique responses in TLS servers. JARM sends different TLS versions, ciphers, and extensions in varying orders to gather unique responses. Does the server support TLS 1.3? Will it negotiate TLS 1.3 with 1.2 ciphers? If we order ciphers from weakest to strongest, which cipher will it pick? These are the types of unusual questions JARM is essentially asking the server to draw out the most unique responses. The 10 responses are then hashed to produce the JARM fingerprint.  
  
The JARM fingerprint hash is a hybrid fuzzy hash, it uses the combination of a reversible and non-reversible hash algorithm to produce a 62 character fingerprint. The first 30 characters are made up of the cipher and TLS version chosen by the server for each of the 10 client hello's sent. A "000" denotes that the server refused to negotiate with that client hello. The remaining 32 characters are a truncated SHA256 hash of the cumulative extensions sent by the server, ignoring x509 certificate data. When comparing JARM fingerprints, if the first 30 characters are the same but the last 32 are different, this would mean that the servers have very similar configurations, accepting the same versions and ciphers, though not exactly the same given the extensions are different.  
  
After receiving each TLS server hello message, JARM closes the connection gracefully with a FIN as to not leave the sockets open.   
  
It is important to note that JARM is a high-performance fingerprint function and should not be considered, or confused with, a secure crypto function. We designed the JARM fingerprint to be human consumable as much as machine consumable. This means it is small enough to eyeball, share, and tweet with enough room for contextual details.  
  
### How JARM Can Be Used to Identify Malicious Servers
  
Malware command and control (C2) and malicious servers are configured by their creators like any other server and then deployed across their fleet. These therefore tend to produce unique JARM fingerprints. Below are examples of common malware and offensive tools and the JARM overlap with the Alexa Top 1M websites (as of Oct. 2020):  
  
| Malicious Server C2 | JARM Fingerprint | Overlap with Alexa Top 1M |
| --- | --- | --- |
| Trickbot | `22b22b09b22b22b22b22b22b22b22b352842cd5d6b0278445702035e06875c` | 0 |
| AsyncRAT | `1dd40d40d00040d1dc1dd40d1dd40d3df2d6a0c2caaa0dc59908f0d3602943` | 0 |
| Metasploit | `07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d` | 0 |
| Cobalt Strike | `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1` | 0 |
| Merlin C2 | `29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38` | 303 |
  
With little to no overlap of the Alexa Top 1M Websites, it should be unlikely for a host within an organization to connect to a server with these JARM fingerprints.  
  
  
### JARM Team  
[John Althouse](https://www.linkedin.com/in/johnalthouse/) - Original idea, concept and project lead  
[Andrew Smart](https://www.linkedin.com/in/andrew-smart-a3b15a2/) - Concept and testing  
[RJ Nunnally](https://www.linkedin.com/in/rjnunnally/) - Programing and testing  
[Mike Brady](https://www.linkedin.com/in/mike-brady-b5293b21/) - Programing and testing  
  
Rewritten in Python for operational use by [Caleb Yu](https://www.linkedin.com/in/caleb-yu/)

Rewritten in Async Python for operational use by: [Anton Zemlyanushkin](https://www.linkedin.com/in/azemlyanushkin/), 
[Andrey Skhomenko](https://www.linkedin.com/in/andrey-skhomenko-23a57a198/)
