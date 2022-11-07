# DNS-Lookup-Service
![image](https://user-images.githubusercontent.com/62523802/197371608-2e19f86d-5f68-4c74-9571-ca9bd86a1fe5.png)<br>
## Diff betwenn Socket and DatagramSocket
Socket require the connection. But DatagramSocket use Connectionless Socket. It does not hold connection between client and server. Server will not wait message from client but can receive message from mutiple clients.
## Walk through the tree
<img width="1148" alt="image" src="https://user-images.githubusercontent.com/62523802/200231449-7272d99d-877e-4bbd-84b8-51ec1e84a9b2.png"> <br>
* If the current name server does not know the answer, then...  <br>
  * The authority section tells you the authoritative name servers that might know the answer.  <br>
  * The additional section might tell you the IPv4/IPv6 address of the authoritative name servers.  <br>
