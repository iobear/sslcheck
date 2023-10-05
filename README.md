<h1>sslcheck</h1>
<hr>

Sslcheck allows you to check ssl keys with or without DNS resolution. The company I work for requires that all servers
have different ssl keys.  So if you've got two, four or more servers that sit behind a load balancer, it makes it hard
to inspect the keys on each server individually as the load balancer is where the DNS name for that SSL key resides.

Sslcheck takes two parameters -ip <ip address> -port <port> -domain <dns name>.  The -ip is optional, and if it's passed sslcheck will not
perform any dns lookups, while the -domain is manditory. The -port is for servers that might be running on a port other than 443.

Sslcheck is written in Go and should compile without the need of additional packages.
<h1>Example:</h1>
<h2>IPv4</h2>
<pre>
  ] $ ./sslcheck -domain www.google.com
  Client connected to: 74.125.137.99:443
  Cert Checks OK
  Server key information:
    CN:	 www.google.com
	  OU:	 []
	  Org:	 [Google Inc]
	  City:	 [Mountain View]
	  State:	 [California]
	  Country: [US]
  SSL Certificate Valid:
	  From:	 2011-10-26 00:00:00 +0000 UTC
	  To:	 2013-09-30 23:59:59 +0000 UTC
  Valid Certificate DNS:
	  www.google.com
  Issued by:
	  Thawte SGC CA
	  []
	  [Thawte Consulting (Pty) Ltd.]</pre>Client connected to: [2607:f8b0:4002:801::1001]:443
</pre>
<h2>IPv6<h2>
<pre>
  ] $ ./sslcheck -domain www.google.com
Client connected to: [2607:f8b0:4002:801::1001]:443
Cert Checks OK
Server key information:
	CN:	 *.google.com
	OU:	 
	Org:	 Google Inc
	City:	 Mountain View
	State:	 California
	Country: US
SSL Certificate Valid:
	From:	 2015-10-15 16:42:43 +0000 UTC
	To:	 2016-01-13 00:00:00 +0000 UTC
	OK: 	Cert Expires in 78 days
Valid Certificate DNS:
	*.google.com
	*.android.com
	...
	youtubeeducation.com
Issued by:
	Google Internet Authority G2
	Google Inc
<pre>
