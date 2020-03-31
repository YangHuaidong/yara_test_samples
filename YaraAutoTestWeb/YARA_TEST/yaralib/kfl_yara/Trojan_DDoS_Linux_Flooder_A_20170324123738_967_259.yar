rule Trojan_DDoS_Linux_Flooder_A_20170324123738_967_259 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Flooder.A"
		threattype = "DDOS"
		family = "Flooder"
		hacker = "None"
		refer = "3e3a507fd3d9bb031f947c37f57a2fdc,b1f95f2593d50838077deb41b69edae1,0bc7587f1ab99a1185ff7f5dffa01982,fd924453dc8c296c1c52bf30d6bafd9e,52d46d7dce3dd42dd3ccbbeb477cd4de"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2017-03-15"
	strings:
		$a0 = "starting DDoS... "
		$a1 = "Starting flood..."
		$b0 = "setup_ip_header"
		$b1 = "setup_udp_header"
		$b2 = "setup_tcp_header"
		$c0 = "Setting up Sockets..."
		$c1 = "Could not open raw socket"
		$c2 = "floodport"
		$c3 = "%s [ip] [port] [thread] [limiter] [time]"
		$c4 = "Usage: %s [HOST] [POWER (1)] [LIMITER (-1)] [TIME] "
		$c5 = "Usage: %s <target IP> <target port> <reflection file> <threads> <pps limiter, -1 for no limit> <time>"

	condition:
		(1 of ($a*) or 1 of ($b*) and 1 of ($c*))
}
