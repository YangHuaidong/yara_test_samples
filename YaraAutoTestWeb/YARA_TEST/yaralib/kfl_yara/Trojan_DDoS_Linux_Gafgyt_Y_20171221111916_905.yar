rule Trojan_DDoS_Linux_Gafgyt_Y_20171221111916_905 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Y"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "2A10D32B6E0AC91AFF4BFBBA13F3E059,3EAA66BF0CD1A9910D653486DD2D6AAD,5C1BC722BBCC5E2342EE9185D46B0A8A,06F74F649D567396F104C3D003F8EA16,0CC825BAA0D89CE5A12DB8D39256EF8A"
		description = "None"
		comment = "None"
		author = "LiuGuangzhu"
		date = "2017-09-07"
	strings:
		$s0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /"
		$s1 = "cd /tmp || cd /var/system || cd /mnt || cd /lib"
		$s2 = "cd /tmp || cd /var/run || cd /dev/shm || cd /mnt || cd /var"
		$s3 = "assword"
		$s4 = "My Public IP: %s"
		$s5 = "CNC <target> <port> <time>"
		$s6 = "STD <target> <port> <time>"
		$s7 = "REPORT %s:%s:%s"
		$s8 = "My IP: %s"
		$s9 = "Version: %d.%d"
		$s10 = "BUILD %s"
		$s11 = "SCANNER"
		$s12 = "LOGIN FOUND - %s:%s:%s"

	condition:
		5 of them
}
