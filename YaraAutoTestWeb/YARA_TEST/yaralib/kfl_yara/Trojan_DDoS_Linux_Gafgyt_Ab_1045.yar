rule Trojan_DDoS_Linux_Gafgyt_Ab_1045
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Gafgyt.Ab"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "9e269741adcfe42e33c268984f6deabb"
		author = "lizhenling"
		comment = "None"
		date = "2019-02-20"
		description = "None"

	strings:		
		$s0 = "/etc/apt/apt.conf"
		$s1 = "Sending TCP Packets To: %s:%d for %d seconds"
		$s2 = "processCmd"
		$s3 = "recvLine"
		$s4 = "macAddress"
		$s5 = "/usr/sbin/telnetd"
		$s6 = "mainCommSock"
		$s7 = "commServer"
		$s8 = "/usr/bin/perl"
		
	condition:
		8 of them
}