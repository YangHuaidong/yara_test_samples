rule Trojan_DDoS_Win32_Gafgyt_mH_20170913122059_923 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.Gafgyt.mH"
		threattype = "DDOS"
		family = "Gafgyt"
		hacker = "None"
		refer = "55c3f1c0f6a393bc236c1c935512f50e"
		description = "None"
		comment = "None"
		author = "xc"
		date = "2017-09-01"
	strings:
		$s0 = "/dev/null"
		$s1 = "/etc/config/resolv.conf"
		$s2 = "hlLjztqZ"
		$s3 = "npxXoudifFeEgGaACScs"
		$s4 = "/usr/bin/python"
		$s5 = "/proc/net/route"
		$s6 = "mHoIJPqGRSTUVWXL"
		$s7 = "cd /tmp"
		$s8 = "chmod 777 python.py"
		$s9 = "chmod 777 gtop.sh"
		$s10 = "LDAP %s /home/ubuntu/.kek/NIGGERL.txt 10 %d"
		$s11 = "SSDP %s 80 /home/ubuntu/.kek/ssdp.txt 10 -1 %d"

	condition:
		8 of them
}
