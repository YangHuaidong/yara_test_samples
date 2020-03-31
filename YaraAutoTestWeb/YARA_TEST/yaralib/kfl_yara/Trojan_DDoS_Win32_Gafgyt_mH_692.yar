rule Trojan_DDoS_Win32_Gafgyt_mH_692
{
    meta:
	    judge = "black"
		threatname = "Trojan[DDoS]/Win32.Gafgyt.mH"
		threattype = "DDoS"
		family = "Gafgyt"
		hacker = "None"
		refer = "55c3f1c0f6a393bc236c1c935512f50e"
		author = "xc"
		comment = "None"
		date = "2017-09-01"
		description = "None"
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