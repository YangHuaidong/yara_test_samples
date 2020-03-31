rule Trojan_DDoS_Linux_DnsAmp_F_747
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.DnsAmp.F"
		threattype = "DDoS"
		family = "DnsAmp"
		hacker = "None"
		refer = "0cad84c0d9e0ff68c34fbaa8ca573d3b"
		author = "LiuGuangZhu"
		comment = "None"
		date = "2017-08-21"
		description = "None"
	strings:
		$s0 = "ls -l %s"
		$s1 = "who|awk '{print $1}'"
		$s2 = "cat /proc/cpuinfo|grep 'cpu MHz'|sed -e 's/.*:[^0-9]//'"
		$s3 = "server=`ps -ef | grep $1 | grep -v grep | grep -v pro.sh`"
		$s4 = "chmod 777 pro.sh"
		$s5 = "./pro.sh %s &"
		$s6 = "chmod 777 /tmp/pro.sh"
		$s7 = "/tmp/pro.sh %s %s&"
	condition:
		//all of them
		$s0 and $s1 and $s2 and $s3 and (($s4 and $s5) or ($s6 and $s7))
}