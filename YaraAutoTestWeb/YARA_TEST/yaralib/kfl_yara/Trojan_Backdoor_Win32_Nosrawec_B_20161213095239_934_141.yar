rule Trojan_Backdoor_Win32_Nosrawec_B_20161213095239_934_141 
{
	meta:
		judge = "black"
		threatname = "Trojan[Backdoor]/Win32.Nosrawec.B"
		threattype = "rat"
		family = "Nosrawec"
		hacker = "None"
		refer = "4189179b9abf69c04109111649ead9de"
		description = "Pandora"
		comment = "None"
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "2016-06-23"
	strings:
		$a = "Can't get the Windows version"
		$b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
		$c = "JPEG error #%d" wide
		$d = "Cannot assign a %s to a %s" wide
		$g = "%s, ProgID:"
		$h = "clave"
		$i = "Shell_TrayWnd"
		$j = "melt.bat"
		$k = "\\StubPath"
		$l = "\\logs.dat"
		$m = "1027|Operation has been canceled!"
		$n = "466|You need to plug-in! Double click to install... |"
		$0 = "33|[Keylogger Not Activated!]"

	condition:
		all of them
}
