rule Trojan_DDoS_Linux_Goram_A_766
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Linux.Goram.A"
		threattype = "DDoS"
		family = "Goram"
		hacker = "None"
		refer = "e4e60add58f6d1a8c98da58d4ca604df"
		author = "HuangYY"
		comment = "None"
		date = "2017-08-21"
		description = "None"
	strings:
		$s0 = "cpu R[%d] += R[%d] %x"
		$s1 = "load D[%d] = %x-%x"
		$s2 = "add D[%d] = D[%d]+D[%d] %x-%x"
		$s3 = "add F[%d] = F[%d]+F[%d] %x"
		$s4 = "cpy S[%d] = R[%d] %x"
		$s5 = "fix unsigned S[%d]=F[%d] %x"
		$s6 = "float D[%d]=S[%d] %x-%x"
		/*
		$s7 = "PassWord"
		$s8 = "/usr/local/go/src/pkg/"
		*/
	condition:
		all of them
}