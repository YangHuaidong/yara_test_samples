rule Trojan_DownLoader_Win32_Script_PowerShell_20180108093237_961 
{
	meta:
		judge = "black"
		threatname = "Trojan[DownLoader]/Win32.Script.PowerShell"
		threattype = "Downloader"
		family = "Script"
		hacker = "None"
		refer = "9f6ada36cedb99e7fbed0448e8f2172f"
		description = "Developed to detect APT32 phishing lures usered to target customers in 2016 and 2017"
		comment = "None"
		author = "dengcong"
		date = "2017-12-28"
	strings:
		$s0 = "[Byte[]]$var_code = [System.Convert]::FromBase64String(\"/OgAAAAA6ydeiw6DxgSLBjHIg8YEVosuMc2JLjHpg8YEg+gEMe056HQC6" nocase wide ascii

	condition:
		all of them
}
