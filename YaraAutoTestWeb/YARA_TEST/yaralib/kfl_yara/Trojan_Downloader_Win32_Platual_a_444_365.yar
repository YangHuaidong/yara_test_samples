rule Trojan_Downloader_Win32_Platual_a_444_365
{

meta: 
    judge = "black"
		threatname = "Trojan[Downloader]/Win32.Platual.a"
		threattype = "Downloader"
		family = "Platual"
		hacker = "None"
		comment = "None"
		date = "2016-04-12"
		author = "Microsoft-DC"
		description = "Installer component" 
		refer = "e0ac2ae221328313a7eee33e9be0924c"
		original_sample_sha1 = "e0ac2ae221328313a7eee33e9be0924c46e2beb9"
    unpacked_sample_sha1 = "ccaf36c2d02c3c5ca24eeeb7b1eae7742a23a86a"

strings:
    $class_name = "AVCObfuscation"
    $scrambled_dir = { A8 8B B8 E3 B1 D7 FE 85 51 32 3E C0 F1 B7 73 99 }

condition:
    $class_name and $scrambled_dir
}