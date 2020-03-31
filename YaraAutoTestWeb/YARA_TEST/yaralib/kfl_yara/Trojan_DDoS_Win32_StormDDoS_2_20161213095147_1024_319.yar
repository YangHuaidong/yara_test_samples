rule Trojan_DDoS_Win32_StormDDoS_2_20161213095147_1024_319 
{
	meta:
		judge = "black"
		threatname = "Trojan[DDoS]/Win32.StormDDoS.2"
		threattype = "DDOS"
		family = "StormDDoS"
		hacker = "None"
		refer = "BF8666A54B1D92650190C1A7CDFC757B,870048278C0C7A4B77231DAECBF46A68,6afd74b9bfa5a903d327eae9e4db0bea,6bbc98f1bfa49364493ad63fcc1896ba,035c1ada4bace78dd104cb0e1d184043,ff4ecf9ea02b0d13782eec2dabb17d8c,035c1ada4bace78dd104cb0e1d184043,77cd6a9c98ef5655d0788e52e1788a85,0af30c29e4a41e2635d18a881de503db,1319b3ea3cd283a6d58eea3acbb7e422,140dcee611615f68267fa90c8c761e63,2649fd1f8f140ac0deb64eb9490ecc69,acc3dc8feb9d4b1d420c29de2805f788,0985f2f061956026e66aa45621bd8e1c,02dcd082f051000b7b45de5542b22845,7cfd6df17ef18a34c0cc88e6b7de7643,8b81cc2b9b1cb9adc9568a5dfd8a1484,045af2c1b048aeabac6b789df3227b21,e6343a904c2fcdda66735e0ce7d7b368,03b808604bf5d904f08ec62edb014ee0,42847dae1679a6ed193eca35a2ae7cf7,880a55548f63fb19c4a726c25b2c62d2,ccf2a36a5caaeb5ca4f2504073aa578a,872bd3b8374aaa7be9bef1ec6d010696,f429a831c4cb22ad920d9c492a09e2c8,c8ea3d25944f7d27f0a51254c16e881b,6AAAD0B43D548A6AA122424D38EA888C"
		description = "None"
		comment = "None"
		author = "sxy"
		date = "2016-09-01"
	strings:
		$s0 = "900pductName"
		$s1 = "8JZnY6M"
		$s2 = "LpkEditControl"
		$s3 = "\\DESCRIPTION_ys"

	condition:
		all of them
}
