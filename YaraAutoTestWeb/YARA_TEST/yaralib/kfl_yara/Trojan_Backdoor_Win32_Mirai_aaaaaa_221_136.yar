rule Trojan_Backdoor_Win32_Mirai_aaaaaa_221_136
{
    meta:
        judge = "black"
        threatname = "Trojan[Backdoor]/Win32.Mirai.aaaaaa"
        threattype = "backdoor"
        family = "Mirai"
        hacker = "None"
        author = "balala"
        refer = "1a4b710621ef2e69b1f7790ae9b7a288,917c92e8662faf96fffb8ffe7b7c80fb,975b458cb80395fa32c9dda759cb3f7b,3ed34de8609cd274e49bbd795f21acc4,b1a55ec420dd6d24ff9e762c7b753868,afd753a42036000ad476dcd81b56b754,fad20abf8aa4eda0802504d806280dd7,ab621059de2d1c92c3e7514e4b51751a,510b77a4b075f09202209f989582dbea,d1b1abfcc2d547e1ea1a4bb82294b9a3,4692337bf7584f6bda464b9a76d268c1,7cae5757f3ba9fef0a22ca0d56188439,1a7ba923c6aa39cc9cb289a17599fce0,f86db1905b3f4447eb5728859f9057b5,37c6d1d3054e554e13d40ea42458ebed,3e7430a09a44c0d1000f76c3adc6f4fa,98eb249e4ddc4897b8be6fe838051af7,1b57a7fad852b1d686c72e96f7837b44,ffb84b8561e49a8db60e0001f630831f,dfb4025352a80c2d81b84b37ef00bcd0,4457e89f4aec692d8507378694e0a3ba,48de562acb62b469480b8e29821f33b8,7a7eed9f2d1807f55a9308e21d81cccd,6817b29e9832d8fd85dcbe4af176efb6"
        comment = "None"
        date = "2018-07-17"
        description = "Operation Clandestine Wolf signature based on OSINT from 06.23.15"
    strings:
        $s0 = "flash.Media.Sound()"
        $s1 = "call Kernel32!VirtualAlloc(0x1f140000hash$=0x10000hash$=0x1000hash$=0x40)"
        $s2 = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
        $s3 = "NetStream"

    condition:
        all of them
}