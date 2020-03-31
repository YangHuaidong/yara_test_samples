rule Worm_Backdoor_Win32_Stuxnet_a_1059
{
	meta:
		judge = "black"
		threatname = "Worm[Backdoor]/Win32.Stuxnet.a"
		threattype = "ICS,Backdoor"
		family = "Stuxnet"
		hacker = "None"
		refer = "016169ebebf1cec2aad6c7f0d0ee9026"
		author = "LiuGuangzhu"
		comment = "None"
		date = "2019-03-09"
		description = "None"
    strings:
         // 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
         // 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
         // 0x10001780 33 c9     xor     ecx, ecx
         // 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
         // 0x10001785 89 02     mov     dword ptr [edx], eax
         // 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
         $op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
         // 0x10002045 74 36     je      0x1000207d
         // 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
         // 0x1000204a 83 ff 00  cmp     edi, 0
         // 0x1000204d 74 2e     je      0x1000207d
         // 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
         // 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
         $op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
         // 0x100020cf 74 70     je      0x10002141
         // 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
         // 0x100020d8 75 1b     jne     0x100020f5
         // 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
         $op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }
    condition:
        all of them
}