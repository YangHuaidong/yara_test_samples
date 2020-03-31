rule WebShell_BackDoor_Unlimit_Hytop_Devpack_Fso_A_1287 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file fso.asp"
    family = "Hytop"
    hacker = "None"
    hash = "b37f3cde1a08890bd822a182c3a881f6"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Hytop.Devpack.Fso.A"
    threattype = "BackDoor"
  strings:
    $s0 = "<!-- PageFSO Below -->"
    $s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
  condition:
    all of them
}