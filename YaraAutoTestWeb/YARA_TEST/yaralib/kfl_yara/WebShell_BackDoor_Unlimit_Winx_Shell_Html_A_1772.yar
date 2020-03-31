rule WebShell_BackDoor_Unlimit_Winx_Shell_Html_A_1772 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file WinX Shell.html.txt"
    family = "Winx"
    hacker = "None"
    hash = "17ab5086aef89d4951fe9b7c7a561dda"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Winx.Shell.Html.A"
    threattype = "BackDoor"
  strings:
    $s0 = "WinX Shell"
    $s1 = "Created by greenwood from n57"
    $s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"
  condition:
    2 of them
}