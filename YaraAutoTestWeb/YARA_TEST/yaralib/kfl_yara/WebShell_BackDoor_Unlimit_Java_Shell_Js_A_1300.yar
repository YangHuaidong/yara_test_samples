rule WebShell_BackDoor_Unlimit_Java_Shell_Js_A_1300 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Java Shell.js.txt"
    family = "Java"
    hacker = "None"
    hash = "36403bc776eb12e8b7cc0eb47c8aac83"
    judge = "unknown"
    reference = "None"
    threatname = "WebShell[BackDoor]/Unlimit.Java.Shell.Js.A"
    threattype = "BackDoor"
  strings:
    $s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
    $s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
    $s4 = "public static int DEFAULT_SCROLLBACK = 100"
  condition:
    2 of them
}