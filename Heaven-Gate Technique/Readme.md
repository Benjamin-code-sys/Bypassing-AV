# Heaven's Gate Cross-injetion

This is the art of injecting 64Bit Payloads into 64Bit Processes using 32Bit Processes 

## Types Of Cross-Injections

⇒ &nbsp;&nbsp;There are four types of cross-injections as listed below

<img src="https://imgur.com/MuA0Igr.png" height="70%" width="75%" alt="COM Hijacking Steps"/>

⇒ How 32Bit applications run on 64Bit systems  
&nbsp;&nbsp;&nbsp;&nbsp;      1- When a 32Bit process is launched   
&nbsp;&nbsp;&nbsp;&nbsp;      2- The 32Bit process will go through WoW64 emulator which is always running in the user space  
&nbsp;&nbsp;&nbsp;&nbsp;      3- The WoW64 emulator will then make syscalls to the 64Bit kernel  
&nbsp;&nbsp;&nbsp;&nbsp;      4- In addition the WoW64 emulator will also provide security hooks for AV engines to monitor the 32Bit processes  

⇒ However Note that there is a way to bypass WoW64. This is accomplished by using Heaven's Gate technique which leverages Stephen Fewer's EXECUTE_X64 & X64_FUNCTION algorithms found in Metasploit-Framework

## Advantages

Heaven's Gate technique bypasses the security measures of WoW64 emulator hence evading AVs & Security Hooks that depend on `WoW64`

## 32Bit to 64Bit Cross-Injection Mechanism

⇒&nbsp;&nbsp; Our initial 32Bit malware trojan running in 32Bit mode contains within it our 64Bit payload & two shellcodes  EXECUTE_X64 & X64_FUNCTION the execution flow is as follows:  

Our trojan will copy the payload over to the target process

Then our trojan will transition from 32Bit mode to 64Bit mode by executing the `EXECUTE_X64` shellcode, Once executed succefully the trojan which was initially running in 32Bit-mode @ the Start will shift it to 64Bit mode

Then now it executes the `X64_FUNCTION` which by the help of Win API `RtlCreateUserThread` will run the payload which has been copied over to the target process















