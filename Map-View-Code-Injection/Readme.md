# Map-View Code Injection

This is the art of creating views on sections of memmory & mapping them to remote processes

## Basic concept

⇒&nbsp;&nbsp; This is a type of `Inter-Process Communication` (IPC) via mapping-view techniques  
⇒&nbsp;&nbsp; Mapping-view are accomplished by sharing memmory btw two processes   
⇒&nbsp;&nbsp; In our case the malware shares its memmory with the target process  
⇒&nbsp;&nbsp; Then the malware executes our shellcode in the shared memmory remotely via the target process  
⇒&nbsp;&nbsp; So it'll be as though the legit process was one to execute the shared memmory  

## Mechanism of Map-View Code injection 

First we create a new section on the Malware's process using the API function `NTCreateSection`

Then we create a local view still on the Malware's process leveraging the API `NTMapViewOfSection` which is used in accessing a section in memmory

Next we copy our shellcode to the created section using `local view` & leveraging `memcpy` function, this populates the new section with our shellcode

Then we create a remote view in the target process by the help of API `NTMapViewOfSection`

Finally we access the shellcode by using Win API `RtlCreateUserThread` In this step the malware trojan will actuall use the targets process remote view as a proxy to access the shellcode copied to the created section

<img src="https://imgur.com/jGMpcZ1.png" height="48%" width="48%" alt="Map-View Hijacking Steps"/>&nbsp;&nbsp;&nbsp;&nbsp;  <img src="https://imgur.com/O25z4NK.png" height="48%" width="48%" alt="Map-View Hijacking Steps"/>

<img src="https://imgur.com/Tt7dxdA.png" height="43%" width="33%" alt="Map-View Hijacking Steps"/> <img src="https://imgur.com/kD3vz6F.png" height="43%" width="33%" alt="Map-View Hijacking Steps"/> <img src="https://imgur.com/kVMMKM3.png" height="36%" width="33%" alt="Map-View Hijacking Steps"/>

## Advantages Of Map-View
• &nbsp;&nbsp;No need to use the following which are often flaged:                      
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;                           → VirtualAllocEX  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;                           → WriteProcessMemmory     
• &nbsp;&nbsp;This technique make it appear as though the legit process was one to execute the shared memmory                                          
• &nbsp;&nbsp;The target process acts as a proxy for our malware  
• &nbsp;&nbsp;Mapping-view technique is more stealthy since our malware runs the shellcode via a legitimate process   































