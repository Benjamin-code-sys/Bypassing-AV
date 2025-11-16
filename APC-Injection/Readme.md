# Asynchronous Procedure Call

This is the art of injecting callback functions on remote processes

## Basic concepts

It is a kinda Call-Back function mechanism  
This is done by putting instructions in memmory queue of a running thread  
When the thread enters a certain state (`alertable`), it will notice the queue & execute the instructions in the queue  
The term Asynchronous means not executing immediatly but rather sometime in the future  

## Example of APC

In example if a process wants to read a file, it'll make a request to the OS   
But since opening a file can be slow the process won't just sit back and wait but rather it'll leave that task to the OS while it performs other tasks  
When the file is ready, the OS will inform the process which will then carry on with the instruction in the queue  

## Mechanism of APC injection 

The malware trojan will search for target process  

Then once it has found it it'll search for the thread inside the target process

Next our trojan containing the malcious code (Shellcode) will allocate memmory to the target process using `VirtualAllocEx` Win API

Then the trojan will write the shellcode to the newly allocated memmory using `WriteProcessMemmory` Win API

Next the trojan will add a job to the APC Queue. This is done by the help of API function `QueueUserAPC`

Then we wait for thread to enter alertable state which include either of the following:  
&nbsp;&nbsp;&nbsp;&nbsp;            → **SleepEx()**  
&nbsp;&nbsp;&nbsp;&nbsp;            → **SignalObjectAndWait**  
&nbsp;&nbsp;&nbsp;&nbsp;            → **MsgWaitForMultipleObjectsEx**  
&nbsp;&nbsp;&nbsp;&nbsp;            → **WaitForMultipleObjectsEx**   
&nbsp;&nbsp;&nbsp;&nbsp;            → **WaitForSingleObjectEx**  

When alertable state is entered it'll notice there is a shellcode in the queue and execute it 

<img src="https://imgur.com/M2VZzjK.png" height="48%" width="48%" alt="APC Injection Steps"/> &nbsp;&nbsp; <img src="https://imgur.com/dwkuG55.png" height="48%" width="48%" alt="APC Injection Steps"/>

<img src="https://imgur.com/3SFa2vo.png" height="48%" width="48%" alt="APC Injection Steps"/> &nbsp;&nbsp; <img src="https://imgur.com/pIfW30f.png" height="48%" width="48%" alt="APC Injection Steps"/>

## Advantages
• &nbsp;&nbsp;Delayed execution of shellcode throws off causation between Malware & Target  
• &nbsp;&nbsp;Alertable state is triggered not by malware but by Target Process, hence user won't suspect that the malware process is responsible  

## Disadvantages
• &nbsp;&nbsp;It needs to wait for thread to enter alertable state  
• &nbsp;&nbsp;Hence Slow & Uncertain  
• &nbsp;&nbsp;Uses VirtualAllocEx & WriteProcessMemmory which are heavily monitored by AV engines if not obfuscated  





























