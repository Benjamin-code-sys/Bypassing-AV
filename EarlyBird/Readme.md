<h1>Early-Bird APC Injection</h1>

⇒ The art of achieving camouflage by hijacking a legitimate process before it hits Entry point  
⇒ In simple terms our malware launches and hides behind a target process & takes its icon whence considered very stealthy    

<h2>Basic Concept</h2>

  ▪ Our malware creates a legitimate process in a suspended state  
  ▪ Then it injects our malicious shellcode to it   
  ▪ Next it inserts a job into the threads APC queue  
  ▪ Finally it resumes the thread  
  ▪ The shellcode executes before the process begins, hence avoiding detection by anti-malware hooks   

<h2>Mechanism of Early-Bird APC injection</h2>

1. Our malware trojan will create a process in a suspended state 
2. Next our trojan will allocate memmory to the target process using VirtualAllocEx Win API
3. Then the trojan will copy our shellcode to the newly allocated memmory using WriteProcessMemmory Win API
4. Next the trojan will add a job to the APC Queue by the help of API function QueueUserAPC
5. Then it'll resume the thread using the ResumeThread API function hence executing the shellcode in the APC queue

<img src="https://imgur.com/2H9JVHS.png" height="80%" width="80%" alt="Early-Bird APC injection steps"/>

<h2>Advantages</h2>

▪ Camouflages the execution of our malicious shellcode by hijacking a legitimate process before it hits Entry point  
▪ The remaining code of the actual legitimate targeted process is abandoned whilst the shellcode runs  
▪ Bypasses security product hooks  
▪ The shellcode executes before the process begins, hence avoiding detection by anti-malware hooks   
▪ Our malware runs with applications icon of the oiginal targeted process  
