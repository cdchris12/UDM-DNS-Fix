# UDM-DNS-Fix

A simple script to provide basic DHCP hostname resolution in the latest UniFi Dream Machine Pro firmware. Borrows heavily from [github.com/wicol/unifi-dns](https://github.com/wicol/unifi-dns) for the core functionality to login to the Unifi UI and grab a list of these clients.

## How it works

This script communicates with the UniFi API to grab a list of all hosts which have an alias set for them. It then builds a custom `dns-alias.conf` file, copies it to the UDM Pro (not the UniFi controller; there's a difference), then restarts the `dnsmasq` service. This provides a crude, but effective method of managing hostname based address resolution until UniFi gets around to implementing a proper DNS solution on the UDM Pro. Recent UniFi sw updates have forced the use of FQDN, so setting a Domain Name for each Network is recommended -- otherwise, the script will default to using `.home.arpa`, per [IETF RFC8375](https://datatracker.ietf.org/doc/html/rfc8375).  Unqualified hostnames are inserted in the event that UniFi rolls back this requirement.

## How to Use This Script

### Install Requirements

This script is designed to be ran on a host within your network (not the UDM Pro). It is written in Python 3 and requires external dependencies, which can be installed by running `pip3 install -r requirements.txt`. I recommend setting this command up to run as a cron job to ensure newly created entreis are added to `dnsmasq` regularly.

### Command Line Arguments

- `-b`: This is the URL you use to log into your local UniFi UI
- `-p`: This is the password you use to log into your local UniFi UI
- `-u`: This is the username you use to log into your local UniFi UI
- `-N`: Use ~/.netrc entry for api host, username, and password (example `https://unifi.lan:443`)
- `-su`: This is the username you use to SSH into your UDM Pro directly
- `-sp`: This is the password you use to SSH into your UDM Pro directly
- `-sa`: This is the address you use to SSH into your UDM Pro directly
- `-S`: Use ~/.netrc entry for ssh host, username, and password (example `unifi`)
- `-f`: This is a flag which tells the script to only add entries which include a fixed IP address to the `/etc/hosts` file
- `-v`: This is a flag which enables verbose output from the script as it runs. Can be specified multiple times for additional levels of verbosity

### Example Commands

#### Bash Command

``` bash
./update-udmpro-dns.py -b https://192.168.1.1:443 -p <pass> -u <user> -su root -sp <ssh_password> -sa 192.168.1.1 -f -vvv
```

#### Using `~/.netrc` entries

``` bash
$ cat ~/.netrc
machine unifi login root account root password ROOTPASSWORD
machine https://unifi.lan:443 login USERNAME account USERNAME password USERPASSWORD

$ ./update-udmpro-dns.py -N https://unifi.lan:443 -S unifi --verbose
```

#### Bash Script

Customize line 10 of the `run.sh` file to suit your needs, then simply run:  

``` bash
./run.sh
```

More information can be found by running `./update-udmpro-dns.py -h`

## How to enable SSH on the UDM Pro (Not the UniFi Controller)

So you can probably figure out the base url stuff pretty easy, but figuring out how to enable SSH on the actual UDM Pro was a bit of a pain, since it's not directly in the UniFi UI I'm used to. To get there, do this:

- Open a browser and go to `https://<local-IP-of-UDMP>`
- Sign in with your Unifi credentials (same as you use for the hosted portal)
- Choose "Settings" at the bottom of the page, so you're taken to the UDMPro overview
- Select "Advanced" from the left menu pane
- Toggle "SSH" to be on
- Use "Change Password" to set the password you want
- SSH in to the UDMP's IP with the username "root" and the password you just set in order to verify everything is working.
