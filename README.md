# UDM-DNS-Fix

A simple script to provide basic DHCP hostname resolution in the latest UniFi Dream Machine Pro firmware. Borrows heavily from https://github.com/wicol/unifi-dns for the core functionality to login to the Unifi UI and grab a list of these clients.

## How it works

This script communicates with the UniFi API to grab a list of all hosts which have an alias set for them. It then grabs the current `/etc/hosts` file from the UDM Pro (not the UniFi controller; there's a difference), updates it as required, then reloads the `dnsmasq` service. This provides a crude, but effective method of managing hostname based address resolution until UniFi gets around to implementing a proper DNS solution on the UDM Pro.

## How to Use This Script

### Install Requirements
This script is based on Python 3 and requires external dependencies, which can be installed by running `pip3 install -r requirements.txt`. 

### Command Line Arguments
- `-b`: This is the URL you use to log into your local UniFi UI
- `-p`: This is the password you use to log into your local UniFi UI
- `-u`: This is the username you use to log into your local UniFi UI
- `-su`: This is the username you use to SSH into your UDM Pro directly
- `-sp`: This is the password you use to SSH into your UDM Pro directly
- `-sa`: This is the address you use to SSH into your UDM Pro directly
- `-f`: This is a flag which tells the script to only add entries which include a fixed IP address to the `/etc/hosts` file

### Example Command
```
./get_unifi_reservations.py -b https://192.168.1.1:443 -p <pass> -u <user> -su root -sp <ssh_password> -sa 192.168.1.1 -f
```

More information can be found by running `./get_unifi_reservations.py -h`

## How to enable SSH on the UDM Pro (Not the UniFi Controller)
So you can probably figure out the base url stuff pretty easy, but figuring out how to enable SSH on the actual UDM Pro was a bit of a pain, since it's not directly in the UniFi UI I'm used to. To get there, do this:

- Open a browser and go to `https://<local-IP-of-UDMP>`
- Sign in with your Unifi credentials (same as you use for the hosted portal)
- Choose "Settings" at the bottom of the page, so you're taken to the UDMPro overview
- Select "Advanced" from the left menu pane
- Toggle "SSH" to be on
- Use "Change Password" to set the password you want
- SSH in to the UDMP's IP with the username "root" and the password you just set in order to verify everything is working.
