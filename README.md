# UDM-DNS-Fix

A simple script to provide basic DHCP hostname resolution in the latest UniFi Dream Machine Pro firmware. Borrows heavily from https://github.com/wicol/unifi-dns for the core functionality to login to the Unifi UI and grab a list of these clients.

## How it works

This script communicates with the UniFi API to grab a list of all hosts which have an alias set for them. It then grabs the current `/etc/hosts` file from the UDM Pro (not the UniFi controller; there's a difference), updates it as required, then reloads the dnsmasq service. This provides a crude, but effective method of managing hostname based address resolution until UniFi gets around to implementing a proper DNS solution on the UDM Pro.

## How to Use This Script

### Install Requirements
This script is based on Python 3 and requires external denepdencies, which can be installed by running `pip3 install -r requirements.txt`. 

### Example Command
```
./get_unifi_reservations.py -p <pass> -u <user> -su root -sp <ssh_password> -f
```

More information can be found by running `./get_unifi_reservations.py -h`