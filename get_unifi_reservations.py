#!/usr/bin/env python3
import os
import re
import sys
from argparse import ArgumentParser
import io
import copy

import requests
import paramiko
from scp import SCPClient

# Disable Insecure Request Warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_configured_clients(session: requests.Session, baseurl: str, site: str):
  # Get configured clients
  r = session.get(f'{baseurl}/proxy/network/api/s/{site}/list/user', verify=False)
  r.raise_for_status()
  return r.json()['data']
# End def

def get_active_clients(session: requests.Session, baseurl: str, site: str):
  # Get active clients
  r = session.get(f'{baseurl}/proxy/network/api/s/{site}/stat/sta', verify=False)
  r.raise_for_status()
  return r.json()['data']
# End def

def get_configured_networks(session: requests.Session, baseurl: str, site: str):
  # Get configured networks
  r = session.get(f'{baseurl}/proxy/network/api/s/{site}/rest/networkconf', verify=False)
  r.raise_for_status()
  return r.json()['data']

def build_fqdn(client: dict, networks: dict):
  if client['network_id'] in networks:
    return f"{client['name']}.{networks[client['network_id']]}"

  # default to .home.arpa, per IETF RFC8375
  return f"{client['name']}.home.arpa"

def get_clients(baseurl: str, username: str, password: str, site: str, fixed_only: bool):  
  s = requests.Session()
  # Log in to controller
  r = s.post(f'{baseurl}/api/auth/login', json={'username': username, 'password': password}, verify=False)
  r.raise_for_status()

  networks = {}
  for n in get_configured_networks(s, baseurl, site):
    if 'domain_name' in n:
      networks[n['_id']] = n['domain_name']

  clients = {}
  # Add clients with alias and reserved IP
  for c in get_configured_clients(s, baseurl, site):
    if 'name' in c and 'fixed_ip' in c:
      fqdn = build_fqdn(c, networks)
      clients[c['mac']] = {'name': c['name'], 'fqdn': fqdn, 'ip': c['fixed_ip']}
  if fixed_only is False:
    # Add active clients with alias
    # Active client IP overrides the reserved one (the actual IP is what matters most)
    for c in get_active_clients(s, baseurl, site):
      if 'name' in c and 'ip' in c:
        fqdn = build_fqdn(c, networks)
        clients[c['mac']] = {'name': c['name'], 'fqdn': fqdn, 'ip': c['ip']}
  
  # Return a list of clients filtered on dns-friendly names and sorted by IP
  friendly_clients = [c for c in clients.values() if re.search('^[a-zA-Z0-9-]+$', c['name'])] 
  return sorted(friendly_clients, key=lambda i: i['name'])
# End def

def scp_dnsmasq(hosts, ssh_username, ssh_password, ssh_address):
  filepath = '/run/dnsmasq.conf.d/dns-alias.conf'
  localpath = 'dns-alias.conf'

  dns_alias_text = ""
  for ip, name, fqdn in hosts:
    dns_alias_text += f'host-record={fqdn},{name},{ip}\n'

  with open(localpath, 'w') as outfile:
    outfile.write(dns_alias_text)

  ssh_client = paramiko.SSHClient()
  ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh_client.connect(hostname=ssh_address,username=ssh_username,password=ssh_password)

  # Push dns-alias.conf file
  with SCPClient(ssh_client.get_transport()) as scp:
    scp.put(localpath, filepath)

  # Restart dnsmasq on the UDM Pro
  ssh_client.exec_command("""killall dnsmasq""")

  # Clean up local file
  os.remove(localpath)

def main():
  # Parse arguments
  parser = ArgumentParser()
  parser.add_argument('-b', '--baseurl', type=str, default="https://192.168.1.1:443", help='The site\'s base URL. Defaults to: "https://192.168.1.1:443"')
  parser.add_argument('-u', '--username', type=str, default="root", help='Your user\'s username. Defaults to: "root"')
  parser.add_argument('-p', '--password', type=str, default="ubnt", help='Your user\'s password. Defaults to: "ubnt"')
  parser.add_argument('-s', '--site', type=str, default="default", help='The name of your unifi site. Defaults to: "default"')
  parser.add_argument('-su', '--ssh_username', type=str, default="root", help='Your UDM\'s SSH username. Defaults to: "root"')
  parser.add_argument('-sp', '--ssh_password', type=str, default="ubnt", help='Your UDM\'s SSH password. Defaults to: "ubnt"')
  parser.add_argument('-sa', '--ssh_address', type=str, default="192.168.1.1", help='Your UDM\'s SSH address. Defaults to: "192.168.1.1"')
  parser.add_argument('-f', "--fixed_only", action='store_true', help='Only add entries with a fixed DNS name configured.')
  args = parser.parse_args()

  # Get list of hosts and IPs
  try:
    hosts = []
    for c in get_clients(args.baseurl, args.username, args.password, args.site, args.fixed_only):
      hosts.append((c['ip'], c['name'], c['fqdn']))
    # End for
  except requests.exceptions.ConnectionError:
    print(f'Could not connect to unifi controller at {args.baseurl}', file=sys.stderr)
    exit(1)
  # End try/except block

  # SCP list onto target UDM Pro
  scp_dnsmasq(hosts, args.ssh_username, args.ssh_password, args.ssh_address)
# End def

if __name__ == '__main__':
  main()
# End if
