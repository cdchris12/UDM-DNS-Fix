#!/usr/bin/env python3
# Builtin modules
import os
import re
import sys
from argparse import ArgumentParser

# External modules
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
# End def

def build_fqdn(client: dict, networks: dict):
  if client['network_id'] in networks:
    return f"{client['name']}.{networks[client['network_id']]}"
  # End if

  # default to .home.arpa, per IETF RFC8375
  return f"{client['name']}.home.arpa"

def get_clients(baseurl: str, username: str, password: str, site: str, fixed_only: bool, verbose: int):
  if verbose>2: print('Creating a session...')
  s = requests.Session()
  # Log in to controller
  if verbose>2: print('Logging into the controller...')
  r = s.post(f'{baseurl}/api/auth/login', json={'username': username, 'password': password}, verify=False)
  r.raise_for_status()
  if verbose>2: print('Login successful!')
  
  networks = {}
  for n in get_configured_networks(s, baseurl, site):
    if 'domain_name' in n:
      networks[n['_id']] = n['domain_name']
    # End if
  # End for

  clients = {}
  # Add clients with alias and reserved IP
  if verbose>2: print('Getting a list of clients and IPs...')
  for c in get_configured_clients(s, baseurl, site):
    if 'name' in c and 'fixed_ip' in c:
      fqdn = build_fqdn(c, networks)
      clients[c['mac']] = {'name': c['name'], 'fqdn': fqdn, 'ip': c['fixed_ip']}
    # End if
  # End for

  if not fixed_only:
    # Add active clients with alias
    # Active client IP overrides the reserved one (the actual IP is what matters most)
    for c in get_active_clients(s, baseurl, site):
      if 'name' in c and 'ip' in c:
        fqdn = build_fqdn(c, networks)
        clients[c['mac']] = {'name': c['name'], 'fqdn': fqdn, 'ip': c['ip']}
      # End if
    # End for
  # End if
  
  # Return a list of clients filtered on dns-friendly names and sorted by IP
  friendly_clients = [c for c in clients.values() if re.search('^[a-zA-Z0-9-]+$', c['name'])] 
  if verbose>2: print('Client list obtained successfully!')
  return sorted(friendly_clients, key=lambda i: i['name'])
# End def

def scp_dnsmasq(hosts: list, ssh_username: str, ssh_password: str, ssh_address: str, verbose: int):
  filepath = '/run/dnsmasq.conf.d/dns-alias.conf'
  localpath = 'dns-alias.conf'

  dns_alias_text = ""
  for ip, name, fqdn in hosts:
    dns_alias_text += f'host-record={fqdn},{name},{ip}\n'
  # End for

  with open(localpath, 'w') as outfile:
    outfile.write(dns_alias_text)
  # End with
  
  if verbose>2: print('Creating an SSH session...')
  ssh_client = paramiko.SSHClient()
  ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh_client.connect(hostname=ssh_address,username=ssh_username,password=ssh_password)
  if verbose>2: print('SSH Session created successfully!')

  # Push dns-alias.conf file
  if verbose>2: print('Pushing new dns-alias.conf file...')
  with SCPClient(ssh_client.get_transport()) as scp:
    scp.put(localpath, filepath)
  # End with

  # Restart dnsmasq on the UDM Pro
  if verbose>2: print('Restarting dnsmasq service...')
  ssh_client.exec_command("""killall dnsmasq""")

  if verbose>2: print('Cleaning up local files...')
  # Clean up local file
  os.remove(localpath)
# End def

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
  parser.add_argument('-f', '--fixed_only', action='store_true', help='Only add entries with a fixed DNS name configured.')
  parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. May be specified multiple times for increased verbosity.')
  args = parser.parse_args()

  # Get list of hosts and IPs
  try:
    if args.verbose: print('Getting host information...')
    hosts = []
    for c in get_clients(args.baseurl, args.username, args.password, args.site, args.fixed_only, args.verbose):
      hosts.append((c['ip'], c['name'], c['fqdn']))
    # End for
  except requests.exceptions.ConnectionError:
    print(f'Could not connect to unifi controller at {args.baseurl}', file=sys.stderr)
    exit(1)
  else:
    if args.verbose:
      if hosts:
        print('Found the following hosts:')
        for host in hosts:
          print('\n\t IP: %s\tName: %s' % (host[0], host[1]))
        # End for
      else:
        print('No hosts found!')
      # End else/if block
    # End if
  # End try/except/else block

  # SCP list onto target UDM Pro
  scp_dnsmasq(hosts, args.ssh_username, args.ssh_password, args.ssh_address, args.verbose)
# End def

if __name__ == '__main__':
  main()
# End if
