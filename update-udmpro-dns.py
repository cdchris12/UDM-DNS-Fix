#!/usr/bin/env python3
"""
Custom DNSMasq configuration for Unifi UDMPro to overcome shortcomings.
- Fetches configured and dynamic clients and gives them proper DNS names for their networks.
- Merges with custom local DNSMasq configuration file for CNAMEs and other options.

Example (using ~/.netrc file):
  $ ./get_unifi_reservations.py -N https://unifi.lan:443 -S unifi --verbose
"""

import os
import re
import sys
import netrc
import tempfile
import urllib3
from argparse import ArgumentParser

# External modules
import requests
import paramiko
from scp import SCPClient

# Disable Insecure Request Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_configured_clients(session: requests.Session, baseurl: str, site: str):
  """Get configured clients from UDMPro"""

  r = session.get(f'{baseurl}/proxy/network/api/s/{site}/list/user', verify=False)
  r.raise_for_status()
  return r.json()['data']
# End def

def get_active_clients(session: requests.Session, baseurl: str, site: str):
  """Get active clients from UDMPro"""

  r = session.get(f'{baseurl}/proxy/network/api/s/{site}/stat/sta', verify=False)
  r.raise_for_status()
  return r.json()['data']
# End def

def get_configured_networks(session: requests.Session, baseurl: str, site: str):
  """Get configured networks from UDMPro"""

  r = session.get(f'{baseurl}/proxy/network/api/s/{site}/rest/networkconf', verify=False)
  r.raise_for_status()
  return r.json()['data']
# End def

def build_fqdn(client: dict, networks: dict):
  """Return fully qualified domain name for client on network"""

  if client['network_id'] in networks:
    return f"{client['name']}.{networks[client['network_id']]}"
  # End if

  # default to .home.arpa, per IETF RFC8375
  return f"{client['name']}.home.arpa"
# End def

def get_clients(baseurl: str, username: str, password: str, site: str, fixed_only: bool, verbose: int):
  """Get clients and networks from UDMPro"""

  if verbose>2: print('Creating API session...')
  s = requests.Session()

  # Log in to controller
  if verbose>2: print('Logging into the controller...')
  r = s.post(f'{baseurl}/api/auth/login', json={'username': username, 'password': password}, verify=False)
  r.raise_for_status()
  if verbose>2: print('Login successful!')
  
  # Get networks...
  networks = {}
  for n in get_configured_networks(s, baseurl, site):
    if 'domain_name' in n:
      networks[n['_id']] = n['domain_name']
    # End if
  # End for

  # Add clients with alias and reserved IP
  clients = {}
  if verbose>2: print('Getting a list of clients and IPs...')
  for c in get_configured_clients(s, baseurl, site):
    if 'name' in c and 'fixed_ip' in c:
      c['name'] = c['name'].lower()
      fqdn = build_fqdn(c, networks)
      clients[c['mac']] = {'name': c['name'], 'fqdn': fqdn, 'ip': c['fixed_ip']}
    # End if
  # End for

  if not fixed_only:
    # Add active clients with alias
    # Active client IP overrides the reserved one (the actual IP is what matters most)
    for c in get_active_clients(s, baseurl, site):
      if 'name' in c and 'ip' in c:
        c['name'] = c['name'].lower()
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

def merge_dnsmasq_conf(hosts: list, custom_path:str, localpath: str, verbose: int):
  """Merge discovered clients with custom options file into temp file to upload"""

  with open(localpath, 'w') as outfile:
    # discovered clients
    for ip, name, fqdn in hosts:
      outfile.write(f'host-record={fqdn},{name},{ip}\n')
    # End for

    # local custom options
    if os.stat(custom_path).st_size > 0:
      if verbose>2: print('Adding custom options to the file...')
      with open(custom_path, 'r') as localfile:
        for line in localfile:
          outfile.write(line)
        # End for
      # End with
  # End with
# End def

def scp_dnsmasq(localpath: str, ssh_username: str, ssh_password: str, ssh_address: str, verbose: int):
  """Copy merged temp file to UDMPro and restart DNSMasq"""

  # Where the UDMPro is looking for DNSMasq files.
  filepath = '/run/dnsmasq.conf.d/dns-alias.conf'

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
  #ssh_client.exec_command("""kill `cat /run/dnsmasq.pid`""")
# End def


def main():
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

  parser.add_argument('-N', '--netrc', type=str, default=None, help='Use ~/.netrc entry for api host')
  parser.add_argument('-S', '--ssh', type=str, default=None, help='Use ~/.netrc entry for ssh host')
  args = parser.parse_args()

  if args.netrc:
    passes = netrc.netrc()
    if args.netrc not in passes.hosts:
      print(f'Unifi API host "{args.netrc}" not in netrc file!')
      exit(1)
    # End if

    (login, account, password) = passes.authenticators(args.netrc)
    args.baseurl = args.netrc
    args.username = login
    args.password = password
  # End if

  if args.ssh:
    if args.ssh not in passes.hosts:
      print(f'SSH host "{args.ssh}" not in netrc file!')
      exit(1)
    # End if

    passes = netrc.netrc()
    (login, _, password) = passes.authenticators(args.ssh)
    args.ssh_address = args.ssh
    args.ssh_username = login
    args.ssh_password = password
  # End if

  # Get list of hosts and IPs
  try:
    if args.verbose: print('Getting host information...')

    hosts = []
    for c in get_clients(args.baseurl, args.username, args.password, args.site, args.fixed_only, args.verbose):
      if args.verbose>2: print(f"Found host - IP: {c['ip']}\tName: {c['name']}\tFQDN:{c['fqdn']}")
      hosts.append((c['ip'], c['name'], c['fqdn']))
    # End for

  except requests.exceptions.ConnectionError:
    print(f'Could not connect to unifi controller at {args.baseurl}', file=sys.stderr)
    exit(1)
  # End try/except block

  if args.verbose:
    if hosts:
      print('Found the following hosts:')
      for host in hosts:
        domainname = host[2][len(host[1])+1:]
        print(f'\t{host[0]:15} {host[1]} ({domainname})')
      # End for
    else:
      print('No hosts found!')
    # End if/else block
  # End if

  # SCP list onto target UDM Pro
  (fp, tempfn) = tempfile.mkstemp()
  merge_dnsmasq_conf(hosts, 'dns-local.conf', tempfn, args.verbose)
  scp_dnsmasq(tempfn, args.ssh_username, args.ssh_password, args.ssh_address, args.verbose)

  # Clean up local file
  if args.verbose>2: print('Cleaning up local files...')
  os.remove(tempfn)
# End def

if __name__ == '__main__':
  main()
# End if