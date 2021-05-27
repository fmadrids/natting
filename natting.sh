#!/bin/bash

#TODO: status
#TODO: use ipsets instead of individual IPs
#TODO: use the cloud token to obtain our public IP, instead of depending on ident.me
#TODO: generate documentation

# Config server from which we download configuration
configserver="127.0.0.1"

###########################################

function error {
  case $1 in
    1)
      echo "Option not supported" | systemd-cat -t natting
      exit 1
      ;;
    2)
      echo "Public IP address seems to be incorrect" | systemd-cat -t natting
      exit 2
      ;;
    3)
      echo "Error retrieving our public IP address" | systemd-cat -t natting
      exit 3
      ;;
    4)
      echo "Error deleting IPtables rule: doesn't exist?" | systemd-cat -t natting
      exit 4
      ;;
    5)
      echo "IaaS credentials file not found" | systemd-cat -t natting
      exit 5
      ;;
    6)
      echo "Config file not found" | systemd-cat -t natting
      exit 6
      ;;
    7)
      echo "Error downloading config file" | systemd-cat -t natting
      exit 7
      ;;
    8)
      echo "Error when starting Strongswan" | systemd-cat -t natting
      exit 8
      ;;
    *)
      echo "Undefined error" | systemd-cat -t natting
      exit 10
      ;;
  esac
}

function usage {
  echo -e "Usage:"
  echo -e
  echo -e "Reload config and restart services:\tnatting reload"
  echo -e "Start connections (tunnel must be up):\tnatting startconns"
  echo -e "Stop connections:\t\t\tnatting stopconns"
  echo -e "Add a single C2S connection:\t\tnatting addc2sservice <offeredIP> <realIP>"
  echo -e "Delete a single C2S connection:\t\tnatting delc2sservice <offeredIP> <realIP>"
  echo -e "Add a single S2C connection:\t\tnatting adds2cservice <offeredIP> <realIP>"
  echo -e "Delete a single S2C connection:\t\tnatting dels2cservice <offeredIP> <realIP>"
  echo -e "Check status:\t\t\t\tnatting status"

  exit 0
}

function check_ip {
  ipcalc -4sc $1

  return $?
}

# Given a CIDR IP address, returns the network
function ip2net {
  local cidripaddress=${1}
  local bits=${cidripaddress##[1-9]*/}
  local ipaddress=${cidripaddress%%/*[1-9]}
  local network=""
  local blksz=""
  local last_octet=""
  local last_dec=""

  full_octets=$((bits/8))
  part_octet=$((bits%8))

  if [ $part_octet -eq 0 ]; then
    blksz=256
    last_octet=$full_octets
  else
    blksz=$((256/2**$part_octet))
    last_octet=$((full_octets+1))
  fi

  last_dec=$(echo $ipaddress | cut -d. -f$last_octet)

  for ((i=0 ; i<256 ; i+=$blksz)) ; do
    if [ $i -gt $(($last_dec-$blksz)) ]; then
      case $full_octets in
        4)
          network=$(echo ${ipaddress})
          ;;
        3)
          network=$(echo ${ipaddress} | cut -d. -f1-3).$i
          ;;
        2)
          network=$(echo ${ipaddress} | cut -d. -f1-2).$i.0
          ;;
        1)
          network=$(echo ${ipaddress} | cut -d. -f1).0.0.0
          ;;
        0)
          network=$i.0.0.0
          ;;
      esac
      [ -n  "$network" ] && break
    fi
  done

  echo ${network}
}

# Given a CIDR network, this function returns the first IP address
function firstipaddress {
  local cidrnetwork=${1}
  local network=""
  local ipaddress=""
  local lastoctet=""

  network=$(ip2net ${cidrnetwork})
  lastoctet=${network##[1-9]*\.}
  ipaddress=$(echo ${network} | cut -d. -f1-3).$((${lastoctet}+1))

  echo ${ipaddress}
}

# Given a CIDR network, this function returns the second IP address
function secondipaddress {
  local cidrnetwork=${1}
  local network=""
  local ipaddress=""
  local lastoctet=""

  network=$(ip2net ${cidrnetwork})
  lastoctet=${network##[1-9]*\.}
  ipaddress=$(echo ${network} | cut -d. -f1-3).$((${lastoctet}+2))

  echo ${ipaddress}
}

# This function downloads the config from the config server
function get_config {
  curl -s -o /etc/company/natting/config http://${configserver}/${1}
  [ $? = 0 ] || error 7

  curl -s -o /etc/strongswan/ipsec.conf http://${configserver}/${1}.ipsec
  [ $? = 0 ] || error 7
}

# This function reads the config from file instead of relying in default values
function read_config {
  [ -f /etc/company/natting/config ] || error 6
  . /etc/company/natting/config

  echo "Reading configuration" | systemd-cat -t natting
  # We read ipsec.conf
  mark=$(grep "mark =" /etc/strongswan/ipsec.conf | cut -d'=' -f 2 | tr -d " ")
  # Tunnel endpoints
  lclendpoint=$(grep "left =" /etc/strongswan/ipsec.conf | cut -d'=' -f 2 | tr -d " ")
  cltendpoint=$(grep "right =" /etc/strongswan/ipsec.conf | cut -d'=' -f 2 | tr -d " ")
  # The SaaS network offered to client (not the real one)
  virtualsaasnet=$(grep "leftsubnet =" /etc/strongswan/ipsec.conf | cut -d'=' -f 2 | tr -d " ")
  # The SaaS network (the real one)
  saasnet=$(ip route list | grep "dev eth0" | grep "scope link" | cut -d ' ' -f 1)
  # The client network
  rmtnet=$(grep "rightsubnet =" /etc/strongswan/ipsec.conf | cut -d'=' -f 2 | tr -d " ")
  # IP address used to nat traffic from client (the first one)
  virtualsaasnetnatip=$(firstipaddress ${virtualsaasnet})
  vethinip=$(firstipaddress ${natnet})
  vethoutip=$(secondipaddress ${natnet})

  [ -n "${virtualcltnet}" ] || virtualcltnet=${virtualsaasnet}
}

# This function gets an authorization token from Telefonica OpenCloud
function opencloud_get_token {
  local token=""
  local tempfile=""

  [ -f /etc/company/natting/iaas.secret ] || error 5
  . /etc/company/natting/iaas.secret

  tempfile=$(mktemp -p /dev/shm)

  # We prepare the API query
  cat <<JSON >${tempfile}
{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"${iamuser}","password":"${iampassword}","domain":{"name":"${iamdomain}"}}}},"scope":{"domain":{"name":"${iamdomain}"}}}}
JSON

  echo "Retrieving IaaS token" | systemd-cat -t natting
  token=$(curl -sSL -D - -H "Content-Type: application/json,charset=utf8" -X POST https://${iamendpoint}/v3/auth/tokens -d @${tempfile} -o /dev/null | grep X-Subject-Token | cut -d' ' -f 2)

  rm -f ${tempfile}

  echo $token
}

# This function obtains our public IP (currently from ident.me)
function opencloud_get_publicip {
  local ipaddress=""
  local token=${1}

  ipaddress=$(curl -s ident.me)
  [ $? = 0 ] || error 3

  check_ip ${ipaddress} || error 2

  echo ${ipaddress}
}

# Configure Strongswan
function config_strongswan {
  # We edit the secrets file
  echo "${lclendpoint} ${cltendpoint} : PSK \"${vpnpsk}\"" >> /etc/strongswan/ipsec.secrets
}

# Checks if strongswan is running
function check_strongswan {
  systemctl is-active --quiet strongswan || return 1

  return 0
}

function set_requisites {
  local token=""

  echo "Setting requisites" | systemd-cat -t natting

  # We get an IaaS token. Not implemented yet
#  token=$(opencloud_get_token)
  # We get our public IP
  publicip=$(opencloud_get_publicip ${token})
  echo "Detected IP: ${publicip}" | systemd-cat -t natting

  # We config ourselves
  echo "Retrieving configuration" | systemd-cat -t natting
  get_config ${publicip}
  read_config

  # We set the strongswan configuration
  echo "Configuring Strongswan" | systemd-cat -t natting
  config_strongswan

  # We create the namespace
  echo "Creating namespace ${natns}" | systemd-cat -t natting
  ip netns add ${natns}

  # We create the virtual interfaces
  echo "Creating interfaces"
  ip tunnel add ${basevti} mode vti local ${lclendpoint} remote ${cltendpoint} key ${mark}
  ip link add ${baseveth}IN type veth peer name ${baseveth}OUT

  # We set the interfaces in their namespaces
  ip link set ${baseveth}IN netns ${natns}

  # We create new IPtables chains
  echo "Configuring IPtables" | systemd-cat -t natting
  iptables -N ${s2cForwardChainname}
  iptables -I FORWARD 1 -j ${s2cForwardChainname}
  iptables -N ${c2sForwardChainname}
  iptables -I FORWARD 1 -j ${c2sForwardChainname}
  iptables -t nat -N ${s2cPreroutingChainname}
  iptables -t nat -I PREROUTING 1 -j ${s2cPreroutingChainname}
  iptables -t nat -N ${c2sPreroutingChainname}
  iptables -t nat -I PREROUTING 1 -j ${c2sPreroutingChainname}
  ip netns exec ${natns} iptables -N ${s2cForwardChainname}
  ip netns exec ${natns} iptables -A FORWARD -j ${s2cForwardChainname}
  ip netns exec ${natns} iptables -N ${c2sForwardChainname}
  ip netns exec ${natns} iptables -A FORWARD -j ${c2sForwardChainname}
  ip netns exec ${natns} iptables -t nat -N ${s2cPreroutingChainname}
  ip netns exec ${natns} iptables -t nat -I PREROUTING 1 -j ${s2cPreroutingChainname}
  ip netns exec ${natns} iptables -t nat -N ${c2sPreroutingChainname}
  ip netns exec ${natns} iptables -t nat -I PREROUTING 1 -j ${c2sPreroutingChainname}

  # We secure the namespace IPtables rules (the default ones should already be secure)
  ip netns exec ${natns} iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
  ip netns exec ${natns} iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
}

function post_start {
  echo "Retrieving configuration" | systemd-cat -t natting
  read_config

  # We check if strongswan is running
  check_strongswan || error 10

  # We assign the IP addresses to the virtual interfaces
  echo "Setting IP addresses to virtual interfaces" | systemd-cat -t natting
  ip netns exec ${natns} ip link set ${baseveth}IN up
  ip link set ${baseveth}OUT up
  ip netns exec ${natns} ip addr add ${vethinip}/30 dev ${baseveth}IN
  ip addr add ${vethoutip}/30 dev ${baseveth}OUT

  # We assign the IP addresses to the tunnel interface
  ip link set ${basevti} netns ${natns}
  ip netns exec ${natns} ip link set ${basevti} up

  echo "Adding C2S routes and rules" | systemd-cat -t natting
  # We add "client-to-saas" routes inside the namespace
  ip netns exec ${natns} ip route add ${virtualsaasnet} via ${vethoutip} dev ${baseveth}IN
  ip netns exec ${natns} ip route add ${rmtnet} dev ${basevti}

  # We masquerade "client-to-saas" traffic outgoing the namespace
  ip netns exec ${natns} iptables -t nat -A POSTROUTING -o ${baseveth}IN -s ${rmtnet} -d ${virtualsaasnet} -j MASQUERADE

  # We masquerade the "client-to-saas" traffic outgoing the physical interface
  iptables -t nat -C POSTROUTING -o eth0 -s ${vethinip} -d ${saasnet} -j MASQUERADE
  if [ $? -ne 0 ]; then
    iptables -t nat -A POSTROUTING -o eth0 -s ${vethinip} -d ${saasnet} -j MASQUERADE
  fi

  echo "Adding S2C routes and rules" | systemd-cat -t natting
  # We add "saas-to-client" routes
  ip route add ${virtualcltnet} via ${vethinip} dev ${baseveth}OUT

  # We masquerade the "saas-to-client" traffic going into the namespace
  iptables -t nat -C POSTROUTING -o ${baseveth}OUT -s ${saasnet} -d ${virtualcltnet} -j MASQUERADE
  if [ $? -ne 0 ]; then
    iptables -t nat -A POSTROUTING -o ${baseveth}OUT -s ${saasnet} -d ${virtualcltnet} -j MASQUERADE
  fi

  # We SNAT all the "saas-to-client" going to the client network to a single IP
  ip netns exec ${natns} iptables -t nat -A POSTROUTING -o ${basevti} -s ${vethoutip} -d ${rmtnet} -j SNAT --to-source ${virtualsaasnetnatip}
}

# "Client-to-SaaS" services
function add_saas_services {
  read_config

  echo "Adding SaaS service mappings" | systemd-cat -t natting
  for (( i=0; i<${#c2sOfferedIPs[@]}; i++ )); do
    add_saas_service_mapping ${c2sOfferedIPs[${i}]} ${c2sRealIPs[${i}]}
  done
}

function del_saas_services
{
  read_config

  echo "Deleting all SaaS service mappings" | systemd-cat -t natting
  iptables -F ${c2sForwardChainname}
  iptables -t nat -F ${c2sPreroutingChainname}
  ip netns exec ${natns} iptables -F ${c2sForwardChainname}
  ip netns exec ${natns} iptables -t nat -F ${c2sPreroutingChainname}
}

# "SaaS-to-Client" services
function add_clt_services {
  read_config

  echo "Adding client service mappings" | systemd-cat -t natting
  for (( i=0; i<${#s2cOfferedIPs[@]}; i++ )); do
    add_clt_service_mapping ${s2cOfferedIPs[${i}]} ${s2cRealIPs[${i}]}
  done
}

function del_clt_services
{
  read_config

  echo "Deleting all client service mappings" | systemd-cat -t natting
  iptables -F ${s2cForwardChainname}
  iptables -t nat -F ${s2cPreroutingChainname}
  ip netns exec ${natns} iptables -F ${s2cForwardChainname}
  ip netns exec ${natns} iptables -t nat -F ${s2cPreroutingChainname}
}

function add_saas_service_mapping {
  local offeredIP=${1}
  local realIP=${2}

  read_config

  echo "Configuring C2S service mapping: ${offeredIP} -> ${realIP}" | systemd-cat -t natting
  # We DNAT the "virtual" service IP address to the real IP address
  iptables -t nat -A ${s2cPreroutingChainname} -s ${vethinip} -d ${offeredIP} -j DNAT --to-destination ${realIP}

  # We allow traffic from client to the SaaS network...
  ip netns exec ${natns} iptables -I ${c2sForwardChainname} 1 -i ${basevti} -o ${baseveth}IN -s ${rmtnet} -d ${offeredIP} -j ACCEPT
  iptables -A ${c2sForwardChainname} -i ${baseveth}OUT -o eth0 -s ${vethinip} -d ${realIP} -j ACCEPT

  # ...and the return path
  iptables -A ${c2sForwardChainname} -i eth0 -o ${baseveth}OUT -s ${realIP} -d ${vethinip} -j ACCEPT
  ip netns exec ${natns} iptables -A ${c2sForwardChainname} -i ${baseveth}IN -o ${basevti} -s ${offeredIP} -d ${rmtnet} -j ACCEPT
}

function remove_saas_service_mapping {
  local offeredIP=${1}
  local realIP=${2}

  read_config

  echo "Deleting C2S service mapping: ${offeredIP} -> ${realIP}" | systemd-cat -t natting
  iptables -t nat -D ${s2cPreroutingChainname} -s ${vethinip} -d ${offeredIP} -j DNAT --to-destination ${realIP} || error 4
  ip netns exec ${natns} iptables -D ${c2sForwardChainname} -i ${basevti} -o ${baseveth}IN -s ${rmtnet} -d ${offeredIP} -j ACCEPT || error 4
  iptables -D ${c2sForwardChainname} -i ${baseveth}OUT -o eth0 -s ${vethinip} -d ${realIP} -j ACCEPT || error 4
  iptables -D ${c2sForwardChainname} -i eth0 -o ${baseveth}OUT -s ${realIP} -d ${vethinip} -j ACCEPT || error 4
  ip netns exec ${natns} iptables -D ${c2sForwardChainname} -i ${baseveth}IN -o ${basevti} -s ${offeredIP} -d ${rmtnet} -j ACCEPT || error 4
}

function add_clt_service_mapping {
  local offeredIP=${1}
  local realIP=${2}

  read_config

  echo "Configuring S2C service mapping: ${offeredIP} -> ${realIP}" | systemd-cat -t natting
  # We DNAT the "virtual" service IP address to the real IP address
  ip netns exec ${natns} iptables -t nat -A ${s2cPreroutingChainname} -s ${vethoutip} -d ${offeredIP} -j DNAT --to-destination ${realIP}

  # We allow traffic from SaaS to the client network
  iptables -A ${s2cForwardChainname} -i eth0 -o ${baseveth}OUT -s ${saasnet} -d ${offeredIP} -j ACCEPT
  ip netns exec ${natns} iptables -A ${s2cForwardChainname} -i ${baseveth}IN -o ${basevti} -s ${vethoutip} -d ${realIP} -j ACCEPT

  # ...and the return path
  ip netns exec ${natns} iptables -A ${s2cForwardChainname} -i ${basevti} -o ${baseveth}IN -s ${realIP} -d ${vethoutip} -j ACCEPT
  iptables -A ${s2cForwardChainname} -i ${baseveth}OUT -o eth0 -s ${offeredIP} -d ${saasnet} -j ACCEPT
}

function remove_clt_service_mapping {
  local offeredIP=${1}
  local realIP=${2}

  read_config

  echo "Deleting S2C service mapping: ${offeredIP} -> ${realIP}" | systemd-cat -t natting
  ip netns exec ${natns} iptables -t nat -D ${s2cPreroutingChainname} -s ${vethoutip} -d ${offeredIP} -j DNAT --to-destination ${realIP} || error 4
  iptables -D ${s2cForwardChainname} -i eth0 -o ${baseveth}OUT -s ${saasnet} -d ${offeredIP} -j ACCEPT || error 4
  ip netns exec ${natns} iptables -D ${s2cForwardChainname} -i ${baseveth}IN -o ${basevti} -s ${vethoutip} -d ${realIP} -j ACCEPT || error 4
  ip netns exec ${natns} iptables -D ${s2cForwardChainname} -i ${basevti} -o ${baseveth}IN -s ${realIP} -d ${vethoutip} -j ACCEPT || error 4
  iptables -D ${s2cForwardChainname} -i ${baseveth}OUT -o eth0 -s ${offeredIP} -d ${saasnet} -j ACCEPT || error 4
}

function reload {
  systemctl stop strongswan

  # We clean up configuration
  rm -f /etc/company/natting/config
  rm -f /etc/strongswan/ipsec.conf

  publicip=$(opencloud_get_publicip ${token})
  get_config ${publicip}
  read_config

  systemctl start companyconns
}

function stop {
  read_config

  # We stop prerequisite services
  systemctl stop companyconns.service
  check_strongswan && systemctl stop strongswan.service

  # We delete namespace and interfaces
  echo "Deleting namespace and VTI interface" | systemd-cat -t natting
  ip netns del ${natns}
  ip link set ${basevti} down
  ip link del ${basevti}

  # We clean up the iptables
  echo "Cleaning up IPtables" | systemd-cat -t natting
  iptables -D FORWARD -j ${s2cForwardChainname}
  iptables -D FORWARD -j ${c2sForwardChainname}
  iptables -X ${s2cForwardChainname}
  iptables -X ${c2sForwardChainname}
  iptables -t nat -D PREROUTING -j ${s2cPreroutingChainname}
  iptables -t nat -D PREROUTING -j ${c2sPreroutingChainname}
  iptables -t nat -X ${s2cPreroutingChainname}
  iptables -t nat -X ${c2sPreroutingChainname}
  iptables -t nat -D POSTROUTING -o eth0 -s ${vethinip} -d ${saasnet} -j MASQUERADE
  iptables -t nat -D POSTROUTING -o ${baseveth}OUT -s ${saasnet} -d ${virtualcltnet} -j MASQUERADE

  # We delete config files
  echo "Deleting config files" | systemd-cat -t natting
  rm -f /etc/company/natting/config
  rm -f /etc/strongswan/ipsec.conf
  rm -f /etc/strongswan/ipsec.secrets
}

case $1 in
  prestart)
    set_requisites
    ;;
  poststart)
    post_start
    add_saas_services
    add_clt_services
    ;;
  stop)
    stop
    ;;
  startconns)
    add_saas_services
    add_clt_services
    ;;
  stopconns)
    del_saas_services
    del_clt_services
    ;;
  reload)
    reload
    ;;
  addc2sservice)
    shift
    add_saas_service_mapping ${1} ${2}
    ;;
  delc2sservice)
    shift
    remove_saas_service_mapping ${1} ${2}
    ;;
  adds2cservice)
    shift
    add_clt_service_mapping ${1} ${2}
    ;;
  dels2cservice)
    shift
    remove_clt_service_mapping ${1} ${2}
    ;;
  status)
    #TODO: should check if the VPN is up and the natting is working
    ;;
  *)
    usage
    ;;
esac

exit 0
