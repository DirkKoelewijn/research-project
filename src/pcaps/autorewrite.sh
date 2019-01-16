#!/bin/bash
# Script to auto-rewrite DDOS-DB PCAP files to be send from
# this device to the other device in the network. Please make
# sure that only this and the receiving device are on the
# network interface.

# This script finds the IP and MAC addresses of sender (this 
# device) and receiver and changes the PCAP to be send to the
# other device on the network.


# Settings
interface=eno1		    # Name of the network interface for the two devices (find with 'ifconfig')
replace_ip=127.0.0.1	# The IP in the PCAP to replace with the destination IP
router_ip=192.168.1.1	# The IP of the router
output_prefix="rw_"	    # Prefix for rewritten file names


# Echo with sudo to force permissions
sudo echo "Rewriting '$1' to be send with $2 as TTL"


# Get own IP and MAC address
ip=$(ifconfig ${interface} | grep inet | grep -v inet6| awk '{print $2}')
mac=$(ifconfig ${interface} | grep ether | grep -v RX | awk '{print $2}')

echo "  from: $ip ($mac)"


# Find other IP and MAC address
other_ip="Could not be resolved"
other_mac="-"

while read line
do
	other_ip=$(echo ${line} | awk '{print $1}')
	if [[ "$other_ip" != "$router_ip" ]]
	then
		other_mac=$(echo ${line} | awk '{print $3}')
		break
	fi
done <<< $(arp -n | grep 192.168 | cat)

echo "  to:   $other_ip ($other_mac)"

# Construct new file name and rewrite command
new_f="$output_prefix$1"
cmd="tcprewrite -i $1 -o $new_f -N $replace_ip:$other_ip --enet-dmac=$other_mac --enet-smac=$mac --ttl=$2"

#Execute
$cmd


if [[ $? = 0 ]]
then
	echo "Output saved to '$new_f'"

	# Create run command
	cmd_run="sudo tcpreplay -t -i $interface $new_f"

	# Check if it should be ran
	if [[ "$3" = "-r" ]]
	then
		echo "Running $cmd_run"
		$cmd_run
	else
		echo "Run replay with"
		echo "    $cmd_run"
	fi
else
	echo "Failed: $cmd"
fi