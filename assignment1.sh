#!/bin/sh


#Flush iptables
$sudo iptables -F

#Delete all chains
$sudo iptables -X

#Display chain
$sudo iptables -L

#Set default policy to drop for all - whitelist
$sudo iptables -P INPUT DROP
$sudo iptables -P OUTPUT DROP
$sudo iptables -P FORWARD DROP

#appending the default policy to add client ip along with the required protocol for input at the given interface
$sudo iptables -A INPUT -s 10.0.2.11 -p tcp -i enp0s3 -j ACCEPT

#appending to add client ip at output with the required protocol 
$sudo iptables -A OUTPUT -d 10.0.2.11 -p tcp -o enp0s3 -j ACCEPT

#appending to forward only 8.8.8.8 from client ip along with icmp protocol
$sudo iptables -A FORWARD -p icmp -o enp0s3 -s 8.8.8.8 -j ACCEPT
$sudo iptables -A FORWARD -p icmp -s 10.0.2.11 -i enp0s3 -d 8.8.8.8 -j ACCEPT

#enable postrouting in the masquerade mode at the required interface
$sudo iptables -t nat -A POSTROUTING -o enp0s8 -j MASQUERADE

#to enable port forwarding, changing the value to 1
$sudo sysctl -w net.ipv4.ip_forward=1

#deleting the default gateway to make sure traffic goes through 10.0.1.1
$sudo ip route del default via 10.0.2.1