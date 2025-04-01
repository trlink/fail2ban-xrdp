#!/bin/bash

# Überprüfen, ob eine IP-Adresse als Parameter übergeben wurde
if [ -z "$1" ]; then
  echo "Bitte geben Sie eine IP-Adresse als Parameter an."
  exit 1
fi

IP=$1
CHAIN="xrdp-block"

# Überprüfen, ob die Chain existiert, und erstellen, wenn nicht
if ! /sbin/iptables -L $CHAIN >/dev/null 2>&1; then
  /sbin/iptables -N $CHAIN
  echo "Chain $CHAIN wurde erstellt."
fi

# IP-Adresse zur Chain hinzufügen
# Überprüfen, ob die IP-Adresse bereits in der Chain existiert
if ! /sbin/iptables -C $CHAIN -s $IP -j DROP >/dev/null 2>&1; then
  /sbin/iptables -A $CHAIN -s $IP -j DROP
  echo "IP-Adresse $IP wurde zur Chain $CHAIN hinzugefügt."
else
  echo "IP-Adresse $IP ist bereits in der Chain $CHAIN vorhanden."
fi


# Überprüfen, ob die Chain in der INPUT-Chain vorhanden ist, und hinzufügen, wenn nicht
if ! /sbin/iptables -C INPUT -j $CHAIN >/dev/null 2>&1; then
  /sbin/iptables -A INPUT -j $CHAIN
  echo "Chain $CHAIN wurde zur INPUT-Chain hinzugefügt."
fi
