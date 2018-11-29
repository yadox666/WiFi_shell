#!/bin/bash
# by @yadox (2018)

channel=11
i=0

# Disable airplane mode if necessary
echo "Disabling airplane mode if enabled..."
rfkill unblock all

# If argument starts with stop, return all wifis to normal state
if [[ $1 == stop* ]] ; then
	echo "Killing all monitor mode VAPs and return to normal state..."
	echo "Restoring regdomain to ES..."
	iw reg set ES

	for mon in $(ls -v /sys/class/net/ | grep mon) ; do
		echo "Deleting monitor VAP $mon..."
		iw dev $mon del
		sleep 1
	done
	for phy in $(ls -v /sys/class/ieee80211/ | grep phy) ; do
		order="$(echo $phy | tr -dc '0-9')"
		echo "Creating managed VAP wlan$order from $phy..."
		iw phy $phy interface add "wlan$order" type managed >/dev/null 2>&1
		sleep 1
		ifconfig "wlan$order" up 2>/dev/null
	done
	echo "Starting network services..."
	service NetworkManager start >/dev/null 2>&1
	service avahi-daemon start >/dev/null 2>&1
	airmon-ng
	exit 0
fi

echo "Stopping conflicting services..."
airmon-ng check kill  >/dev/null 2>&1
sleep 2

echo "Changing regdomain to BO..."
iw reg set BP

for phy in $(ls -v /sys/class/ieee80211/ | grep phy) ; do
	order="$(echo $phy | tr -dc '0-9')"
	if [ ! -d "/sys/class/net/mon$order" ] ; then
		iw phy $phy interface add "mon$order" type monitor >/dev/null 2>&1
		sleep 1
		ifconfig "mon$order" down 2>/dev/null
		macchanger -A "mon$order" >/dev/null 2>&1
		sleep 1
		ifconfig "mon$order" up  >/dev/null 2>&1
		sleep 1
		iw dev "mon$order" set channel $channel 2>/dev/null
		setchannel="$(iwlist mon$order chan 2>/dev/null | grep Current | awk '{print $4,$5}' | tr -dc '0-9')"
		echo "Creating monitor VAP mon$order from $phy channel $setchannel with MAC $(macchanger -s mon$order | grep Current | cut -d' '  -f 5-)..."
		iw dev "mon$order" set txpower fixed 30000 2>/dev/null
	fi
done

for wlan in $(ls -v /sys/class/net/ | grep wlan) ; do
	echo "Deleting managed VAP $wlan..."
	ifconfig $wlan down
	iw dev $wlan del >/dev/null 2>&1
	sleep 1
done

airmon-ng
exit 0
