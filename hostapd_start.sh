sudo nmcli nm wifi off

sudo rfkill unblock wlan

sudo ifconfig wlan0 10.0.0.2/24 up
sleep 1
sudo service dnsmasq restart
sleep 1
sudo service radvd restart
sleep 1
sudo service hostapd start
#sudo hostapd /etc/hostapd/hostapd.conf
