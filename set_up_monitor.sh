#!/usr/bin/env bash

ifconfig wlan1 down
iwconfig wlan1 mode Monitor
ifconfig wlan1 up
