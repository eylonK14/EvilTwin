#!/usr/bin/env bash

ifconfig $1 down
iwconfig $1 mode Monitor
ifconfig $1 up
