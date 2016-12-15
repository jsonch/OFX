#!/bin/bash
 
 
if [ -z "$1" ]; then
        echo
        echo usage: $0 network-interface
        echo
        echo e.g. $0 eth0
        echo
        echo shows packets-per-second
        exit
fi
 
IF=$1
 
while true
do
        R1=`cat /sys/class/net/$IF/statistics/rx_packets`
        T1=`cat /sys/class/net/$IF/statistics/tx_packets`
        sleep 1
        R2=`cat /sys/class/net/$IF/statistics/rx_packets`
        T2=`cat /sys/class/net/$IF/statistics/tx_packets`
        TXPPS=`expr $T2 - $T1`
        RXPPS=`expr $R2 - $R1`
        echo "tx $IF: $TXPPS pkts/s rx $IF: $RXPPS pkts/s"
done
