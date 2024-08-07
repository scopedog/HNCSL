#!/bin/sh
#
# This script automatically runs server and client programs and
# measures throughput for HNC, OpenSSL and no crypto algorithms.
#

REPEAT=10
TMP_FILE="bench.tmp"

cd ..
echo "Algorithm: Enc/dec speed (Gbps), Throughput (Gbps)"
for dir in no-crypt hnc-32bit-4 hnc-16bit-4 hnc-16bit-6 openssl 
do
    cd $dir
    /bin/echo -n "$dir: "
    cd server
    ./run.sh > /dev/null 2>&1 &
    cd ../client
    sleep 2
    enc_dec_sum=0
    thru_sum=0
    for i in `seq 1 $REPEAT`
    do
        rm -f $TMP_FILE
        ./run.sh 2>&1 > $TMP_FILE # Run
        res=`grep Encrypt/decrypt $TMP_FILE` # Try to get enc/dec speed
        if [ $? -eq 0 ]; then
             res=`echo $res | awk '{print $3}'`
             enc_dec_sum=`echo $enc_dec_sum+$res | bc`
        fi
        res=`grep Throughput $TMP_FILE | awk '{print $2}'` # Get throughput
        thru_sum=`echo $thru_sum+$res | bc`
        rm -f $TMP_FILE
        sleep 1
    done
    enc_dec_avg=`echo "scale=3; $enc_dec_sum/$REPEAT" | bc`
    thru_avg=`echo "scale=3; $thru_sum/$REPEAT" | bc`
    echo $enc_dec_avg, $thru_avg
    cd ../server
    pkill openssl_server
    pkill hncsld
    pkill run.sh
    cd ../..
    sleep 2
done

