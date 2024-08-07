#!/bin/sh

make clean all
./hncsld

# Or change CPU scheduler to SCHED_FIFO and give higher priority to hncsld for stable
# bandwidth on Linux as low CPU usage of hncsld causes lower bandwidth. 
#sudo chrt -f 99 ./hncsld
