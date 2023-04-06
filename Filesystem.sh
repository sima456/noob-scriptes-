#!/bin/bash

if [[ $# -eq 0 ]]; then
    echo "Please provide a file to analyze"
    exit 1
fi

FILE=$1

# Get the starting sector of the partition
START=$(fdisk -l $FILE | grep Linux | awk '{print $2}')

# Get the sector size
SECTOR_SIZE=$(fdisk -l $FILE | grep "Sector size" | awk '{print $4}')

# Calculate the starting byte offset
START_BYTE=$((START * SECTOR_SIZE))

# Get the partition size
PARTITION_SIZE=$(fdisk -l $FILE | grep Linux | awk '{print $4}')

# Calculate the ending byte offset
END_BYTE=$((START_BYTE + (PARTITION_SIZE * SECTOR_SIZE)))

echo "Partition starts at sector $START ($START_BYTE bytes)"
echo "Partition ends at sector $((START + PARTITION_SIZE - 1)) ($END_BYTE bytes)"

# Create a mount point directory
mkdir -p /mnt/image

# Mount the partition to the mount point directory
mount -o ro,loop,offset=$START_BYTE $FILE /mnt/image

# Use Sleuth Kit to analyze network artifacts
tshark_cmd="tshark -r /mnt/image/$FILE -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -E header=y -E separator=, -E quote=d -E occurrence=f"
tshark_output=$(sudo -u $USER sh -c "$tshark_cmd")

# Parse the tshark output and create a DataFrame
echo "$tshark_output" | awk -v FS=, '{ print $2 "," $3 "," $4 "," $5 "," $6 "," $7 "," $8 "," $9 }' > /tmp/tshark_output.csv

# Add new columns for packet direction and protocol
sed -i '1i Frame_Time_Relative,Source,Destination,Source_Port,Destination_Port,Direction,Protocol' /tmp/tshark_output.csv
sed -i 's/192\.168\.1\.1/Outgoing/g; s/192\.168\.1\.2/Incoming/g' /tmp/tshark_output.csv
awk -F',' '{ if($4 ~ /^[0-9]+$/) { print $0 ",TCP" } else { print $0 ",UDP" } }' /tmp/tshark_output.csv > /tmp/tshark_output_with_protocol.csv

# Plot the protocol counts
echo -e "Protocol,Direction,Count" > /tmp/protocol_counts.csv
awk -F',' '{ count[$7 "," $6] += 1 } END { for (i in count) { split(i, a, ","); print a[1] "," a[2] "," count[i] } }' /tmp/tshark_output_with_protocol.csv >> /tmp/protocol_counts.csv
python3 -c 'import pandas as pd; import matplotlib.pyplot as plt; df = pd.read_csv("/tmp/protocol_counts.csv"); df.groupby(["Protocol", "Direction"]).sum().unstack().plot(kind="bar"); plt.show()'

# Unmount the partition
umount /mnt/image

# Use gdisk to display partition information
echo ""
echo "GPT partition information:"
gdisk -l $FILE
