#!/bin/bash

for specimen in ./dataset/*/; do
    if [ -d "$specimen" ]; then
        echo "Contents of $specimen:"
        ls "$specimen"
        echo

        for data in "$specimen"/*; do
            # cd $data
            # zeek -r net.pcap
            # cd -
            pcap_path="$data/conn.log"
            output_path="$TMP_DIR/$(basename $specimen)/$(basename $data)"
            mkdir -p $output_path
            python zeek2kyoto2006feature/scripts/zeek2feature.py $pcap_path $output_path
        done
    fi
done