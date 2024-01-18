import csv
import os
import sys
import csv
import datetime
import csv
import os
import sys
import csv
import datetime



OUTPUT_DIR=os.environ.get("OUTPUT_DIR")
TMP_DIR=os.environ.get("TMP_DIR")

COMMON_LIST = [30, 60, 90, 120, 150]

def createRelativeTimeCSV(name):
    specimen_dir = os.path.join(TMP_DIR, name)
    


    if not os.path.exists(specimen_dir):
        print("Not exists")
        return

    dir_list = os.listdir(specimen_dir)
    for dir in dir_list:
        net_csv_path = os.path.join(specimen_dir, dir, "net_session.csv")
        
        csv_output_dir = os.path.join(specimen_dir, dir)
        if not os.path.exists(csv_output_dir):
            os.makedirs(csv_output_dir)
    
        output_csv_path = os.path.join(csv_output_dir, "net_session_relative.csv")

        with open(net_csv_path, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            header = next(csv_reader)

            # Get the first timestamp
            first_timestamp = None
            for row in csv_reader:
                first_timestamp = float(row[0]) + (float(row[1]) * 1e-9)
                break

            # Calculate relative time and write to the new CSV file
            with open(output_csv_path, 'w', newline='') as output_file:
                csv_writer = csv.writer(output_file)
                csv_writer.writerow(header)

                csv_file.seek(0)  # Reset the file pointer to the beginning
                next(csv_reader)  # Skip the header row

                for row in csv_reader:
                    timestamp = float(row[0]) + (float(row[1]) * 1e-9)

                    relative_time = timestamp - first_timestamp

                    csv_writer.writerow([relative_time] + row[2:])


def createCommon(name, sec):
    src_dir = os.path.join(TMP_DIR, name)
    out_dir=os.path.join(OUTPUT_DIR, f"common{sec}sec", name)
    dir_list = os.listdir(src_dir)
    for dir in dir_list:
        csv_file_path = os.path.join(src_dir, dir, "net_session_relative.csv")
        csv_out_dir=os.path.join(out_dir, dir)
        if not os.path.exists(csv_out_dir):
            os.makedirs(csv_out_dir)
        
        csv_file_output_path = os.path.join(csv_out_dir, f"net.csv")
        

        with open(csv_file_path, 'r') as input_file, open(csv_file_output_path, 'w', newline='') as output_file:
            csv_reader = csv.reader(input_file)
            csv_writer = csv.writer(output_file)

            header = next(csv_reader)

            for row in csv_reader:
                timestamp = float(row[0])
                if timestamp <= sec:
                    csv_writer.writerow(row)





if __name__ == "__main__":
    specimen_list = os.listdir(TMP_DIR)
    for specimen in specimen_list:
        createRelativeTimeCSV(specimen)
        for sec in COMMON_LIST:
            createCommon(specimen, sec)
    

