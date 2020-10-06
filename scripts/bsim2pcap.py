import csv
import argparse
import pathlib
import sys
import os
from datetime import datetime
import pcapify

class CsvParser:
    """ Parse csv file, so it can be accesseb by column names """
    def __init__(self, file_path):
        """ 
            Loads the data from file.

            Args:
                file_path (str) = path to csv file
        """
        self.csv_data = {}

        with open(file_path, "r") as csv_file:
            reader = csv.reader(csv_file, delimiter=",")
            csv_data = [row for row in reader]

            try:
                for key in csv_data[0]:
                    self.csv_data[key] = []
                for row in csv_data[1:]:
                    for item, key in zip(row, self.csv_data.keys()):
                        self.csv_data[key].append(item)
            except IndexError:
                print(f"{file_path} is invalid csv file")

    def __getitem__(self, col_name):
        """ 
            Gets the whole column of col_name. 

            Args:
                col_name (str) = the csv column name

            Return:
                csv column (list)
        """
        return self.csv_data.get(col_name, [])

class HexDumpCreator:
    """ Parse the timestamp and hex data into formatted hex string """
    def __init__(self):
        self.start_timestamp = datetime.now().timestamp()

    def create_line(self, timestamp, hex_str):
        """ 
            Create the hex dump line in format: [YYYY-mm-dd HH:MM:SS,ms]hexdata. 
        
            Args:
                timestamp (int) = relative timestamp
                hex_str   (str) = hex data wthout 0x on the beginning and without spaces

            Return:
                formatted line (str)
        """
        strftime = self.timestamp_to_strtime(timestamp)
        return f"[{strftime}]{hex_str}"

    def timestamp_to_strtime(self, timestamp_us):
        """ 
            Convert timestamp to string.

            Args:
                timestamp_us (int) = relative timestamp expressed in microseconds
            
            Return:
                timestamp formated as [YYYY-mm-dd HH:MM:SS,ms]
        """
        timestamp = self.start_timestamp + (timestamp_us/1000000)
        timestamp = datetime.fromtimestamp(timestamp)
        return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")


class App:
    description = "bsim2pcap converts csv files that are dumped by BabbleSim "\
                  "to .pcap files that can be loaded into Wireshark. "\
                  "It is intented to parse only *_Rx_ files. If used with "\
                  "802.15.4 \"-nofcs\" option can used helpful to remove FCS bytes."
    def __init__(self):
        self.csv_file_paths = None
        self.hex_file_path = None
        self.pcap_file_path = None
        self.delete_fcs = None

        args = vars(self.get_arg_parser().parse_args())
        self.csv_file_paths = args.get("csvfiles")
        self.hex_file_path = "_out.hex"
        self.pcap_file_path = args.get("outfile")
        self.delete_fcs = args.get("deletefcs")

        for csv_file_path in self.csv_file_paths:
            if not pathlib.Path(csv_file_path).is_file():
                print(f"{self.csv_file_path} doesn't exist")
                sys.exit(-1)
        
        self.csv_parsers = [CsvParser(csv_file_path) for csv_file_path in self.csv_file_paths]
        self.hex_creator = HexDumpCreator()

    def __del__(self):
        """ Clean up intermediate files. """
        if self.hex_file_path is not None:
            os.remove(self.hex_file_path)

    def main(self):
        """ Parse csv files to on hex file and feed pcapify with it. """
        hex_logs = []
        for csv_parser in self.csv_parsers:
            for timestamp, packet in zip(csv_parser["rx_time_stamp"], csv_parser["packet"]):
                if len(packet) > 0:
                    packet = packet.replace(" ", "")
                    packet = packet[:-4] if self.delete_fcs else packet
                    hex_logs.append(self.hex_creator.create_line(int(timestamp), packet))

        with open(self.hex_file_path, "w") as out_file:
            for log in hex_logs:
                out_file.write(f"{log}\n")
        
        # 802.15.4 with FCS (c3), without FCS (e6)
        link = 230 if self.delete_fcs else 195
        pcapify.main([self.hex_file_path], self.pcap_file_path, None, link)
        
    def get_arg_parser(self):
        """ 
            Create argument parser. 

            Return:
                parser (argparse.ArgumentParser)
        """
        parser = argparse.ArgumentParser(description=App.description)
        parser.add_argument("-cf", "--csvfiles", nargs="+", required=True, type=str,
                            help="List of files containing the logs in csv format")
        parser.add_argument("-of", "--outfile", required=True, type=str,
                            help="The out .pcap file")
        parser.add_argument("-nofcs", "--deletefcs", required=False, action="store_true",
                            help="Trim fcs from hex data read from csv")
        return parser

if __name__ == "__main__":
    App().main()
