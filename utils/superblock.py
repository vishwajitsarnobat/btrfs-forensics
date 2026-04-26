# utils/superblock.py

import struct
import uuid
from .constants import SUPERBLOCK_OFFSET, MAGIC_NUMBER

def parse_superblock(image_path):
    """
    Reads the Btrfs superblock and extracts the master keys needed
    for forensic node validation.
    """
    print(f"[*] Parsing Superblock for {image_path}...")
    
    with open(image_path, "rb") as f:
        f.seek(SUPERBLOCK_OFFSET)
        raw_sb = f.read(256)
        
        # Validate Magic String
        magic = raw_sb[64:72]
        if magic != MAGIC_NUMBER:
            print("[!] Error: Not a valid Btrfs Superblock.")
            return None
            
        # Extract Keys
        raw_fsid = raw_sb[32:48]
        fsid = uuid.UUID(bytes=raw_fsid)
        generation = struct.unpack("<Q", raw_sb[72:80])[0]
        nodesize = struct.unpack("<I", raw_sb[148:152])[0]

        print("[+] Superblock Parsed Successfully!")
        print(f"    - FSID:       {fsid}")
        print(f"    - Generation: {generation}")
        print(f"    - Node Size:  {nodesize} bytes\n")
        
        return {
            "fsid": raw_fsid,
            "generation": generation,
            "nodesize": nodesize
        }
