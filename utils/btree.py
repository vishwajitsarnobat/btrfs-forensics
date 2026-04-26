# utils/btree.py

import struct
import os
from .constants import (
    SUPERBLOCK_OFFSET, NODE_HEADER_SIZE, ITEM_POINTER_SIZE, 
    BTRFS_EXTENT_DATA_KEY, BTRFS_DIR_ITEM_KEY
)

OUTPUT_DIR = "recovery_output"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def parse_node_items(f, current_offset, node_gen):
    f.seek(current_offset)
    header = f.read(NODE_HEADER_SIZE)
    
    if header[100] != 0:
        return 
        
    nritems = struct.unpack("<I", header[96:100])[0]
    
    for i in range(nritems):
        pointer_offset = current_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
        f.seek(pointer_offset)
        pointer_raw = f.read(ITEM_POINTER_SIZE)
        
        key_raw, data_offset, data_size = struct.unpack("<17sII", pointer_raw)
        object_id = struct.unpack("<Q", key_raw[0:8])[0]
        item_type = key_raw[8]
        
        absolute_data_offset = current_offset + NODE_HEADER_SIZE + data_offset
        
        # --- CARVE FILENAMES ---
        if item_type == BTRFS_DIR_ITEM_KEY:
            f.seek(absolute_data_offset)
            
            # Read the 30-byte Btrfs Directory Item Header
            dir_item_header = f.read(30)
            
            # Unpack to get the Target Inode and the Name Length
            # <17s (Location Key) Q (Transid) H (Data Len) H (Name Len) B (Type)
            target_key, transid, data_len, name_len, file_type = struct.unpack("<17sQHHB", dir_item_header)
            
            # The target Inode is the first 8 bytes of the target_key
            target_inode = struct.unpack("<Q", target_key[0:8])[0]
            
            # Read the actual filename string
            raw_name = f.read(name_len)
            try:
                filename = raw_name.decode('utf-8', errors='ignore')
                print(f"        [DIR] Found Filename: '{filename}' -> Points to Inode {target_inode}")
            except:
                pass
                
        # --- CARVE FILE DATA ---
        elif item_type == BTRFS_EXTENT_DATA_KEY:
            f.seek(absolute_data_offset)
            extent_header = f.read(21)
            extent_type = extent_header[20]
            
            if extent_type == 0:
                payload_size = data_size - 21
                raw_file_bytes = f.read(payload_size)
                
                # Note: We temporarily save it as its Inode number until we cross-reference
                out_path = f"{OUTPUT_DIR}/inode_{object_id}_gen_{node_gen}_inline.bin"
                with open(out_path, "wb") as out_file:
                    out_file.write(raw_file_bytes)
                
                print(f"        [***] Extracted Data for Inode {object_id} -> {out_path}")

def sweep_for_orphans(image_path, sb_data):
    """
    Sweeps the raw disk for valid B-tree nodes that belong to previous
    generations, effectively bypassing the active filesystem tree.
    """
    print("[*] Starting raw disk sweep for orphaned CoW nodes...")
    fsid = sb_data["fsid"]
    sb_gen = sb_data["generation"]
    nodesize = sb_data["nodesize"]
    orphans_found = 0
    
    with open(image_path, "rb") as f:
        current_offset = SUPERBLOCK_OFFSET + nodesize
        
        while True:
            f.seek(current_offset)
            header = f.read(NODE_HEADER_SIZE)
            
            if not header or len(header) < NODE_HEADER_SIZE:
                break 
                
            node_fsid = header[32:48]
            
            if node_fsid == fsid:
                node_gen = struct.unpack("<Q", header[80:88])[0]
                
                # Check for Orphan Status
                if node_gen < sb_gen:
                    print(f"    [!] Orphaned Node Found at offset: {current_offset} (Gen: {node_gen})")
                    orphans_found += 1
                    parse_node_items(f, current_offset, node_gen)
            
            current_offset += nodesize

    print(f"\n[*] Sweep complete. Found {orphans_found} orphaned nodes.")
