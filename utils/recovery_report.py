# utils/recovery_report.py
# Generates summary reports of all recovered artifacts.

import json
import os
from datetime import datetime, timezone


class RecoveryReport:
    """
    Collects and reports on all artifacts recovered during a scan.
    """

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.recovered_files = []     # list of dicts
        self.inode_metadata = {}      # inode_id → {generation, inode_item_data}
        self.orphan_items_found = 0
        self.nodes_scanned = 0
        self.orphan_nodes_found = 0
        self.current_nodes_scanned = 0
        self.inline_files_recovered = 0
        self.regular_extents_recovered = 0
        self.regular_extents_failed = 0

    def add_recovered_file(self, entry):
        """
        Register a recovered file artifact.

        entry should be a dict with keys:
            filename, inode, generation, extent_type, size,
            output_path, source ('valid_item' or 'orphan_item'),
            timestamps (optional)
        """
        self.recovered_files.append(entry)

    def add_inode_metadata(self, inode_id, generation, metadata):
        """Store parsed INODE_ITEM data for an inode."""
        key = (inode_id, generation)
        if key not in self.inode_metadata:
            self.inode_metadata[key] = metadata

    def print_summary(self):
        """Print a human-readable summary to stdout."""
        print("\n" + "=" * 70)
        print("  RECOVERY SUMMARY")
        print("=" * 70)
        print(f"  Nodes Scanned (total):       {self.nodes_scanned}")
        print(f"  Orphan Nodes Found:          {self.orphan_nodes_found}")
        print(f"  Current-Gen Nodes Scanned:   {self.current_nodes_scanned}")
        print(f"  Orphan-Items Found:          {self.orphan_items_found}")
        print(f"  Inline Files Recovered:      {self.inline_files_recovered}")
        print(f"  Regular Extents Recovered:   {self.regular_extents_recovered}")
        print(f"  Regular Extents Failed:      {self.regular_extents_failed}")
        print(f"  Total Artifacts:             {len(self.recovered_files)}")
        print("-" * 70)

        if self.recovered_files:
            print(f"\n  {'Filename':<30} {'Inode':<8} {'Gen':<6} {'Type':<10} {'Size':<10} {'Source'}")
            print(f"  {'-'*30} {'-'*8} {'-'*6} {'-'*10} {'-'*10} {'-'*12}")
            for f in self.recovered_files:
                name = f.get("filename", "?")[:30]
                inode = f.get("inode", "?")
                gen = f.get("generation", "?")
                etype = f.get("extent_type", "?")
                size = f.get("size", 0)
                source = f.get("source", "?")

                size_str = _format_size(size) if isinstance(size, (int, float)) else str(size)
                print(f"  {name:<30} {str(inode):<8} {str(gen):<6} {etype:<10} {size_str:<10} {source}")

        # Inode metadata summary
        if self.inode_metadata:
            print(f"\n  Inode Metadata Recovered: {len(self.inode_metadata)} unique (inode, gen) pairs")

        print("=" * 70)

    def save_json_report(self):
        """Save a machine-readable JSON report to the output directory."""
        report_path = os.path.join(self.output_dir, "recovery_report.json")
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": {
                "nodes_scanned":            self.nodes_scanned,
                "orphan_nodes_found":       self.orphan_nodes_found,
                "current_nodes_scanned":    self.current_nodes_scanned,
                "orphan_items_found":       self.orphan_items_found,
                "inline_files_recovered":   self.inline_files_recovered,
                "regular_extents_recovered":self.regular_extents_recovered,
                "regular_extents_failed":   self.regular_extents_failed,
                "total_artifacts":          len(self.recovered_files),
            },
            "recovered_files": self.recovered_files,
            "inode_metadata": {
                f"{k[0]}_{k[1]}": _serialize_metadata(v)
                for k, v in self.inode_metadata.items()
            },
        }

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n[+] JSON report saved to: {report_path}")


def _format_size(size_bytes):
    """Format bytes into human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024*1024):.1f} MB"
    else:
        return f"{size_bytes / (1024*1024*1024):.1f} GB"


def _serialize_metadata(meta):
    """Make inode metadata JSON-serializable."""
    if meta is None:
        return None
    result = {}
    for k, v in meta.items():
        if isinstance(v, dict):
            result[k] = {sk: str(sv) for sk, sv in v.items()}
        else:
            result[k] = v
    return result
