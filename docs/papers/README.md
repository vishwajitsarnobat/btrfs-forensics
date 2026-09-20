# Paper library

Reference papers for the project, one PDF per work. Per-paper digests are in
[`../research.md`](../research.md) §4; BibTeX entries (by the key below) are in
[`../paper-draft.md`](../paper-draft.md) §12.1.

**File naming:** `firstauthor[_secondauthor]_short_topic_year.pdf`, lowercase,
underscores, year of the published version last. Add a row here with every
new PDF.

**Open access** records what research.md or the PDF itself states; "unverified"
means nobody has checked the licence, not that the paper is closed.

## Btrfs forensics and recovery

| File | Work | DOI / source | BibTeX key | Open access |
|---|---|---|---|---|
| `pandey_beyond_carving_2026.pdf` | Pandey, Jain & Shetty, "Beyond Carving: Deterministic Deleted File Recovery in Btrfs", IEEE Access, 2026 (authors' accepted version) | 10.1109/ACCESS.2026.3713173 | `pandey2026beyond` | yes (CC BY 4.0) |
| `bhat_wani_forensic_analysis_btrfs_2018.pdf` | Bhat & Wani, "Forensic analysis of B-tree file system (Btrfs)", Digital Investigation 27, 2018 | 10.1016/j.diin.2018.09.001 | `bhat2018forensic` | no |
| `wani_bhat_btrfs_dataset_2018.pdf` | Wani & Bhat, "Dataset for forensic analysis of B-tree file system", Data in Brief 18, 2018 | 10.1016/j.dib.2018.04.100 | `wani2018dataset` | unverified |
| `wani_antiforensic_btrfs_2020.pdf` | Wani, Bhat & Dehghantanha, "An analysis of anti-forensic capabilities of B-tree file system (Btrfs)", Australian Journal of Forensic Sciences 52(4), 2020 | 10.1080/00450618.2018.1533038 | `wani2020antiforensic` | no |
| `hilgert_multidevice_btrfs_tsk_2018.pdf` | Hilgert, Lambertz & Yang, "Forensic analysis of multiple device BTRFS configurations using The Sleuth Kit", DFRWS USA 2018 | 10.1016/j.diin.2018.04.020 | `hilgert2018multidevice` | unverified (DFRWS proceedings copy) |
| `juch_btrfs_forensics_2014.pdf` | Juch, "Btrfs Filesystem Forensics", master's thesis, TU Wien, 2014 | TU Wien library | — | unverified |
| `chaudhary_metarecoverx_2026.pdf` | Chaudhary, Panchal, Tak & Kumar, "MetaRecoverX: Recovery of Deleted Data and Associate Metadata from XFS and Btrfs Filesystems", IJISRT 11(4), 2026 | 10.38124/ijisrt/26apr738 | `chaudhary2026metarecoverx` | unverified |
| `pratyashrit_dmpedia_xfs_btrfs_recovery_2026.pdf` | Pratyashrit, Sharma & Sathiyasuntharam, "Recovery of Deleted Data and Associated Metadata from XFS and Btrfs Filesystems", DMPedia LNMR 1 (IMPACT 2026) | 10.65890/dmp.lnmr.IMPACT26.107 | `pratyashrit2026recovery` | unverified |

## Btrfs design

| File | Work | DOI / source | BibTeX key | Open access |
|---|---|---|---|---|
| `rodeh_btrfs_linux_btree_filesystem_2013.pdf` | Rodeh, Bacik & Mason, "BTRFS: The Linux B-Tree Filesystem", ACM Transactions on Storage 9(3), 2013 | 10.1145/2501620.2501623 | `rodeh2013btrfs` | unverified |
| `rodeh_btrees_shadowing_clones_2008.pdf` | Rodeh, "B-trees, Shadowing, and Clones", ACM Transactions on Storage 3(4), 2008 (IBM Haifa version) | 10.1145/1326542.1326544 | `rodeh2008btrees` | unverified |

## Data hiding and anti-forensics

| File | Work | DOI / source | BibTeX key | Open access |
|---|---|---|---|---|
| `toolan_humphries_hiding_data_btrfs_2026.pdf` | Toolan & Humphries, "Hiding data in Btrfs file systems", FSI: Digital Investigation 58:302198, 2026 | 10.1016/j.fsidi.2026.302198 | `toolan2026hiding` | yes (CC BY per OpenAlex) |
| `schwietert_hilgert_datahiding_corpus_2025.pdf` | Schwietert & Hilgert, "Data hiding in file systems: Current state, novel methods, and a standardized corpus", DFRWS APAC 2025 | 10.1016/j.fsidi.2025.301984 | `schwietert2025hiding` | unverified (DFRWS proceedings copy) |
| `schwietert_hilgert_mind_the_slack_2026.pdf` | Schwietert & Hilgert, "Mind the Slack? Reassessing the Relevance of File Slack in Modern Forensic Investigations", FSI: Digital Investigation, 2026 | 10.1016/j.fsidi.2026.302123 | `schwietert2026slack` | unverified |
| `goebel_fishy_framework_2018.pdf` | Göbel & Baier, "fishy – A Framework for Implementing Filesystem-Based Data Hiding Techniques", ICDF2C 2018 | 10.1007/978-3-030-05487-8_2 | `goebel2018fishy` | unverified |
| `goebel_generating_traces_filesystem_2024.pdf` | Göbel, Baier & Türr, "Generating Usable and Assessable Datasets Containing Anti-Forensic Traces at the Filesystem Level", 2024 | 10.1007/978-3-031-71025-4_12 | `goebel2025generating` | unverified |

## Copy-on-write and other filesystems (analogs, method precedents)

| File | Work | DOI / source | BibTeX key | Open access |
|---|---|---|---|---|
| `plum_dewald_apfs_recovery_2018.pdf` | Plum & Dewald, "Forensic APFS File Recovery", ARES 2018 | 10.1145/3230833.3232808 | `plum2018apfs` | listed gold OA (research.md §10.1) |
| `oh_hwang_f2fs_recovery_2025.pdf` | Oh & Hwang, "Advanced forensic recovery of deleted file data in F2FS", DFRWS APAC 2025, FSI: Digital Investigation 54:301976 | 10.1016/j.fsidi.2025.301976 | `oh2025f2fs` | yes (CC BY-NC-ND per OpenAlex) |
| `beebe_zfs_forensics_2009.pdf` | Beebe, Stacy & Stuckey, "Digital forensic implications of ZFS", DFRWS USA 2009 | 10.1016/j.diin.2009.06.006 | `beebe2009zfs` | unverified (DFRWS proceedings copy) |
| `hilgert_pooled_storage_tsk_slides_2017.pdf` | Hilgert, Lambertz & Plohmann, "Extending The Sleuth Kit and its underlying model for pooled storage file system forensic analysis", DFRWS USA 2017. **Slide deck, not the article** | 10.1016/j.diin.2017.06.003 | `hilgert2017pooled` | unverified |
| `hilgert_stacked_filesystems_2024.pdf` | Hilgert, Lambertz & Baier, "Forensic implications of stacked file systems", DFRWS EU 2024, FSI: Digital Investigation 48:301678 | 10.1016/j.fsidi.2023.301678 | `hilgert2024stacked` | unverified |
| `kim_ext4_xfs_tsk_2021.pdf` | Kim, Kim, Shin, Jo, Lee & Shon, "Ext4 and XFS File System Forensic Framework Based on TSK", Electronics 10(18), 2021 | 10.3390/electronics10182310 | `kim2021ext4` | yes (MDPI) |
| `lee_extsfr_2020.pdf` | Lee, Jo, Eo & Shon, "ExtSFR: scalable file recovery framework based on an Ext file system", Multimedia Tools and Applications 79, 2020 (online 2019) | 10.1007/s11042-019-7199-y | `lee2020extsfr` | no |

## Still wanted

| Work | Where | Why it is not here |
|---|---|---|
| Hilgert, "Contemporary File System Forensic Analysis", PhD thesis, Univ. Bonn, 2025 | <https://hdl.handle.net/20.500.11811/13313> (open access) | `bonndoc.ulb.uni-bonn.de` times out from the dev network (2026-08-17 and 2026-09-20); fetch from a browser |
| Vaheed Ali et al., "Efficient Recovery of Deleted Data and Metadata from XFS and Btrfs Filesystem", IEEE ICPCSN 2025 | DOI 10.1109/ICPCSN65854.2025.11035132 | Closed access, no repository copy (OpenAlex, 2026-09-20). Low priority: companion to the MetaRecoverX and DMPedia papers above |
| Hraiz, "Btrfs Forensic Analysis", thesis, Princess Sumaya Univ. for Technology, 2016 | ProQuest | Needs a ProQuest login |
