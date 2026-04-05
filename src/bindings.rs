#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(non_snake_case)]
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl FsMagic {
    pub fn is_ephemeral_fs(self) -> bool {
        matches!(
            self,
            FsMagic::ANON_INODE_FS_MAGIC
                | FsMagic::AUTOFS_SUPER_MAGIC
                | FsMagic::BINFMTFS_MAGIC
                | FsMagic::BPF_FS_MAGIC
                | FsMagic::CGROUP_SUPER_MAGIC
                | FsMagic::CGROUP2_SUPER_MAGIC
                | FsMagic::DEBUGFS_MAGIC
                | FsMagic::DEVFS_SUPER_MAGIC
                | FsMagic::DEVPTS_SUPER_MAGIC
                | FsMagic::EFIVARFS_MAGIC
                | FsMagic::FUTEXFS_SUPER_MAGIC
                | FsMagic::HUGETLBFS_MAGIC
                | FsMagic::MQUEUE_MAGIC
                | FsMagic::PIPEFS_MAGIC
                | FsMagic::PROC_SUPER_MAGIC
                | FsMagic::PSTOREFS_MAGIC
                | FsMagic::RAMFS_MAGIC
                | FsMagic::SECURITYFS_MAGIC
                | FsMagic::SELINUX_MAGIC
                | FsMagic::SMACK_MAGIC
                | FsMagic::SOCKFS_MAGIC
                | FsMagic::SYSFS_MAGIC
                | FsMagic::TMPFS_MAGIC
                | FsMagic::TRACEFS_MAGIC
        )
    }

    pub fn magic_to_pretty_name(self) -> Option<&'static str> {
        match self {
            FsMagic::EXT4_SUPER_MAGIC => Some("ext4"),
            FsMagic::XFS_SUPER_MAGIC => Some("xfs"),
            FsMagic::BTRFS_SUPER_MAGIC => Some("btrfs"),
            FsMagic::F2FS_SUPER_MAGIC => Some("f2fs"),
            FsMagic::NFS_SUPER_MAGIC => Some("nfs"),
            FsMagic::SMB_SUPER_MAGIC => Some("smb"),
            FsMagic::SMB2_MAGIC_NUMBER => Some("smb"),
            FsMagic::OVERLAYFS_SUPER_MAGIC => Some("overlayfs"),
            FsMagic::SQUASHFS_MAGIC => Some("squashfs"),
            _ => None,
        }
    }
}
