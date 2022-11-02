use bpf_ins::MemoryOpLoadType;

/// Enum for BPF helper function IDs.
pub enum Helpers {
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    ProbeRead = 4,
    TracePrintk = 6,
    SkbStoreBytes = 9,
    L3CsumReplace = 10,
    L4CsumReplace = 11,
    TailCall = 12,
    CloneRedirect = 13,
    GetCurrentPidTgid = 14,
    GetCurrentUidGid = 15,
    GetCurrentComm = 16,
    SkbVlanPush = 18,
    SkbVlanPop = 19,
    SkbGetTunnelKey = 20,
    SkbSetTunnelKey = 21,
    Redirect = 23,
    PerfEventOutput = 25,
    SkbLoadBytes = 26,
    GetStackid = 27,
    SkbGetTunnelOpt = 29,
    SkbSetTunnelOpt = 30,
    SkbChangeProto = 31,
    SkbChangeType = 32,
    SkbUnderCgroup = 33,
    ProbeWriteUser = 36,
    CurrentTaskUnderCgroup = 37,
    SkbChangeTail = 38,
    SkbPullData = 39,
    GetNumaNodeId = 42,
    SkbChangeHead = 43,
    XdpAdjustHead = 44,
    ProbeReadStr = 45,
    SetHash = 48,
    Setsockopt = 49,
    SkbAdjustRoom = 50,
    RedirectMap = 51,
    SkRedirectMap = 52,
    SockMapUpdate = 53,
    XdpAdjustMeta = 54,
    PerfEventReadValue = 55,
    PerfProgReadValue = 56,
    Getsockopt = 57,
    OverrideReturn = 58,
    SockOpsCbFlagsSet = 59,
    MsgRedirectMap = 60,
    MsgApplyBytes = 61,
    MsgCorkBytes = 62,
    MsgPullData = 63,
    Bind = 64,
    XdpAdjustTail = 65,
    SkbGetXfrmState = 66,
    GetStack = 67,
    SkbLoadBytesRelative = 68,
    FibLookup = 69,
    SockHashUpdate = 70,
    MsgRedirectHash = 71,
    SkRedirectHash = 72,
    LwtPushEncap = 73,
    LwtSeg6StoreBytes = 74,
    LwtSeg6AdjustSrh = 75,
    LwtSeg6Action = 76,
    RcRepeat = 77,
    RcKeydown = 78,
    SkSelectReuseport = 82,
    SkRelease = 86,
    MapPushElem = 87,
    MapPopElem = 88,
    MapPeekElem = 89,
    MsgPushData = 90,
    MsgPopData = 91,
    RcPointerRel = 92,
    SpinLock = 93,
    SpinUnlock = 94,
    SkbEcnSetCe = 97,
    TcpCheckSyncookie = 100,
    SysctlGetName = 101,
    SysctlGetCurrentValue = 102,
    SysctlGetNewValue = 103,
    SysctlSetNewValue = 104,
    Strtol = 105,
    Strtoul = 106,
    SkStorageDelete = 108,
    SendSignal = 109,
    SkbOutput = 111,
    ProbeReadUser = 112,
    ProbeReadKernel = 113,
    ProbeReadUserStr = 114,
    ProbeReadKernelStr = 115,
    TcpSendAck = 116,
    SendSignalThread = 117,
    ReadBranchRecords = 119,
    GetNsCurrentPidTgid = 120,
    XdpOutput = 121,
    SkAssign = 124,
    SeqPrintf = 126,
    SeqWrite = 127,
    RingbufOutput = 130,
    CsumLevel = 135,
    GetTaskStack = 141,
    LoadHdrOpt = 142,
    StoreHdrOpt = 143,
    ReserveHdrOpt = 144,
    DPath = 147,
    CopyFromUser = 148,
    SnprintfBtf = 149,
    SeqPrintfBtf = 150,
    RedirectNeigh = 152,
    RedirectPeer = 155,
    TaskStorageDelete = 157,
    BprmOptsSet = 159,
    ImaInodeHash = 161,
    CheckMtu = 163,
    ForEachMapElem = 164,
    Snprintf = 165,
}

impl Helpers {
    /// Returns the argument types for a given helper function.
    pub fn get_arg_types(&self) -> &[MemoryOpLoadType] {
        match self {
            Helpers::MapLookupElem => &[
                MemoryOpLoadType::Map,
                MemoryOpLoadType::MapIndex,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
            ],
            Helpers::MapUpdateElem => &[
                MemoryOpLoadType::Map,
                MemoryOpLoadType::MapIndex,
                MemoryOpLoadType::MapValue,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
            ],
            Helpers::MapDeleteElem => &[
                MemoryOpLoadType::Map,
                MemoryOpLoadType::MapIndex,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
            ],
            Helpers::MapPushElem => &[
                MemoryOpLoadType::Map,
                MemoryOpLoadType::MapValue,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
            ],
            Helpers::MapPopElem => &[
                MemoryOpLoadType::Map,
                MemoryOpLoadType::MapValue,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
            ],
            Helpers::MapPeekElem => &[
                MemoryOpLoadType::Map,
                MemoryOpLoadType::MapValue,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
            ],
            _ => &[
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
                MemoryOpLoadType::Void,
            ],
        }
    }

    /// Returns a Helper from the string representation of a helper function.
    ///
    /// # Arguments
    ///
    /// * `name` - The C name of the helper without the `bpf_` prefix.
    ///
    /// # Examples
    /// ```
    /// use bpf_script::helpers::Helpers;
    ///
    /// matches!(Helpers::from_string("map_update_elem"), Some(Helpers::MapUpdateElem));
    /// ```
    pub fn from_string(name: &str) -> Option<Self> {
        Some(if name.eq("map_update_elem") {
            Helpers::MapUpdateElem
        } else if name.eq("map_delete_elem") {
            Helpers::MapDeleteElem
        } else if name.eq("probe_read") {
            Helpers::ProbeRead
        } else if name.eq("trace_printk") {
            Helpers::TracePrintk
        } else if name.eq("skb_store_bytes") {
            Helpers::SkbStoreBytes
        } else if name.eq("l3_csum_replace") {
            Helpers::L3CsumReplace
        } else if name.eq("l4_csum_replace") {
            Helpers::L4CsumReplace
        } else if name.eq("tail_call") {
            Helpers::TailCall
        } else if name.eq("clone_redirect") {
            Helpers::CloneRedirect
        } else if name.eq("get_current_pid_tgid") {
            Helpers::GetCurrentPidTgid
        } else if name.eq("get_current_uid_gid") {
            Helpers::GetCurrentUidGid
        } else if name.eq("get_current_comm") {
            Helpers::GetCurrentComm
        } else if name.eq("skb_vlan_push") {
            Helpers::SkbVlanPush
        } else if name.eq("skb_vlan_pop") {
            Helpers::SkbVlanPop
        } else if name.eq("skb_get_tunnel_key") {
            Helpers::SkbGetTunnelKey
        } else if name.eq("skb_set_tunnel_key") {
            Helpers::SkbSetTunnelKey
        } else if name.eq("redirect") {
            Helpers::Redirect
        } else if name.eq("perf_event_output") {
            Helpers::PerfEventOutput
        } else if name.eq("skb_load_bytes") {
            Helpers::SkbLoadBytes
        } else if name.eq("get_stackid") {
            Helpers::GetStackid
        } else if name.eq("skb_get_tunnel_opt") {
            Helpers::SkbGetTunnelOpt
        } else if name.eq("skb_set_tunnel_opt") {
            Helpers::SkbSetTunnelOpt
        } else if name.eq("skb_change_proto") {
            Helpers::SkbChangeProto
        } else if name.eq("skb_change_type") {
            Helpers::SkbChangeType
        } else if name.eq("skb_under_cgroup") {
            Helpers::SkbUnderCgroup
        } else if name.eq("probe_write_user") {
            Helpers::ProbeWriteUser
        } else if name.eq("current_task_under_cgroup") {
            Helpers::CurrentTaskUnderCgroup
        } else if name.eq("skb_change_tail") {
            Helpers::SkbChangeTail
        } else if name.eq("skb_pull_data") {
            Helpers::SkbPullData
        } else if name.eq("get_numa_node_id") {
            Helpers::GetNumaNodeId
        } else if name.eq("skb_change_head") {
            Helpers::SkbChangeHead
        } else if name.eq("xdp_adjust_head") {
            Helpers::XdpAdjustHead
        } else if name.eq("probe_read_str") {
            Helpers::ProbeReadStr
        } else if name.eq("set_hash") {
            Helpers::SetHash
        } else if name.eq("setsockopt") {
            Helpers::Setsockopt
        } else if name.eq("skb_adjust_room") {
            Helpers::SkbAdjustRoom
        } else if name.eq("redirect_map") {
            Helpers::RedirectMap
        } else if name.eq("sk_redirect_map") {
            Helpers::SkRedirectMap
        } else if name.eq("sock_map_update") {
            Helpers::SockMapUpdate
        } else if name.eq("xdp_adjust_meta") {
            Helpers::XdpAdjustMeta
        } else if name.eq("perf_event_read_value") {
            Helpers::PerfEventReadValue
        } else if name.eq("perf_prog_read_value") {
            Helpers::PerfProgReadValue
        } else if name.eq("getsockopt") {
            Helpers::Getsockopt
        } else if name.eq("override_return") {
            Helpers::OverrideReturn
        } else if name.eq("sock_ops_cb_flags_set") {
            Helpers::SockOpsCbFlagsSet
        } else if name.eq("msg_redirect_map") {
            Helpers::MsgRedirectMap
        } else if name.eq("msg_apply_bytes") {
            Helpers::MsgApplyBytes
        } else if name.eq("msg_cork_bytes") {
            Helpers::MsgCorkBytes
        } else if name.eq("msg_pull_data") {
            Helpers::MsgPullData
        } else if name.eq("bind") {
            Helpers::Bind
        } else if name.eq("xdp_adjust_tail") {
            Helpers::XdpAdjustTail
        } else if name.eq("skb_get_xfrm_state") {
            Helpers::SkbGetXfrmState
        } else if name.eq("get_stack") {
            Helpers::GetStack
        } else if name.eq("skb_load_bytes_relative") {
            Helpers::SkbLoadBytesRelative
        } else if name.eq("fib_lookup") {
            Helpers::FibLookup
        } else if name.eq("sock_hash_update") {
            Helpers::SockHashUpdate
        } else if name.eq("msg_redirect_hash") {
            Helpers::MsgRedirectHash
        } else if name.eq("sk_redirect_hash") {
            Helpers::SkRedirectHash
        } else if name.eq("lwt_push_encap") {
            Helpers::LwtPushEncap
        } else if name.eq("lwt_seg6_store_bytes") {
            Helpers::LwtSeg6StoreBytes
        } else if name.eq("lwt_seg6_adjust_srh") {
            Helpers::LwtSeg6AdjustSrh
        } else if name.eq("lwt_seg6_action") {
            Helpers::LwtSeg6Action
        } else if name.eq("rc_repeat") {
            Helpers::RcRepeat
        } else if name.eq("rc_keydown") {
            Helpers::RcKeydown
        } else if name.eq("sk_select_reuseport") {
            Helpers::SkSelectReuseport
        } else if name.eq("sk_release") {
            Helpers::SkRelease
        } else if name.eq("map_push_elem") {
            Helpers::MapPushElem
        } else if name.eq("map_pop_elem") {
            Helpers::MapPopElem
        } else if name.eq("map_peek_elem") {
            Helpers::MapPeekElem
        } else if name.eq("msg_push_data") {
            Helpers::MsgPushData
        } else if name.eq("msg_pop_data") {
            Helpers::MsgPopData
        } else if name.eq("rc_pointer_rel") {
            Helpers::RcPointerRel
        } else if name.eq("spin_lock") {
            Helpers::SpinLock
        } else if name.eq("spin_unlock") {
            Helpers::SpinUnlock
        } else if name.eq("skb_ecn_set_ce") {
            Helpers::SkbEcnSetCe
        } else if name.eq("tcp_check_syncookie") {
            Helpers::TcpCheckSyncookie
        } else if name.eq("sysctl_get_name") {
            Helpers::SysctlGetName
        } else if name.eq("sysctl_get_current_value") {
            Helpers::SysctlGetCurrentValue
        } else if name.eq("sysctl_get_new_value") {
            Helpers::SysctlGetNewValue
        } else if name.eq("sysctl_set_new_value") {
            Helpers::SysctlSetNewValue
        } else if name.eq("strtol") {
            Helpers::Strtol
        } else if name.eq("strtoul") {
            Helpers::Strtoul
        } else if name.eq("sk_storage_delete") {
            Helpers::SkStorageDelete
        } else if name.eq("send_signal") {
            Helpers::SendSignal
        } else if name.eq("skb_output") {
            Helpers::SkbOutput
        } else if name.eq("probe_read_user") {
            Helpers::ProbeReadUser
        } else if name.eq("probe_read_kernel") {
            Helpers::ProbeReadKernel
        } else if name.eq("probe_read_user_str") {
            Helpers::ProbeReadUserStr
        } else if name.eq("probe_read_kernel_str") {
            Helpers::ProbeReadKernelStr
        } else if name.eq("tcp_send_ack") {
            Helpers::TcpSendAck
        } else if name.eq("send_signal_thread") {
            Helpers::SendSignalThread
        } else if name.eq("read_branch_records") {
            Helpers::ReadBranchRecords
        } else if name.eq("get_ns_current_pid_tgid") {
            Helpers::GetNsCurrentPidTgid
        } else if name.eq("xdp_output") {
            Helpers::XdpOutput
        } else if name.eq("sk_assign") {
            Helpers::SkAssign
        } else if name.eq("seq_printf") {
            Helpers::SeqPrintf
        } else if name.eq("seq_write") {
            Helpers::SeqWrite
        } else if name.eq("ringbuf_output") {
            Helpers::RingbufOutput
        } else if name.eq("csum_level") {
            Helpers::CsumLevel
        } else if name.eq("get_task_stack") {
            Helpers::GetTaskStack
        } else if name.eq("load_hdr_opt") {
            Helpers::LoadHdrOpt
        } else if name.eq("store_hdr_opt") {
            Helpers::StoreHdrOpt
        } else if name.eq("reserve_hdr_opt") {
            Helpers::ReserveHdrOpt
        } else if name.eq("d_path") {
            Helpers::DPath
        } else if name.eq("copy_from_user") {
            Helpers::CopyFromUser
        } else if name.eq("snprintf_btf") {
            Helpers::SnprintfBtf
        } else if name.eq("seq_printf_btf") {
            Helpers::SeqPrintfBtf
        } else if name.eq("redirect_neigh") {
            Helpers::RedirectNeigh
        } else if name.eq("redirect_peer") {
            Helpers::RedirectPeer
        } else if name.eq("task_storage_delete") {
            Helpers::TaskStorageDelete
        } else if name.eq("bprm_opts_set") {
            Helpers::BprmOptsSet
        } else if name.eq("ima_inode_hash") {
            Helpers::ImaInodeHash
        } else if name.eq("check_mtu") {
            Helpers::CheckMtu
        } else if name.eq("for_each_map_elem") {
            Helpers::ForEachMapElem
        } else if name.eq("snprintf") {
            Helpers::Snprintf
        } else {
            return None;
        })
    }
}
