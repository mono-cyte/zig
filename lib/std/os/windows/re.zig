const std = @import("../../std.zig");
const windows = std.os.windows;
const ntdll = @import("ntdll.zig");

const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const LPCVOID = windows.LPCVOID;
const PMEMORY_BASIC_INFORMATION = windows.PMEMORY_BASIC_INFORMATION;
const MEM = windows.MEM;
const PAGE = windows.PAGE;
const ACCESS_MASK = windows.ACCESS_MASK;
const SIZE_T = windows.SIZE_T;
const ULONG_PTR = windows.ULONG_PTR;
const PVOID = windows.PVOID;
const HANDLE = windows.HANDLE;
const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
const LPTHREAD_START_ROUTINE = windows.LPTHREAD_START_ROUTINE;
const LPVOID = windows.LPVOID;
const OBJECT_ATTRIBUTES = windows.OBJECT_ATTRIBUTES;
const unexpectedStatus = windows.unexpectedStatus;
const STARTUPINFOW = windows.STARTUPINFOW;

pub extern "kernel32" fn VirtualQueryEx(hProcess: HANDLE, lpAddress: ?LPCVOID, lpBuffer: PMEMORY_BASIC_INFORMATION, dwLength: SIZE_T) callconv(.winapi) SIZE_T;

pub extern "kernel32" fn VirtualProtectEx(
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: *DWORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn OpenProcess(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) callconv(.winapi) ?HANDLE;

pub const PS_ATTRIBUTE_LIST = extern struct {
    TotalLength: SIZE_T,
    Attributes: [0]Entry,

    const List = @This();

    pub const PS_ATTRIBUTE = enum(usize) {
        pub const NUM = enum(u16) {
            ParentProcess = 0,
            DebugObject = 1,
            Token = 2,
            ClientId = 3,
            TebAddress = 4,
            ImageName = 5,
            ImageInfo = 6,
            MemoryReserve = 7,
            PriorityClass = 8,
            ErrorMode = 9,
            StdHandleInfo = 10,
            HandleList = 11,
            GroupAffinity = 12,
            PreferredNode = 13,
            IdealProcessor = 14,
            UmsThread = 15,
            MitigationOptions = 16,
            ProtectionLevel = 17,
            SecureProcess = 18,
            JobList = 19,
            ChildProcessPolicy = 20,
            AllApplicationPackagesPolicy = 21,
            Win32kFilter = 22,
            SafeOpenPromptOriginClaim = 23,
            BnoIsolation = 24,
            DesktopAppPolicy = 25,
            Chpe = 26,
            MitigationAuditOptions = 27,
            MachineType = 28,
            ComponentFilter = 29,
            EnableOptionalXStateFeatures = 30,
            SupportedMachines = 31,
            SveVectorLength = 32,
            Max,
        };

        pub const Bits = packed struct(usize) {
            num: u16,
            thread: bool,
            input: bool,
            additive: bool,
            _reserved: u45,
            pub fn init(num: NUM, thread: bool, input: bool, additive: bool) Bits {
                return .{
                    .num = @intFromEnum(num),
                    .thread = thread,
                    .input = input,
                    .additive = additive,
                    ._reserved = 0,
                };
            }
            pub fn asValue(self: Bits) usize {
                const v: usize = @bitCast(self);
                return v;
            }
        };

        pub fn value(num: NUM, thread: bool, input: bool, additive: bool) usize {
            return Bits.init(num, thread, input, additive).asValue();
        }

        PARENT_PROCESS = value(.ParentProcess, false, true, true),
        DEBUG_OBJECT = value(.DebugObject, false, true, true),
        TOKEN = value(.Token, false, true, true),
        CLIENT_ID = value(.ClientId, true, false, false),
        TEBA_ADDRESS = value(.TebAddress, true, false, false),
        IMAGE_NAME = value(.ImageName, false, true, false),
        IMAGE_INFO = value(.ImageInfo, false, false, false),
        MEMORY_RESERVE = value(.MemoryReserve, false, true, false),
        PRIORITY_CLASS = value(.PriorityClass, false, true, false),
        ERROR_MODE = value(.ErrorMode, false, true, false),
        STD_HANDLE_INFO = value(.StdHandleInfo, false, true, false),
        HANDLE_LIST = value(.HandleList, false, true, false),
        GROUP_AFFINITY = value(.GroupAffinity, true, true, false),
        PREFERRED_NODE = value(.PreferredNode, false, true, false),
        IDEAL_PROCESSOR = value(.IdealProcessor, true, true, false),
        UMS_THREAD = value(.UmsThread, true, true, false),
        MITIGATION_OPTIONS = value(.MitigationOptions, false, true, false),
        PROTECTION_LEVEL = value(.ProtectionLevel, false, true, true),
        SECURE_PROCESS = value(.SecureProcess, false, true, false),
        JOB_LIST = value(.JobList, false, true, false),
        CHILD_PROCESS_POLICY = value(.ChildProcessPolicy, false, true, false),
        ALL_APPLICATION_PACKAGES_POLICY = value(.AllApplicationPackagesPolicy, false, true, false),
        WIN32K_FILTER = value(.Win32kFilter, false, true, false),
        SAFE_OPEN_PROMPT_ORIGIN_CLAIM = value(.SafeOpenPromptOriginClaim, false, true, false),
        BNO_ISOLATION = value(.BnoIsolation, false, true, false),
        DESKTOP_APP_POLICY = value(.DesktopAppPolicy, false, true, false),
        CHPE = value(.Chpe, false, true, true),
        MITIGATION_AUDIT_OPTIONS = value(.MitigationAuditOptions, false, true, false),
        MACHINE_TYPE = value(.MachineType, false, true, true),
        COMPONENT_FILTER = value(.ComponentFilter, false, true, false),
        ENABLE_OPTIONAL_XSTATE_FEATURES = value(.EnableOptionalXStateFeatures, true, true, false),
        //SUPPORTED_MACHINES, // Unknown
        //SVE_VECTOR_LENGTH, // Unknown
    };

    const Entry = extern struct {
        Attribute: PS_ATTRIBUTE,
        Size: SIZE_T,
        Data: extern union {
            value: ULONG_PTR,
            ptr: PVOID,
        },
        ReturnLength: ?*SIZE_T,
    };

    pub fn Buffer(len: usize) type {
        return extern struct {
            list: List,
            entries: [len]Entry,

            const Self = @This();
            pub fn init() Self {
                var self: Self = undefined;
                self.list.TotalLength = @sizeOf(List) + len * @sizeOf(Entry);
                for (&self.entries) |*entry| {
                    entry.* = .{
                        .Attribute = undefined,
                        .Size = 0,
                        .Data = undefined,
                        .ReturnLength = null,
                    };
                }
                return self;
            }
            pub fn asList(self: *Self) *List {
                return @ptrCast(self);
            }
        };
    }
};

pub const PUSER_THREAD_START_ROUTINE = windows.PUSER_THREAD_START_ROUTINE;

pub const THREAD_CREATE_FLAGS = packed struct(u32) {
    CREATE_SUSPENDED: bool = false,
    SKIP_THREAD_ATTACH: bool = false, // Ex only
    HIDE_FROM_DEBUGGER: bool = false, // Ex only
    _reserved1: u1 = 0, // Ex only
    LOADER_WORKER: bool = false, // Ex only, since THRESHOLD
    SKIP_LOADER_INIT: bool = false, // Ex only, since REDSTONE2
    BYPASS_PROCESS_FREEZE: bool = false, // Ex only, since 19H1
    _reserved2: u25 = 0,
};

pub const CreateThreadFlags = packed struct(u32) {
    _reserved: u2 = 0,
    CREATE_SUSPEND: bool = false,
    _reserved2: u13 = 0,
    STACK_SIZE_PARAM_IS_A_RESERVATION: bool = false,
    _reserved3: u15 = 0,

    const Self = @This();
    const THREAD_CREATE_FLAGS = ntdll.THREAD_CREATE_FLAGS;
};

const CLIENT_ID = windows.CLIENT_ID;

const CreateThreadError = error{Unexpected};

pub fn CreateRemoteThreadEx(
    ProcessHandle: HANDLE,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    CreationFlags: CreateThreadFlags,
    lpAttributeList: ?*PROC_THREAD_ATTRIBUTE_LIST,
    lpThreadId: ?*DWORD,
) CreateThreadError!HANDLE {
    var thread_h: HANDLE = undefined;

    const access = ACCESS_MASK.Specific.Thread.ALL_ACCESS;

    var attrs: OBJECT_ATTRIBUTES = .{
        .Length = @sizeOf(OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .Attributes = .{},
        .ObjectName = null,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    if (lpThreadAttributes) |a| {
        attrs.Attributes.INHERIT = a.bInheritHandle != 0;
    }

    const flags: THREAD_CREATE_FLAGS = .{};
    if (CreationFlags.STACK_SIZE_PARAM_IS_A_RESERVATION) {}

    var cid: CLIENT_ID = undefined;

    var list = PS_ATTRIBUTE_LIST.Buffer(1).init();
    list.entries[0].Attribute = .CLIENT_ID;
    list.entries[0].Size = @sizeOf(CLIENT_ID);
    list.entries[0].Data.ptr = @ptrCast(&cid);

    if (lpAttributeList) |l| {
        _ = l;
    }

    const rc = std.os.windows.ntdll.NtCreateThreadEx(&thread_h, access, &attrs, ProcessHandle, @ptrCast(lpStartAddress), lpParameter, flags, 0, dwStackSize, 0, list.asList());
    switch (rc) {
        .SUCCESS => {
            if (lpThreadId) |tid| {
                tid.* = @truncate(@intFromPtr(cid.UniqueThread));
            }
            return thread_h;
        },
        else => return unexpectedStatus(rc),
    }
}

pub extern "kernel32" fn CreateRemoteThread(
    hProcess: HANDLE,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: CreateThreadFlags,
    lpThreadId: ?*DWORD,
) callconv(.winapi) ?HANDLE;

const GetCurrentProcess = windows.GetCurrentProcess;

pub fn CreateThread(
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: CreateThreadFlags,
    lpThreadId: ?*DWORD,
) ?HANDLE {
    return CreateRemoteThread(GetCurrentProcess(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

pub fn VirtualAlloc(
    BaseAddress: ?LPVOID,
    RegionSize: SIZE_T,
    AllocationType: MEM.ALLOCATE,
    Protect: PAGE,
) VirtualAllocError!LPVOID {
    return try VirtualAllocEx(
        GetCurrentProcess(),
        BaseAddress,
        RegionSize,
        AllocationType,
        Protect,
    );
}

const VirtualFreeExError = error{
    AccessDenied,
    InvalidHandle,
    InvalidParameter,
    Unexpected,
};

pub fn VirtualFreeEx(ProcessHandle: HANDLE, lpAddress: LPVOID, Size: SIZE_T, FreeType: MEM.FREE) VirtualFreeExError!void {
    if (FreeType.RELEASE and Size != 0) {
        return error.InvalidParameter;
    }

    var addr = lpAddress;
    var size = Size;
    var rc = ntdll.NtFreeVirtualMemory(
        ProcessHandle,
        &addr,
        &size,
        FreeType,
    );
    if (rc == .INVALID_PAGE_PROTECTION) {
        if (ProcessHandle == GetCurrentProcess()) {
            if (ntdll.RtlFlushSecureMemoryCache(lpAddress, Size) == 0) {
                return error.Unexpected;
            }
            rc = ntdll.NtFreeVirtualMemory(
                ProcessHandle,
                &addr,
                &size,
                FreeType,
            );
        }
    }
    switch (rc) {
        .SUCCESS => return,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_HANDLE => return error.InvalidHandle,
        .INVALID_PARAMETER => return error.InvalidParameter,
        else => return unexpectedStatus(rc),
    }
}

const VirtualFreeError = VirtualFreeExError;

pub fn VirtualFree(lpAddress: LPVOID, Size: SIZE_T, FreeType: MEM.FREE) VirtualFreeError!void {
    return try VirtualFreeEx(GetCurrentProcess(), lpAddress, Size, FreeType);
}

pub const VirtualAllocError = error{
    AccessDenied,
    InvalidHandle,
    InvalidParameter,
    Unexpected,
};

pub fn VirtualAllocEx(
    ProcessHandle: HANDLE,
    BaseAddress: ?LPVOID,
    RegionSize: SIZE_T,
    AllocationType: MEM.ALLOCATE,
    Protect: PAGE,
) VirtualAllocError!LPVOID {
    var base_addr: ?LPVOID = BaseAddress;
    var region_size: SIZE_T = RegionSize;
    const alloc_type = AllocationType;

    const rc = ntdll.NtAllocateVirtualMemory(
        ProcessHandle,
        @ptrCast(&base_addr),
        0,
        &region_size,
        alloc_type,
        Protect,
    );

    switch (rc) {
        .SUCCESS => return base_addr orelse error.Unexpected,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_HANDLE => return error.InvalidHandle,
        .INVALID_PARAMETER => return error.InvalidParameter,
        else => return unexpectedStatus(rc),
    }
}

pub const PROC_THREAD_ATTRIBUTE = enum(usize) {
    pub const Bits = packed struct(u32) {
        number: u16,
        thread: bool,
        input: bool,
        additive: bool,
        _reserved: u13,

        pub fn init(id: Num, thread: bool, input: bool, additive: bool) Bits {
            return .{
                .number = @intFromEnum(id),
                .thread = thread,
                .input = input,
                .additive = additive,
                ._reserved = 0,
            };
        }

        pub fn asValue(self: Bits) usize {
            const v: u32 = @bitCast(self);
            return @intCast(v);
        }
    };

    pub const Num = enum(u16) {
        ParentProcess = 0,
        HandleList = 2,
        GroupAffinity = 3,
        PreferredNode = 4,
        IdealProcessor = 5,
        UmsThread = 6,
        MitigationPolicy = 7,
        SecurityCapabilities = 9,
        ProtectionLevel = 11,
        JobList = 13,
        ChildProcessPolicy = 14,
        AllApplicationPackagesPolicy = 15,
        Win32kFilter = 16,
        SafeOpenPromptOriginClaim = 17,
        DesktopAppPolicy = 18,
        PseudoConsole = 22,
        MitigationAuditPolicy = 24,
        MachineType = 25,
        ComponentFilter = 26,
        EnableOptionalXStateFeatures = 27,
        TrustedApp = 29,
        SveVectorLength = 30,
    };

    fn value(id: Num, thread: bool, input: bool, additive: bool) usize {
        return Bits.init(id, thread, input, additive).asValue();
    }

    // Windows 7 and later
    PARENT_PROCESS = value(.ParentProcess, false, true, false),
    HANDLE_LIST = value(.HandleList, false, true, false),
    GROUP_AFFINITY = value(.GroupAffinity, true, true, false),
    PREFERRED_NODE = value(.PreferredNode, false, true, false),
    IDEAL_PROCESSOR = value(.IdealProcessor, true, true, false),
    UMS_THREAD = value(.UmsThread, true, true, false),
    MITIGATION_POLICY = value(.MitigationPolicy, false, true, false),
    // Windows 8 and later
    SECURITY_CAPABILITIES = value(.SecurityCapabilities, false, true, false),
    PROTECTION_LEVEL = value(.ProtectionLevel, false, true, false),
    // Windows 10 and later
    PSEUDOCONSOLE = value(.PseudoConsole, false, true, false), // 1809(RS5) and later
    MACHINE_TYPE = value(.MachineType, false, true, false), // 20H1(MN) and later
    ENABLE_OPTIONAL_XSTATE_FEATURES = value(.EnableOptionalXStateFeatures, true, true, false), // 21H1(FE) and later
    // Windows 11 and later
    SVE_VECTOR_LENGTH = value(.SveVectorLength, false, true, false), // 24H2(GE) and later

    const Self = @This();
    pub fn asBits(self: Self) Bits {
        return @bitCast(@as(u32, @truncate(@intFromEnum(self))));
    }

    pub fn getId(self: Self) Num {
        const id = self.asBits().number;
        return @enumFromInt(id);
    }
};

pub const PROC_THREAD_ATTRIBUTE_LIST = extern struct {
    Flags: u32,
    Size: u32,
    Count: u32,
    Reserved: u32,
    Unknown: ?*u32, // pointer to 0x00060001
    Entries: [0]Entry,

    const List = @This();

    pub const Entry = extern struct {
        Attribute: PROC_THREAD_ATTRIBUTE,
        Size: SIZE_T,
        lpValue: LPVOID,
    };

    pub fn getEntry(self: *List, i: u32) ?*Entry {
        if (i >= self.Count) {
            return null;
        } else {
            const entries: [*]Entry = @ptrCast(&self.Entries);
            return &entries[i];
        }
    }

    pub const InitError = error{
        InvalidFlags,
        TooManyAttributes,
        InsufficientBuffer,
    };

    pub fn cb(attr_cnt: u32) u32 {
        const list_size = @sizeOf(List);
        const entry_size = @sizeOf(Entry);
        return list_size + attr_cnt * entry_size;
    }

    pub fn Buffer(attr_cnt: u32, flags: u32) type {
        return extern struct {
            list: List,
            entries: [attr_cnt]Entry,

            const Self = @This();
            pub fn init() InitError!Self {
                if (flags != 0) return error.InvalidFlags; //INVALID_PARAMETER_3
                if (attr_cnt > 31) return error.TooManyAttributes; //INVALID_PARAMETER_2
                return .{ .list = .{
                    .Flags = 0,
                    .Size = attr_cnt,
                    .Count = 0,
                    .Reserved = 0,
                    .Unknown = null,
                    .Entries = .{},
                }, .entries = undefined };
            }
            pub fn asList(self: *Self) *List {
                return @ptrCast(self);
            }
        };
    }

    const UpdateError = error{
        InvalidParameter,
        InsufficientCapacity,
        AttributeAlreadySet,
        Unexpected,
    };

    pub fn update(
        list: *List,
        Flags: DWORD,
        attr: PROC_THREAD_ATTRIBUTE,
        lpValue: LPVOID,
        size: SIZE_T,
        lpPreviousValue: ?LPVOID,
        lpReturnSize: ?*SIZE_T,
    ) UpdateError!void {
        // Reserved parameters must be zero / null
        if ((Flags & 0xFFFFFFFE) != 0) return error.InvalidParameter;
        if (lpReturnSize != null) return error.InvalidParameter;

        if (list.Count >= list.Size) return error.InsufficientCapacity;

        const bits = attr.asBits();
        if (bits.additive and lpPreviousValue != null) return error.InvalidParameter;

        const id = attr.getId();
        const flag = @as(u32, 1) << @as(u5, @intCast(@intFromEnum(id) & 0x1F));
        if ((list.Flags & flag) != 0) return error.AttributeAlreadySet; // NTSTATUS: OBJECT_NAME_EXISTS

        switch (id) {
            .ParentProcess => if (size != @sizeOf(HANDLE)) return error.InvalidParameter,
            .HandleList => {
                if (size == 0 or (size % @sizeOf(HANDLE) != 0)) return error.InvalidParameter;
            },
            else => {
                if (size == 0) return error.InvalidParameter;
            },
        }

        const entry = list.getEntry(list.Count);

        entry.lpValue = lpValue;
        entry.Attribute = attr;
        entry.Size = size;

        list.Count += 1;
        list.Flags |= flag;
    }
};

const STARTUPINFOEXW = extern struct {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: *PROC_THREAD_ATTRIBUTE_LIST,
};
