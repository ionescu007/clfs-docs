# CLFS Internals

With the large number of Common Log File System (CLFS) CVEs issued in the last few months, and the removal of the respective section in the latest Windows Internals, 7th Edition, Part 2 (not that it went into this level of detail to begin with), I figured some unofficial 'documentation' would be helpful to those playing with this previously obscure component, associated with the Kernel Transaction Manager (KTM) that powers TxF (Transactional NTFS) and TxR (Transactional Registry).

All of this research was based on public information cleverly obtained from the Windows 11 SDK and symbol data for `clfs.sys`.

# Past References

There are two public sources of information on CLFS that I want to partially credit and refer readers to, which can help in digesting this information, somewhat. I will warn that these authors reverse-engineered many of the data structures (likely not having realized symbol data is available), but there are some nice diagrams and code.

The first is the *libclfs* project, which contains source code and some [documentation](https://github.com/libyal/libfsclfs/blob/7b3d245a837351d825f25a6e6f14882a03e843b7/documenation/Common%20Log%20File%20System%20(CLFS).asciidoc) for parsing parts of CLFS files.

The second is the *DeathNote of Microsoft Windows Kernel*, a [presentation](https://www.slideshare.net/PeterHlavaty/deathnote-of-microsoft-windows-kernel) by Peter Hlavaty on his initial fuzzing of CLFS files more than 5 years ago.

# Data Structures

CLFS data structures can be roughly divided into three types:
* Those that are stored in kernel-mode memory and attached to an object and follow its lifetime (such as an FCB attached to a File Object).

* Those that are ephemerally stored in the memory of a *user*- or *kernel*- mode caller that uses the CLFS Public API interface to parse, scan, or use a CLFS log file for their own purposes.

* Those that are persistently stored on disk, in the persistent Base Log File (BLF), and then parsed in memory. Some of these structures have in-memory versions that are sometimes, but not always, flushed back to disk.

Every such data structure is preceded by a `CLFS_NODE_ID`, which is documented in the `clfs.h` header file:
```
//
// Common log file system node identifier.  Every CLFS file system
// structure has a node identity and type.  The node type is a signature
// field while the size is used in for consistency checking.
//
typedef struct _CLFS_NODE_ID
{
    ULONG   cType;                                      // CLFS node type.
    ULONG   cbNode;                                     // CLFS node size.
} CLFS_NODE_ID, *PCLFS_NODE_ID;
```
## Node Types

All CLFS data structures are represented by a Node Type Code (NTC) that contains the letters CLFD (CLF Driver) in "leetspeak", ie `C1FD` followed by an identifier starting with `F000`.

The usual data structures seen in any File System (File Control Block, Volume Control Block, and Cache Control Block) are seen below:

```
const ULONG CLFS_NODE_TYPE_FCB                      = 0xC1FDF001;
const ULONG CLFS_NODE_TYPE_VCB                      = 0xC1FDF002;
const ULONG CLFS_NODE_TYPE_CCB                      = 0xC1FDF003;
```
The FCB is attached to the `FILE_OBJECT` through the `FsContext` field, and the CCB is attached through the `FsContext2`. Since CLFS does not handle volumes, no VCB is actually ever used.

When parsing IRPs, CLFS builds a Request (`CClfsRequest`) structure:
```
const ULONG CLFS_NODE_TYPE_REQ                      = 0xC1FDF004;
```
Note, however, that the structure does not actually have an NTC field, so the above is never used.

This next NTC is unused and it is unclear what the abbreviation CCA stands for:
```
const ULONG CLFS_NODE_TYPE_CCA                      = 0xC1FDF005;
```
The next set of NTCs are found in the on-disk data structures that are present inside of Base Log Files (BLF):
```
const ULONG CLFS_NODE_TYPE_SYMBOL                   = 0xC1FDF006;
const ULONG CLFS_NODE_TYPE_CLIENT_CONTEXT           = 0xC1FDF007;
const ULONG CLFS_NODE_TYPE_CONTAINER_CONTEXT        = 0xC1FDF008;
const ULONG CLFS_NODE_TYPE_SHARED_SECURITY_CONTEXT  = 0xC1FDF00D;
```
This next NTC is associated with the CLFS Device Extension that is attached to the `\Device\clfs` Device Object:
```
const ULONG CLFS_NODE_TYPE_DEVICE_EXTENSION         = 0xC1FDF009;
```
Marshalling contexts, identified by `CClfsKernelMarshallingContext` or `CClfsMarshallingContext` are represented by the following NTC.
```
const ULONG CLFS_NODE_TYPE_MARSHALING_AREA          = 0xC1FDF00A;
```
Such data structures are created through the `ClfsCreateMarshallingArea` API, which is documented on MSDN and not relevant to our purposes.

When using the `ScanLogContainers` and `PrepareLogArchive` user-mode APIs, an Archive Context (`CLFS_LOG_ARCHIVE_CONTEXT`) and Scan Context (`CLFS_LOG_SCAN_CONTEXT`) can be created, with the following NTCs:
```
const ULONG CLFS_NODE_TYPE_ARCHIVE_CONTEXT          = 0xC1FDF00C;
const ULONG CLFS_NODE_TYPE_SCAN_CONTEXT             = 0xC1FDF00E;
```
These data structures are documented on MSDN and not interesting for our purposes.

Finally, when using log restart areas, with either the `ReadLogRestartArea` or `WriteLogRestartArea` APIs, the following two NTCs are used for the `pvContext` data structure that is allocated and used.
```
const ULONG CLFS_NODE_TYPE_LOG_READ_IOCB            = 0xC1FDF00F;
const ULONG CLFS_NODE_TYPE_LOG_WRITE_IOCB           = 0xC1FDF010;
```
Once again, these two ephemeral data structures are not relevant to our purposes.

## Log Blocks and Sectors
Every Base Log File is made up various *records*. These records are stored in *sectors*, which are written to in units of I/O called *log blocks*. These log blocks are always read and written in an atomic fashion to guarantee consistency.

### Sectors

The sector size is always 512 bytes, defined by the following constants:
```
const ULONG CLFS_SECTOR_SIZE    = 0x00000200;
const UCHAR SECTORSHIFT         = 9;
```
#### Sector Types
A sector can belong to one of these types:
```
const UCHAR SECTOR_BLOCK_NONE   = 0x00;
const UCHAR SECTOR_BLOCK_DATA   = 0x04;
const UCHAR SECTOR_BLOCK_OWNER  = 0x08;
const UCHAR SECTOR_BLOCK_BASE   = 0x10;
```
In the case of Base Log File records, the sectors will always be of the `SECTOR_BLOCK_BASE` type.

#### Sector Signatures
At the end of every sector will be a *signature*, which is used to guarantee consistency. This signature is composed of the following bytes:
```
[Sector Block Type][Usn]
```
The *sector block type* corresponds to one of the types define above, with an additional flag to identify the first sector and/or the last sector, defined below:
```
const UCHAR SECTOR_BLOCK_END    = 0x20;
const UCHAR SECTOR_BLOCK_BEGIN  = 0x40;
```
The *update sequence number* (USN), on the other hand, comes from the log block header (see below) at the beginning of the first sector, and identifies all sectors as having been part of the same non-torn atomic I/O.

### Log Block Header
Every log block starts with a *log block header*, called the `CLFS_LOG_BLOCK_HEADER`. Unfortunately its definition is not available in any public sources, but the `CreateMetadataBlock` and `ClfsStampLogBlock` functions give us a fairly clear overview of the fields.

All offsets, both in the log block header itself, as well as in records part of the block, are always based on the beginning of the log block (the first sector).
```
typedef struct _CLFS_LOG_BLOCK_HEADER
{
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    UCHAR Usn;
    CLFS_CLIENT_ID ClientId;
    USHORT TotalSectorCount;
    USHORT ValidSectorCount;
    ULONG Padding;
    ULONG Checksum;
    ULONG Flags;
    CLFS_LSN CurrentLsn;
    CLFS_LSN NextLsn;
    ULONG RecordOffsets[16];
    ULONG SignaturesOffset;
} CLFS_LOG_BLOCK_HEADER, *PCLFS_LOG_BLOCK_HEADER;
```
The *major* and *minor* version numbers are always set according to the following constants:
```
const UCHAR MAJORVERSION  = 0x15;
const UCHAR MINORVERSION  = 0x00;
```
The *update count* is incremented each time a consistent write has completed.

The *client ID* corresponds to the client identifier associated with the block, also called the *stream identifier*. For metadata blocks such as the ones in the Base Log File, this is irrelevant, and will always be set to `0`.

The *total sector count* and *valid sector count* correspond to the number of sectors in the block, both initially as well as after truncation. For the Base Log File, these numbers will always be fixed as shown in the next section.

The *checksum* is the checksum of the contents of the log block, using the fixed polynomial `0x04C11DB7`.

The *flags* are defined as follows:
```
const ULONG CLFS_BLOCK_RESET             = 0x00000000;
const ULONG CLFS_BLOCK_ENCODED           = 0x00000001;
const ULONG CLFS_BLOCK_DECODED           = 0x00000002;
const ULONG CLFS_BLOCK_LATCHED           = 0x00000004;
const ULONG CLFS_BLOCK_TRUNCATE_DISCARD  = 0x00000008;
```
You should always expect to see the blocks of the Base Log File as being *encoded* when stored in their on-disk format.

The *current LSN* and *next LSN*, for base blocks, are always set to `CLFS_LSN_INVALID`.

The first *record offset* always starts at `sizeof(CLFS_LOG_BLOCK_HEADER)`. No other record offsets are used for base blocks.

Finally, the *signatures offset* corresponds to an in-memory array that is used to store all of sector bytes that were overwritten by the sector signatures. The array is located on the last sector, and must be large enough to hold `TotalSectorCount * overwritten sector data` bytes , remembering to leave space for the ULONG-aligned signature data of the last sector itself. When reading the Base Log File from disk, it is critical to parse this array, and take each 2 bytes and overlay them on top of the signature bytes of each corresponding sector (restoring the original data bytes).

## Metadata Blocks

The Base Log File is composed of 6 different *metadata blocks*, which are all examples of *base log blocks* as shown earlier. Each of them will first therefore have a log block header. These count of metadata blocks is defined by the following constant:
```
const USHORT CLFS_METADATA_BLOCK_COUNT  = 6;
```

The metadata blocks always only have a single record, so `RecordOffsets[0]` is always used from the log block header to identify the record starting offset. This fact was indicated in the earlier section as well, and is repeated here for edification.

### Metadata Records
The three types of records that exist in such blocks are as follows:
|Record Type  |Metadata Block Type  | Description |
|--|--|--|
|Control Record|Control Metadata Block  |Contains information about the *layout*, the *extend* area, and the *truncate* area |
|Base Record|General Metadata Block|Contains the *symbol tables* that store information on the various *client*, *container* and *security* contexts associated with the Base Log File, as well as accounting information on these. |
|Truncate Record|Scratch Metadata Block|Contains information on every client (stream) that needs to have sectors changed as a result of a truncate operation, and the relevant sector byte changes.|

#### Metadata Record Header
All of these metadata records will be described in the next section, but first note that they all begin with the same header, shown below:
```
typedef struct _CLFS_METADATA_RECORD_HEADER
{
    ULONGLONG ullDumpCount;
} CLFS_METADATA_RECORD_HEADER, *PCLFS_METADATA_RECORD_HEADER;
```
This *dump count* corresponds to a sort of sequence number for the metadata record, and can be used to identify the newest, or "freshest" copy of a record.

### Shadow Blocks
You may have realized that only 3 metadata records were defined in the table above, yet 6 metadata blocks exist (and we said each metadata block only contains one record). This is due to *shadow blocks*, which are yet another technique used for consistency. These shadow blocks contain the previous copy of the metadata that was written, and by using the dump count in the record header, can be used to restore previously known good data in case of torn writes.

### Metadata Block Types
Taking everything we have explained above, we can use the following enumeration to describe the 6 types of metadata blocks.
```
typedef enum _CLFS_METADATA_BLOCK_TYPE
{
    ClfsMetaBlockControl,
    ClfsMetaBlockControlShadow,
    ClfsMetaBlockGeneral,
    ClfsMetaBlockGeneralShadow,
    ClfsMetaBlockScratch,
    ClfsMetaBlockScratchShadow
} CLFS_METADATA_BLOCK_TYPE, *PCLFS_METADATA_BLOCK_TYPE;
```
The function `CClfsBaseFilePersisted::CreateImage` can be useful for seeing how the various metadata blocks are created, written, and flushed in the Base Log File.

We will now take a look at each metadata block type in detail.

## Control Record

The *control record* is always composed of 2 sectors, as defined by the constant below:
```
const USHORT CLFS_CONTROL_BLOCK_RAW_SECTORS  = 2;
```
It is defined by the structure `CLFS_CONTROL_RECORD`, which is shown below:
```
typedef struct _CLFS_CONTROL_RECORD
{
    CLFS_METADATA_RECORD_HEADER hdrControlRecord;
    ULONGLONG ullMagicValue;
    UCHAR Version;
    CLFS_EXTEND_STATE eExtendState;
    USHORT iExtendBlock;
    USHORT iFlushBlock;
    ULONG cNewBlockSectors;
    ULONG cExtendStartSectors;
    ULONG cExtendSectors;
    CLFS_TRUNCATE_CONTEXT cxTruncate;
    USHORT cBlocks;
    ULONG cReserved;
    CLFS_METADATA_BLOCK rgBlocks[ANYSIZE_ARRAY];
} CLFS_CONTROL_RECORD, *PCLFS_CONTROL_RECORD;
```
### Version and Magic

Apart from starting with the previously described standard header, control records also have the CLFS string in "leetspeak" (`C1F5`) repeated twice and then inverted as per the following *magic value* constant:
```
const ULONGLONG CLFS_CONTROL_RECORD_MAGIC_VALUE = 0xC1F5C1F500005F1C;
```
The *version number* is currently defined to `1`, as per the constant shown here:
```
const UCHAR MAJORVERSION_CONTROL  = 0x01;
```
### Extend Context
After the version, the next set of fields are all related to CLFS Log Extension. This data could potentially be non-zero in memory, but for a stable Base Log File on disk, you should expect all of these fields to be zero. This does not, of course, imply the CLFS driver or code necessarily makes this assumption.

The first such field identifies the current *extend state* for the file, using the enumeration below:
```
typedef enum _CLFS_EXTEND_STATE
{
    ClfsExtendStateNone,
    ClfsExtendStateExtendingFsd,
    ClfsExtendStateFlushingBlock
} CLFS_EXTEND_STATE, *PCLFS_EXTEND_STATE;
```
The next two values identify the index of the block being *extended*, followed by the block being *flushed* -- the latter of which will normally be the shadow block.

Next, the sector size of the *new block* is stored, as well as the original sector size *before the extend* operation, follow.

Finally, the number of sectors that were added (*extended*) is present.

### Truncate Context
Unlike the extend context, the *truncate context* is stored in its own data structure (`CLFS_TRUNCATE_CONTEXT`), shown below. Once again, you should expect these fields to be all zeroed out when present on disk, with the same caveat on the CLFS driver's own assumptions.
```
typedef struct _CLFS_TRUNCATE_CONTEXT
{
    CLFS_TRUNCATE_STATE eTruncateState;
    CLFS_CLIENT_ID cClients;
    CLFS_CLIENT_ID iClient;
    CLFS_LSN lsnOwnerPage;
    CLFS_LSN lsnLastOwnerPage;
    ULONG cInvalidSector;
} CLFS_TRUNCATE_CONTEXT, *PCLFS_TRUNCATE_CONTEXT;
```
The *truncation state* is represented by the values in this enumeration:
```
typedef enum _CLFS_TRUNCATE_STATE
{
    ClfsTruncateStateNone,
    ClfsTruncateStateModifyingStream,
    ClfsTruncateStateSavingOwner,
    ClfsTruncateStateModifyingOwner,
    ClfsTruncateStateSavingDiscardBlock,
    ClfsTruncateStateModifyingDiscardBlock
} CLFS_TRUNCATE_STATE, *PCLFS_TRUNCATE_STATE;
```
Next, the *number of clients* being truncated is stored, followed by the precise *client index* that is currently being truncated.

Then, the LSN of the *current owner page* being worked on, as well as the LSN of the *last owner page*, are stored if the owner block is being saved or modified.

Finally, if the *discard block* is being saved or modified, then the `cInvalidSector` field identifies the sector index currently being processed as part of that block.

### Block Context
The control record ends with the `rgBlocks` array which defines the set of metadata blocks that exist in the Base Log File. Although we know that this is expected to be 6, there could potentially exist additional metadate blocks, and so for forward support, the `cBlocks` field indicates the number of blocks in the array.

Each array entry is identified by the `CLFS_METADATA_BLOCK` structure, shown below:
```
typedef struct _CLFS_METADATA_BLOCK
{
    union
    {
        PUCHAR pbImage;
        ULONGLONG ullAlignment;
    };
    ULONG cbImage;
    ULONG cbOffset;
    CLFS_METADATA_BLOCK_TYPE eBlockType;
} CLFS_METADATA_BLOCK, *PCLFS_METADATA_BLOCK;
```
On disk, the `cbOffset` field indicates the offset, starting from the control metadata block (i.e.: the first sector in the Base Log File). of where the metadata block can be found. The `cbImage` field, on the other hand, contains the size of the corresponding block, while the `eBlockType` corresponds to the previously shown enumeration of possible metadata block types.

In memory, an additional field, `pbImage`, is used to store a pointer to the data in kernel-mode memory. You should expect this field to be zeroed out when stored on disk, and hopefully not trusted when loaded from an existing Base Log File.

## Base Record
The base record contains information about the *clients* and *containers* associated with the Base Log File, as well as their related *contexts*. Furthermore, the *shared security context* for each container is also stored here. Finally, some state information is also present. 

This information is stored in a combination of data structures described as *symbols*, as well as fields in a header at the beginning of the record.

### Clients

A client is a user of a CLFS log. For the Base Log File, a single *metadata client* exists initially. The maximum number of clients is defined as follows:
```
const UCHAR MAX_CLIENTS_DEFAULT          = 124;
```
Each client has an identifier, whose highest value is defined as such:
```
const UCHAR HIGHEST_CLIENT_ID            = 96;
```
All clients can be looked up through a *client symbol table*, which has a bucket size defined by the constant shown below:
```
const UCHAR CLIENT_SYMTBL_SIZE           = 11;
```
### Containers
A container is the entity that is holding the log records for particular data subject to CLFS semantics. The maximum number of containers supported by CLFS is shown below:
```
const ULONG MAX_CONTAINERS_DEFAULT       = 1024;
```
Just like clients, containers can be looked up in their own *container symbol table*, with the following bucket size:
```
const UCHAR CONTAINER_SYMTBL_SIZE        = 11;
```
### Shared Security Context
Shared security contexts are used to store the security descriptors for the containers that are described by the Base Log File. 

No maximum value seems to exist, and, just like the previously shown symbol tables, the bucket size for the *shared security context symbol table* is as follows:
```
const UCHAR SHARED_SECURITY_SYMTBL_SIZE  = 11;
```

### Base Record Header
In order to describe these elements, the base record begins with a header (`CLFS_BASE_RECORD_HEADER`), which is described by the following structure:
```
typedef struct _CLFS_BASE_RECORD_HEADER
{
    CLFS_METADATA_RECORD_HEADER hdrBaseRecord;
    CLFS_LOG_ID cidLog;
    ULONGLONG rgClientSymTbl[CLIENT_SYMTBL_SIZE];
    ULONGLONG rgContainerSymTbl[CONTAINER_SYMTBL_SIZE];
    ULONGLONG rgSecuritySymTbl[SHARED_SECURITY_SYMTBL_SIZE];
    ULONG cNextContainer;
    CLFS_CLIENT_ID cNextClient;
    ULONG cFreeContainers;
    ULONG cActiveContainers;
    ULONG cbFreeContainers;
    ULONG cbBusyContainers;
    ULONG rgClients[MAX_CLIENTS_DEFAULT];
    ULONG rgContainers[MAX_CONTAINERS_DEFAULT];
    ULONG cbSymbolZone;
    ULONG cbSector;
    USHORT bUnused;
    CLFS_LOG_STATE eLogState;
    UCHAR cUsn;
    UCHAR cClients;
} CLFS_BASE_RECORD_HEADER, *PCLFS_BASE_RECORD_HEADER;
```
Apart from the standard metadata header, the base record header also includes the *log identifier* which is a randomly generated UUID at log creation time.

Next, the following three fields contain the symbol tables (which are *hash tables*) for the 3 contexts described above. Each entry is a 64-bit offset to a *hash symbol*, which will be described in the next section. Collisions are handled using a binary search tree. Following each non-zero hash symbol, the appropriate context structure would follow.

Continuing, the next available *container index* and *client index* are stored, followed by the count of *free containers* and *active containers*. The former field (`cFreeContainers`), however, seems to never be used. The next two fields, `cbFreeContainers` and `cbBusyContainers` are zeroed out and never used.

We then encounter the array of 32-bit offsets that point to each client context and container context, respectively. Unlike the hash symbol table, these offsets point directly to the appropriate context structure (i.e.: you would expect to find their associated hash symbol above). The `rgContainers` array should have the same number of entries as the `cActiveContainers` field described above.

The `cbSymbolZone` field contains the size of the *symbol zone* where all symbols (i.e.: the 3 types of contexts) can be found, or in other words, the next free available offset for a new symbol.

Although named otherwise, both the `cbSector` and `bUnused` fields are unused.

Near the end of the header, we find the current state of the log, which can be composed of the following constants:
```
typedef UCHAR CLFS_LOG_STATE, *PCLFS_LOG_STATE;
const CLFS_LOG_STATE CLFS_LOG_UNINITIALIZED    = 0x01;
const CLFS_LOG_STATE CLFS_LOG_INITIALIZED      = 0x02;
const CLFS_LOG_STATE CLFS_LOG_ACTIVE           = 0x04;
const CLFS_LOG_STATE CLFS_LOG_PENDING_DELETE   = 0x08;
const CLFS_LOG_STATE CLFS_LOG_PENDING_ARCHIVE  = 0x10;
const CLFS_LOG_STATE CLFS_LOG_SHUTDOWN         = 0x20;
const CLFS_LOG_STATE CLFS_LOG_MULTIPLEXED      = 0x40;
const CLFS_LOG_STATE CLFS_LOG_SECURE           = 0x80;
```
This state is then followed by the *next USN* to use for a container (which will match the *current USN* of that container context), and finally, the number of clients stored in the Base Log File (which should match the number of entries in the `rgClients` array).

With an understanding of the header, we can now look at how symbols are defined in the base record.

## Symbols

Clients, containers, and shared security contexts in the Base Log File are represented by *symbols*, which are preceded by the `CLFSHASHSYM` structure shown below. Each 64-bit offset in the 3 tables shown earlier points to one of these structures.
```
typedef struct _CLFSHASHSYM
{
    CLFS_NODE_ID cidNode;
    ULONG ulHash;
    ULONG cbHash;
    ULONGLONG ulBelow;
    ULONGLONG ulAbove;
    LONG cbSymName;
    LONG cbOffset;
    BOOLEAN fDeleted;
} CLFSHASHSYM, *PCLFSHASHSYM;
```
You should expect consistent nodes to always be of size `sizeof(CLFSHASHSYM)` and of type `CLFS_NODE_TYPE_SYMBOL`.

The `ulHash` field contains the *hash code*, which is computed using Hollub's version (the one that's often misprinted and causes poor results) of the PJW Hash of a `UNICODE_STRING` that stores the symbol's name, with each letter upper cased. See `ClfsHashPJW` for the implementation (note the XOR'ing of the high byte instead of the masking, as in `ElfHash` and the correct PJW Hash). The full name of the symbol is referenced by its offset, in the `cbSymName` field.

The `cbHash` field contains the size of the symbol data (without the header), while `cbOffset` contains the offset of where the data begins. `fDeleted` is a flag indicating if the symbol has been deleted.

Finally, in the case of hash collisions, the `ulBelow` and `ulAbove` are the 64-bit offsets of the preceding and following symbol, respectively, treating collisions as a binary search tree. If there are no collisions, these fields will be zeroed out.

> **Note:** All these offsets continue to be based on the beginning of the general block (i.e.: the base record).

## Client Context
The first context stored in the symbol tables is the *client context*, which identifies a user, or client, of a log file. There will always be at least one such *metadata client* created in every Base Log File.

Each client context is described by the `CLFS_CLIENT_CONTEXT` structure, shown below:
```
typedef struct _CLFS_CLIENT_CONTEXT
{
    CLFS_NODE_ID cidNode;
    CLFS_CLIENT_ID cidClient;
    USHORT fAttributes;
    ULONG cbFlushThreshold;
    ULONG cShadowSectors;
    ULONGLONG cbUndoCommitment;
    LARGE_INTEGER llCreateTime;
    LARGE_INTEGER llAccessTime;
    LARGE_INTEGER llWriteTime;
    CLFS_LSN lsnOwnerPage;
    CLFS_LSN lsnArchiveTail;
    CLFS_LSN lsnBase;
    CLFS_LSN lsnLast;
    CLFS_LSN lsnRestart;
    CLFS_LSN lsnPhysicalBase;
    CLFS_LSN lsnUnused1;
    CLFS_LSN lsnUnused2;
    CLFS_LOG_STATE eState;
    union
    {
        HANDLE hSecurityContext;
        ULONGLONG ullAlignment;
    };
} CLFS_CLIENT_CONTEXT, *PCLFS_CLIENT_CONTEXT;
```
You should expect consistent nodes to always be of size `sizeof(CLFS_CLIENT_CONTEXT)` and of type `CLFS_NODE_TYPE_CLIENT_CONTEXT`.

Most of the other fields, such as the various *times* and *LSNs* are self-describing and related to actual CLFS operations being done on the log file. For the standard on-disk metadata client, these will usually all be zeroed out or set to `CLFS_INVALID_LSN`, with a few exceptions:

* `cbFlushTreshold` comes from the registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS\Parameters\` and `REG_DWORD` value `FlushThreshold` and is usually set to `40000`.
* `fAttributes` corresponds to the set of `FILE_ATTRIBUTE` flags associated with the Base Log File (such as `System` and `Hidden`).

In memory, the `hSecurityContext` field is the offset pointing to the shared security context for the client, since you may have noticed no array of shared security contexts exists in the base record header.


## Container Context

The second type of context stored in the base record is the *container context*, which is described by the `CLFS_CONTAINER_CONTEXT` structure shown below:
```
typedef struct _CLFS_CONTAINER_CONTEXT
{
    CLFS_NODE_ID cidNode;
    ULONGLONG cbContainer;
    CLFS_CONTAINER_ID cidContainer;
    CLFS_CONTAINER_ID cidQueue;
    union
    {
        CClfsContainer* pContainer;
        ULONGLONG ullAlignment;
    };
    CLFS_USN usnCurrent;
    CLFS_CONTAINER_STATE eState;
    ULONG cbPrevOffset;
    ULONG cbNextOffset;
} CLFS_CONTAINER_CONTEXT, *PCLFS_CONTAINER_CONTEXT;
```
You should expect consistent nodes to always be of size `sizeof(CLFS_CONTAINER_CONTEXT)` and of type `CLFS_NODE_TYPE_CONTAINER_CONTEXT`.

The first following field contains the 64-bit *size* of the container, followed by its *container identifier* (starting at 0). If the container is in a container queue, the next field will contain its identifier in the *queue*. Normally, these two numbers will be the same in the on-disk structures.

On disk, the next field should always be zeroed out, but in memory, it actually contains the kernel pointer to the `CClfsContainer` class describing the container at runtime. Just like other in-memory fields, the CLFS driver should take care not to ever write out this value (to avoid information leaks), as well as to never incorrectly use it off the disk (to avoid privilege escalation).

The `usnCurrent` field was introduced a bit earlier -- and corresponds to the USN for the container, which should be monotonically increasing based on the `cUsn` of the base record header.

The next field describes the *container state* and is actually documented on MSDN, as the public APIs allow querying this information, while the final two are never used. On disk, the container state will usually be `ClfsContainerInactive`.

## Shared Security Context
The final context structure in the base record is the *shared security context*, and should normally only ever be found in the in-memory representation, and never on disk.

It is described by the `CLFS_SHARED_SECURITY_CONTEXT` structure, shown below:
```
typedef struct _CLFS_SHARED_SECURITY_CONTEXT
{
    CLFS_NODE_ID cidNode;
    ULONG cRef;
    ULONG cRefActive;
    ULONG coffDescriptor;
    ULONG cbDescriptor;
    UCHAR rgbSecurityDescriptor[ANYSIZE_ARRAY];
} CLFS_SHARED_SECURITY_CONTEXT, *PCLFS_SHARED_SECURITY_CONTEXT;
```
You should expect consistent nodes to always be of size `sizeof(CLFS_SHARED_SECURITY_CONTEXT)` and of type `CLFS_NODE_TYPE_SHARED_SECURITY_CONTEXT`.

Two reference counts are used, one to store the number of callers using the shared context, while the other keeps track of the security descriptors associated with the shared context.

The `coffDescriptor` field points to the security descriptor bytes themselves, and should normally always be set to `offsetof(CLFS_SHARED_SECURITY_CONTEXT, rgbSecurityDescriptor);`

Finally, `cbDescriptor` stores the size of the security descriptor, and the final field corresponds to the byte data backing the  `SECURITY_DESCRIPTOR` structure itself.

## CLFS In-Memory Class
Once in memory, a CLFS Base Log File is represented by a `CClfsBaseFile` class, which can be further extended by a `CClfsBaseFilePersisted`. The definition for the former can be found in public symbols and is shown below:
```
struct _CClfsBaseFile
{
    ULONG m_cRef;
    PUCHAR m_pbImage;
    ULONG m_cbImage;
    PERESOURCE m_presImage;
    USHORT m_cBlocks;
    PCLFS_METADATA_BLOCK m_rgBlocks;
    PUSHORT m_rgcBlockReferences;
    CLFSHASHTBL m_symtblClient;
    CLFSHASHTBL m_symtblContainer;
    CLFSHASHTBL m_symtblSecurity;
    ULONGLONG m_cbContainer;
    ULONG m_cbRawSectorSize;
    BOOLEAN m_fGeneralBlockReferenced;
} CClfsBaseFile, *PCLFSBASEFILE;
```
These fields mainly represent data we've already seen earlier, such as the size of the container, the sector size, the array of metadata blocks and their number, as well as the size of the whole Base Log File and its location in kernel mode memory.

Additionally, the class is reference counted, and almost any access to any of its fields is protected by the `m_presImage` lock, which is an *executive resource* accessed in either shared or exclusive mode. 

Finally, each block itself is also referenced in the `m_rgcBlockReferences` array, noting there's a limit of `65535` references. A casual look at `AcquireMetadataBlock`, for example, shows no meaningful protection is done against overflow or underflow (although one would need to recursively cause acquisitions without releases). When the general block has been referenced at least once, the `m_fGeneralBlockReferenced` boolean is used to indicate the fact.

### In-memory Hash Table
You may note that in the in-memory class, the symbol hash tables are represented by this structure, shown below:
```
typedef struct _CLFSHASHTBL
{
    PULONGLONG rgSymHash;
    LONG cHashElt;
    CClfsBaseFile* pBaseFile;
} CLFSHASHTBL, *PCLFSHASHTBL;
```
This allows the offsets from the base record header to be stored as pointers in-memory, along with the bucket count and a pointer back to the `CClfsBaseFile`.
## Truncate Record
The *truncate record* is the last record type and is used during log truncation. The data structure (`CLFS_TRUNCATE_RECORD_HEADER`) is not present in the public symbols, but the `ValidateTruncateRecord`, `TruncateLogRewriteOwnerPages`, and `TruncateLogStart` functions can be used to infer the fields.

Its best guess definition is given below:
```
typedef struct _CLFS_TRUNCATE_RECORD_HEADER
{
    CLFS_METADATA_RECORD_HEADER hdrBaseRecord;
    ULONG coffClientChange;
    ULONG coffOwnerPage;
} CLFS_TRUNCATE_RECORD_HEADER, *PCLFS_TRUNCATE_RECORD_HEADER;
```
Apart from the usual header, the offset to the first `CLFS_TRUNCATE_CLIENT_CHANGE` structure is indicated, followed by the offset of the first owner page. Both of these are present in the scratch metadata block.

### Client Change Descriptor

The `CLFS_TRUNCATE_CLIENT_CHANGE` structure *is* defined in the symbols, and is shown below:

```
typedef struct _CLFS_TRUNCATE_CLIENT_CHANGE
{
    CLFS_CLIENT_ID cidClient;
    CLFS_LSN lsn;
    CLFS_LSN lsnClient;
    CLFS_LSN lsnRestart;
    USHORT cLength;
    USHORT cOldLength;
    ULONG cSectors;
    CLFS_SECTOR_CHANGE rgSectors[ANYSIZE_ARRAY];
} CLFS_TRUNCATE_CLIENT_CHANGE, *PCLFS_TRUNCATE_CLIENT_CHANGE;
```
This structure specifies which client identifier (stream identifier) is being modified, and the physical and virtual LSN of the replacement block. 

Once truncation is completed, the `lsnRestart` field will contain the LSN of the new restart area.

The next two fields host the size of the new replaced block, as well as the size of the old block.

Finally, for each sector subject to changes as part of truncation, an array of `cSectors` is present at the end of the structure (`rgSectors`), which is made up of `CLFS_SECTOR_CHANGE` structures.

#### Sector Change Descriptor
```
typedef struct _CLFS_SECTOR_CHANGE
{
    ULONG iSector;
    ULONG ulUnused;
    BYTE rgbSector[CLFS_SECTOR_SIZE];
} CLFS_SECTOR_CHANGE, *PCLFS_SECTOR_CHANGE;
```
Quite simply, these structures indicate the target sector index, and the new sector data to write.
