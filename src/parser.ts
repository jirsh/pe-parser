type DOSHeaderType = {
  e_magic: number; // Magic number
  e_cblp: number; // Bytes on last page of file
  e_cp: number; // Pages in file
  e_crlc: number; // Relocations
  e_cparhdr: number; // Size of header in paragraphs
  e_minalloc: number; // Minimum extra paragraphs needed
  e_maxalloc: number; // Maximum extra paragraphs needed
  e_ss: number; // Initial (relative) SS value
  e_sp: number; // Initial SP value
  e_csum: number; // Checksum
  e_ip: number; // Initial IP value
  e_cs: number; // Initial (relative) CS value
  e_lfarlc: number; // File address of relocation table
  e_ovno: number; // Overlay number
  e_res: number[]; // Reserved words
  e_oemid: number; // OEM identifier (for e_oeminfo)
  e_oeminfo: number; // OEM information; e_oemid specific
  e_res2: number[]; // Reserved words
  e_lfanew: number; // File address of new exe header
};

type FileHeaderType = {
  Machine: number;
  NumberOfSections: number;
  TimeDateStamp: number;
  PointerToSymbolTable: number;
  NumberOfSymbols: number;
  SizeOfOptionalHeader: number;
  Characteristics: number;
};

type IMAGE_DATA_DIRECTORY = {
  VirtualAddress: number;
  Size: number;
};

type OptionalHeaderType = {
  Magic: number;
  MajorLinkerVersion: number;
  MinorLinkerVersion: number;
  SizeOfCode: number;
  SizeOfInitializedData: number;
  SizeOfUninitializedData: number;
  AddressOfEntryPoint: number;
  BaseOfCode: number;
  ImageBase: BigInt;
  SectionAlignment: number;
  FileAlignment: number;
  MajorOperatingSystemVersion: number;
  MinorOperatingSystemVersion: number;
  MajorImageVersion: number;
  MinorImageVersion: number;
  MajorSubsystemVersion: number;
  MinorSubsystemVersion: number;
  Win32VersionValue: number;
  SizeOfImage: number;
  SizeOfHeaders: number;
  CheckSum: number;
  Subsystem: number;
  DllCharacteristics: number;
  SizeOfStackReserve: BigInt;
  SizeOfStackCommit: BigInt;
  SizeOfHeapReserve: BigInt;
  SizeOfHeapCommit: BigInt;
  LoaderFlags: number;
  NumberOfRvaAndSizes: number;
  DataDirectory: IMAGE_DATA_DIRECTORY[];
};

type NTHeadersType = {
  Signature: number;
  FileHeader?: FileHeaderType;
  OptionalHeader?: OptionalHeaderType;
};

type PEFile = {
  dos_header: DOSHeaderType;
  nt_headers: NTHeadersType;
};

export function Parse(file: Buffer): Promise<PEFile> {
  return new Promise((resolve, reject) => {
    let pefile: PEFile = {
      dos_header: {
        e_magic: file.readUInt16LE(0x0),
        e_cblp: file.readUInt16LE(0x2),
        e_cp: file.readUInt16LE(0x4),
        e_crlc: file.readUInt16LE(0x6),
        e_cparhdr: file.readUInt16LE(0x8),
        e_minalloc: file.readUInt16LE(0xa),
        e_maxalloc: file.readUInt16LE(0xc),
        e_ss: file.readUInt16LE(0xe),
        e_sp: file.readUInt16LE(0x10),
        e_csum: file.readUInt16LE(0x12),
        e_ip: file.readUInt16LE(0x14),
        e_cs: file.readUInt16LE(0x16),
        e_lfarlc: file.readUInt16LE(0x18),
        e_ovno: file.readUInt16LE(0x1a),
        e_res: [file.readUInt16LE(0x1c + 0 * 2), file.readUInt16LE(0x1c + 1 * 2), file.readUInt16LE(0x1c + 2 * 2), file.readUInt16LE(0x1c + 3 * 2)],
        e_oemid: file.readUInt16LE(0x24),
        e_oeminfo: file.readUInt16LE(0x26),
        e_res2: [file.readUInt16LE(0x28 + 0 * 2), file.readUInt16LE(0x28 + 1 * 2), file.readUInt16LE(0x28 + 2 * 2), file.readUInt16LE(0x28 + 3 * 2), file.readUInt16LE(0x28 + 4 * 2), file.readUInt16LE(0x28 + 5 * 2), file.readUInt16LE(0x28 + 6 * 2), file.readUInt16LE(0x28 + 7 * 2), file.readUInt16LE(0x28 + 8 * 2), file.readUInt16LE(0x28 + 9 * 2)],
        e_lfanew: file.readUInt16LE(0x3c)
      },
      nt_headers: {
        Signature: 0,
      }
    };

    resolve(pefile);
  });
}
