export type DOSHeaderType = {
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

export type FileHeaderType = {
  Machine: number;
  NumberOfSections: number;
  TimeDateStamp: number;
  PointerToSymbolTable: number;
  NumberOfSymbols: number;
  SizeOfOptionalHeader: number;
  Characteristics: number;
};

export type IMAGE_DATA_DIRECTORY = {
  VirtualAddress: number;
  Size: number;
};

export type OptionalHeaderType = {
  Magic: number;
  MajorLinkerVersion: number;
  MinorLinkerVersion: number;
  SizeOfCode: number;
  SizeOfInitializedData: number;
  SizeOfUninitializedData: number;
  AddressOfEntryPoint: number;
  BaseOfCode: number;
  BaseOfData?: number;
  ImageBase: BigInt | number;
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
  SizeOfStackReserve: BigInt | number;
  SizeOfStackCommit: BigInt | number;
  SizeOfHeapReserve: BigInt | number;
  SizeOfHeapCommit: BigInt | number;
  LoaderFlags: number;
  NumberOfRvaAndSizes: number;
  DataDirectory: IMAGE_DATA_DIRECTORY[];
};

export type NTHeadersType = {
  Signature: number;
  FileHeader: FileHeaderType;
  OptionalHeader: OptionalHeaderType;
};

export type IMAGE_SECTION_HEADER = {
  Name: string;
  VirtualSize: number;
  VirtualAddress: number;
  SizeOfRawData: number;
  PointerToRawData: number;
  PointerToRelocations: number;
  PointerToLinenumbers: number;
  NumberOfRelocations: number;
  NumberOfLinenumbers: number;
  Characteristics: number;
};

export type PEFile = {
  dos_header: DOSHeaderType;
  nt_headers: NTHeadersType;
  sections: IMAGE_SECTION_HEADER[];
};

export function Parse(file: Buffer): Promise<PEFile> {
  const e_lfanew = file.readUInt16LE(0x3c);
  const PE64 = 523 === file.readUint16LE(e_lfanew + 0x18);

  let directories: IMAGE_DATA_DIRECTORY[] = [];
  const directoryOffset = e_lfanew + (PE64 ? 0x88 : 0x78);
  for (let i = 0; i < 16; i++) {
    directories.push({
      VirtualAddress: file.readUint32LE(directoryOffset + i * 8),
      Size: file.readUint32LE(4 + directoryOffset + i * 8),
    });
  }

  const dos_header: DOSHeaderType = {
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
    e_res: [
      file.readUInt16LE(0x1c + 0 * 2),
      file.readUInt16LE(0x1c + 1 * 2),
      file.readUInt16LE(0x1c + 2 * 2),
      file.readUInt16LE(0x1c + 3 * 2),
    ],
    e_oemid: file.readUInt16LE(0x24),
    e_oeminfo: file.readUInt16LE(0x26),
    e_res2: [
      file.readUInt16LE(0x28 + 0 * 2),
      file.readUInt16LE(0x28 + 1 * 2),
      file.readUInt16LE(0x28 + 2 * 2),
      file.readUInt16LE(0x28 + 3 * 2),
      file.readUInt16LE(0x28 + 4 * 2),
      file.readUInt16LE(0x28 + 5 * 2),
      file.readUInt16LE(0x28 + 6 * 2),
      file.readUInt16LE(0x28 + 7 * 2),
      file.readUInt16LE(0x28 + 8 * 2),
      file.readUInt16LE(0x28 + 9 * 2),
    ],
    e_lfanew,
  };

  const nt_headers: NTHeadersType = {
    Signature: file.readUint32LE(e_lfanew),
    FileHeader: {
      Machine: file.readUint16LE(e_lfanew + 0x4),
      NumberOfSections: file.readUint16LE(e_lfanew + 0x6),
      TimeDateStamp: file.readUint32LE(e_lfanew + 0x8),
      PointerToSymbolTable: file.readUint32LE(e_lfanew + 0xc),
      NumberOfSymbols: file.readUint32LE(e_lfanew + 0x10),
      SizeOfOptionalHeader: file.readUint16LE(e_lfanew + 0x14),
      Characteristics: file.readUint16LE(e_lfanew + 0x16),
    },
    OptionalHeader: {
      Magic: file.readUint16LE(e_lfanew + 0x18),
      MajorLinkerVersion: file.readUint8(e_lfanew + 0x1a),
      MinorLinkerVersion: file.readUint8(e_lfanew + 0x1b),
      SizeOfCode: file.readUint32LE(e_lfanew + 0x1c),
      SizeOfInitializedData: file.readUint32LE(e_lfanew + 0x20),
      SizeOfUninitializedData: file.readUint32LE(e_lfanew + 0x24),
      AddressOfEntryPoint: file.readUint32LE(e_lfanew + 0x28),
      BaseOfCode: file.readUint32LE(e_lfanew + 0x2c),
      BaseOfData: PE64 ? null : file.readUint32LE(e_lfanew + 0x30),
      ImageBase: PE64
        ? file.readBigUInt64LE(e_lfanew + 0x30)
        : file.readUint32LE(e_lfanew + 0x34),
      SectionAlignment: file.readUint32LE(e_lfanew + 0x38),
      FileAlignment: file.readUint32LE(e_lfanew + 0x3c),
      MajorOperatingSystemVersion: file.readUint16LE(e_lfanew + 0x40),
      MinorOperatingSystemVersion: file.readUint16LE(e_lfanew + 0x42),
      MajorImageVersion: file.readUint16LE(e_lfanew + 0x44),
      MinorImageVersion: file.readUint16LE(e_lfanew + 0x46),
      MajorSubsystemVersion: file.readUint16LE(e_lfanew + 0x48),
      MinorSubsystemVersion: file.readUint16LE(e_lfanew + 0x4a),
      Win32VersionValue: file.readUint32LE(e_lfanew + 0x4c),
      SizeOfImage: file.readUint32LE(e_lfanew + 0x50),
      SizeOfHeaders: file.readUint32LE(e_lfanew + 0x54),
      CheckSum: file.readUint32LE(e_lfanew + 0x58),
      Subsystem: file.readUint16LE(e_lfanew + 0x5c),
      DllCharacteristics: file.readUint16LE(e_lfanew + 0x5e),
      SizeOfStackReserve: PE64
        ? file.readBigUInt64LE(e_lfanew + 0x60)
        : file.readUint32LE(e_lfanew + 0x60),
      SizeOfStackCommit: PE64
        ? file.readBigUInt64LE(e_lfanew + 0x68)
        : file.readUint32LE(e_lfanew + 0x64),
      SizeOfHeapReserve: PE64
        ? file.readBigUInt64LE(e_lfanew + 0x70)
        : file.readUint32LE(e_lfanew + 0x68),
      SizeOfHeapCommit: PE64
        ? file.readBigUInt64LE(e_lfanew + 0x78)
        : file.readUint32LE(e_lfanew + 0x6c),
      LoaderFlags: file.readUint32LE(e_lfanew + (PE64 ? 0x80 : 0x70)),
      NumberOfRvaAndSizes: file.readUint32LE(e_lfanew + (PE64 ? 0x84 : 0x74)),
      DataDirectory: directories,
    },
  };

  const sections: IMAGE_SECTION_HEADER[] = [];
  const sectionsOffset =
    nt_headers.FileHeader.SizeOfOptionalHeader + e_lfanew + 0x18;

  for (let i: number = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
    const offs = sectionsOffset + i * 0x28;
    sections.push({
      Name: file
        .slice(offs, offs + 8)
        .toString()
        .replace(/\0/g, ""),
      VirtualSize: file.readUint32LE(offs + 8),
      VirtualAddress: file.readUint32LE(offs + 12),
      SizeOfRawData: file.readUint32LE(offs + 16),
      PointerToRawData: file.readUint32LE(offs + 20),
      PointerToRelocations: file.readUint32LE(offs + 24),
      PointerToLinenumbers: file.readUint32LE(offs + 28),
      NumberOfRelocations: file.readUint16LE(offs + 32),
      NumberOfLinenumbers: file.readUint16LE(offs + 34),
      Characteristics: file.readUint32LE(offs + 36),
    });
  }

  return new Promise((resolve, reject) => {
    resolve({
      dos_header,
      nt_headers,
      sections,
    });
  });
}
