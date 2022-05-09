type ValidateReturn = {
  architecture: "x64" | "x86";
};

const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_IA64 = 0x0200;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;

export function Validate(file: Buffer): Promise<ValidateReturn> {
  return new Promise((resolve, reject) => {
    if (file.length < 97)
      // http://www.phreedom.org/research/tinype
      return reject("File too small");

    if (0x5a4d !== file.readInt16LE(0))
      // Check if the magic value in the DOS header is 'MZ'
      return reject("Invalid DOS header");

    const e_lfanew = file.readInt32LE(0x3c); // New header pointer
    if (0x4550 !== file.readInt32LE(e_lfanew))
      // Check if the new header signature is 'PE\0\0'
      return reject("Invalid PE header");

    const machine = file.readUint16LE(e_lfanew + 4);
    if (
      machine !== IMAGE_FILE_MACHINE_I386 &&
      machine !== IMAGE_FILE_MACHINE_AMD64
    )
      // Check if this is a header we're familiar with
      return reject("PE file not parsable");

    resolve({
      architecture: machine === IMAGE_FILE_MACHINE_I386 ? "x86" : "x64",
    });
  });
}
