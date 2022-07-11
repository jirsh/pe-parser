import { readFileSync } from "fs";
import { join } from "path";
import { Parse } from "./parser";

test("parse x86", async () => {
  const file = readFileSync(join("testbin", "x86", "testbin.exe"));
  const parsed = await Parse(file);
  expect(parsed.sections[0].Name).toBe(".text");
});

test("parse x64", async () => {
  const file = readFileSync(join("testbin", "x64", "testbin.exe"));
  const parsed = await Parse(file);
  expect(parsed.sections[0].Name).toBe(".text");
});
