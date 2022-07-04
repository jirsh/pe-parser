import { readFileSync } from "fs";
import { join } from "path";
import { Validate } from "./validate";
import { Parse } from "./parser";

test("validate function x86", async () => {
    const file = readFileSync(join("testbin", "x86", "testbin.exe"));
    const { architecture } = await Validate(file);
    expect(architecture).toBe("x86");
});

test("validate function x64", async () => {
    const file = readFileSync(join("testbin", "x64", "testbin.exe"));
    const { architecture } = await Validate(file);
    expect(architecture).toBe("x64");
});

test("parse x86", async () => {
    const file = readFileSync(join("testbin", "x86", "testbin.exe"));
    const parsed = await Parse(file);
});

test("parse x64", async () => {
    const file = readFileSync(join("testbin", "x64", "testbin.exe"));
    const parsed = await Parse(file);
});
