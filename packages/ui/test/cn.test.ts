import { describe, expect, test } from "bun:test";
import { cn } from "../src/cn";

describe("cn", () => {
  test("merges conditional and conflicting utility classes", () => {
    expect(cn("px-2 text-sm", false, "px-4")).toBe("text-sm px-4");
  });
});
