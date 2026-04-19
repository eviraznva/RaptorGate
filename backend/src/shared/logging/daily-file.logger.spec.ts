import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DailyFileLogger, formatLocalDate } from "./daily-file.logger.js";

describe("DailyFileLogger", () => {
  let logDir: string;

  beforeEach(() => {
    logDir = mkdtempSync(join(tmpdir(), "raptorgate-backend-logs-"));
  });

  afterEach(() => {
    rmSync(logDir, { recursive: true, force: true });
  });

  it("writes logs to a file named with the local calendar date", () => {
    const logger = new DailyFileLogger({
      logDir,
      context: "TestContext",
      mirrorToConsole: false,
      now: () => new Date(Date.UTC(2026, 3, 14, 10, 30, 0)),
    });

    logger.log("backend started");

    const logPath = join(logDir, "2026-04-14.log");
    const record = JSON.parse(readFileSync(logPath, "utf8"));

    expect(existsSync(logPath)).toBe(true);
    expect(record).toMatchObject({
      context: "TestContext",
      level: "info",
      message: "backend started",
      service: "backend",
      timestamp: "2026-04-14T10:30:00.000Z",
    });
  });

  it("uses a new file after the local date changes", () => {
    let now = new Date(2026, 3, 14, 23, 59, 59);
    const logger = new DailyFileLogger({
      logDir,
      mirrorToConsole: false,
      now: () => now,
    });

    logger.warn("before midnight", "Scheduler");
    now = new Date(2026, 3, 15, 0, 0, 1);
    logger.warn("after midnight", "Scheduler");

    expect(readFileSync(join(logDir, "2026-04-14.log"), "utf8")).toContain(
      "before midnight",
    );
    expect(readFileSync(join(logDir, "2026-04-15.log"), "utf8")).toContain(
      "after midnight",
    );
  });

  it("formats local dates without using utc conversion", () => {
    expect(formatLocalDate(new Date(2026, 0, 5, 1, 2, 3))).toBe("2026-01-05");
  });

  it("writes structured metadata and redacts secrets", () => {
    const logger = new DailyFileLogger({
      logDir,
      mirrorToConsole: false,
      now: () => new Date(Date.UTC(2026, 3, 14, 10, 30, 0)),
    });

    logger.log({
      event: "auth.login.succeeded",
      message: "user logged in",
      refreshToken: "secret-refresh-token",
      userId: "user-1",
    });

    const record = JSON.parse(
      readFileSync(join(logDir, "2026-04-14.log"), "utf8"),
    );

    expect(record.event).toBe("auth.login.succeeded");
    expect(record.metadata.userId).toBe("user-1");
    expect(record.metadata.refreshToken).toBe("[REDACTED]");
  });
});
