import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { inspect } from "node:util";
import type { LoggerService, LogLevel } from "@nestjs/common";

export const DEFAULT_BACKEND_LOG_DIR = "/var/log/raptorgate/backend";

interface DailyFileLoggerOptions {
  logDir: string;
  context?: string;
  mirrorToConsole?: boolean;
  now?: () => Date;
}

type DailyFileLogLevel = LogLevel | "fatal";

interface ParsedLogParams {
  context?: string;
  extra: unknown[];
  stack?: string;
}

interface NormalizedLogMessage {
  event?: string;
  error?: string;
  message: string;
  metadata?: unknown;
  stack?: string;
}

export class DailyFileLogger implements LoggerService {
  private readonly logDir: string;
  private readonly context?: string;
  private readonly mirrorToConsole: boolean;
  private readonly now: () => Date;
  private enabledLogLevels?: Set<string>;

  constructor(options: DailyFileLoggerOptions) {
    this.logDir = options.logDir;
    this.context = options.context;
    this.mirrorToConsole = options.mirrorToConsole ?? true;
    this.now = options.now ?? (() => new Date());

    mkdirSync(this.logDir, { recursive: true });
  }

  withContext(context: string): DailyFileLogger {
    return new DailyFileLogger({
      logDir: this.logDir,
      context,
      mirrorToConsole: this.mirrorToConsole,
      now: this.now,
    });
  }

  log(message: unknown, ...optionalParams: unknown[]) {
    this.write("log", message, this.parseDefaultParams(optionalParams));
  }

  error(message: unknown, ...optionalParams: unknown[]) {
    this.write("error", message, this.parseErrorParams(optionalParams));
  }

  warn(message: unknown, ...optionalParams: unknown[]) {
    this.write("warn", message, this.parseDefaultParams(optionalParams));
  }

  debug(message: unknown, ...optionalParams: unknown[]) {
    this.write("debug", message, this.parseDefaultParams(optionalParams));
  }

  verbose(message: unknown, ...optionalParams: unknown[]) {
    this.write("verbose", message, this.parseDefaultParams(optionalParams));
  }

  fatal(message: unknown, ...optionalParams: unknown[]) {
    this.write("fatal", message, this.parseErrorParams(optionalParams));
  }

  setLogLevels(levels: LogLevel[]) {
    this.enabledLogLevels = new Set(levels);
  }

  private write(
    level: DailyFileLogLevel,
    message: unknown,
    params: ParsedLogParams,
  ) {
    if (!this.isLevelEnabled(level)) {
      return;
    }

    const now = this.now();
    const logPath = join(this.logDir, `${formatLocalDate(now)}.log`);
    const line = this.formatLine(now, level, message, params);

    mkdirSync(this.logDir, { recursive: true });
    appendFileSync(logPath, line, { encoding: "utf8", mode: 0o640 });

    if (this.mirrorToConsole) {
      this.writeConsole(level, line);
    }
  }

  private formatLine(
    now: Date,
    level: DailyFileLogLevel,
    message: unknown,
    params: ParsedLogParams,
  ): string {
    const context = params.context ?? this.context;
    const normalized = normalizeMessage(message);
    const metadata = mergeMetadata(normalized.metadata, params.extra);
    const record = compactRecord({
      timestamp: now.toISOString(),
      level: normalizeLevel(level),
      service: "backend",
      context,
      event: normalized.event,
      message: normalized.message,
      metadata,
      error: normalized.error,
      stack: normalized.stack ?? params.stack,
    });

    return `${JSON.stringify(redact(record))}\n`;
  }

  private writeConsole(level: DailyFileLogLevel, line: string) {
    const stream =
      level === "error" || level === "fatal" || level === "warn"
        ? process.stderr
        : process.stdout;

    stream.write(line);
  }

  private isLevelEnabled(level: DailyFileLogLevel): boolean {
    if (!this.enabledLogLevels) {
      return true;
    }

    return (
      this.enabledLogLevels.has(level) ||
      this.enabledLogLevels.has(normalizeLevel(level))
    );
  }

  private parseDefaultParams(optionalParams: unknown[]): ParsedLogParams {
    if (optionalParams.length === 0) {
      return { context: this.context, extra: [] };
    }

    const contextCandidate = optionalParams[optionalParams.length - 1];

    if (typeof contextCandidate === "string") {
      return {
        context: contextCandidate,
        extra: optionalParams.slice(0, -1),
      };
    }

    return {
      context: this.context,
      extra: optionalParams,
    };
  }

  private parseErrorParams(optionalParams: unknown[]): ParsedLogParams {
    const [traceCandidate, contextCandidate, ...extra] = optionalParams;

    if (typeof contextCandidate === "string") {
      return {
        context: contextCandidate,
        stack: typeof traceCandidate === "string" ? traceCandidate : undefined,
        extra,
      };
    }

    if (
      typeof traceCandidate === "string" &&
      looksLikeStackTrace(traceCandidate)
    ) {
      return {
        context: this.context,
        stack: traceCandidate,
        extra: optionalParams.slice(1),
      };
    }

    if (typeof traceCandidate === "string") {
      return {
        context: traceCandidate,
        extra: optionalParams.slice(1),
      };
    }

    return {
      context: this.context,
      extra: optionalParams,
    };
  }
}

function normalizeLevel(level: DailyFileLogLevel): string {
  return level === "log" ? "info" : level;
}

export function formatLocalDate(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}

function normalizeMessage(value: unknown): NormalizedLogMessage {
  if (value instanceof Error) {
    return {
      error: value.name,
      message: value.message,
      stack: value.stack,
    };
  }

  if (typeof value === "string") {
    return { message: value };
  }

  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    const metadata = { ...record };
    const message =
      typeof record.message === "string"
        ? record.message
        : inspect(redact(record), {
            depth: 8,
            breakLength: Number.POSITIVE_INFINITY,
            compact: true,
          });
    const error = normalizeError(record.error);

    delete metadata.message;
    delete metadata.event;
    delete metadata.error;
    delete metadata.stack;

    return {
      event: typeof record.event === "string" ? record.event : undefined,
      error: error.error,
      message,
      metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
      stack: typeof record.stack === "string" ? record.stack : error.stack,
    };
  }

  return { message: inspect(value, { depth: 8, compact: true }) };
}

function normalizeError(value: unknown): { error?: string; stack?: string } {
  if (value instanceof Error) {
    return { error: value.name, stack: value.stack };
  }

  if (typeof value === "string") {
    return { error: value };
  }

  return {};
}

function mergeMetadata(metadata: unknown, extra: unknown[]): unknown {
  if (extra.length === 0) {
    return metadata;
  }

  return {
    ...(metadata && typeof metadata === "object" && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)
      : metadata === undefined
        ? {}
        : { value: metadata }),
    extra,
  };
}

function compactRecord(record: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(record).filter(([, value]) => value !== undefined),
  );
}

function redact(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack,
    };
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "bigint") {
    return value.toString();
  }

  if (typeof value !== "object") {
    return value;
  }

  if (seen.has(value)) {
    return "[Circular]";
  }

  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redact(item, seen));
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      isSecretKey(key) ? "[REDACTED]" : redact(item, seen),
    ]),
  );
}

function isSecretKey(key: string): boolean {
  return /password|authorization|cookie|secret|token|privateKey|certificatePem/iu.test(
    key,
  );
}

function looksLikeStackTrace(value: string): boolean {
  return (
    value.includes("\n") ||
    /^\s*at\s+/u.test(value) ||
    /^[A-Za-z]*Error:/u.test(value)
  );
}
