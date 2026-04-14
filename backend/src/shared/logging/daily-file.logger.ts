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
    const contextPart = context ? ` [${context}]` : "";
    const extraPart =
      params.extra.length > 0
        ? ` ${params.extra.map(formatValue).join(" ")}`
        : "";
    const stackPart = params.stack ? `\n${params.stack}` : "";

    return `${now.toISOString()} ${level.toUpperCase()}${contextPart} ${formatValue(
      message,
    )}${extraPart}${stackPart}\n`;
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

    return this.enabledLogLevels.has(level);
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

export function formatLocalDate(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}

function formatValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  if (value instanceof Error) {
    return value.stack ?? value.message;
  }

  return inspect(value, {
    depth: 8,
    breakLength: Number.POSITIVE_INFINITY,
    compact: true,
  });
}

function looksLikeStackTrace(value: string): boolean {
  return (
    value.includes("\n") ||
    /^\s*at\s+/u.test(value) ||
    /^[A-Za-z]*Error:/u.test(value)
  );
}
