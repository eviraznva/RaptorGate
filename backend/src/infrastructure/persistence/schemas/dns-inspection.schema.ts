import { z } from "zod";
import { IpAddress } from "../../../domain/value-objects/ip-address.vo.js";

const ipOrEmptySchema = z
  .string()
  .refine((value) => value === "" || IpAddress.isValid(value), {
    message: "Invalid IP address",
  });

const ipRequiredSchema = z
  .string()
  .refine((value) => IpAddress.isValid(value), {
    message: "Invalid IP address",
  });

const resolverEndpointSchema = z
  .object({
    address: z.string(),
    port: z.number().int().min(1).max(65535),
  })
  .strict();

export const DnsInspectionRecordSchema = z
  .object({
    general: z
      .object({
        enabled: z.boolean(),
      })
      .strict(),
    blocklist: z
      .object({
        enabled: z.boolean(),
        domains: z.array(z.string()),
      })
      .strict(),
    dnsTunneling: z
      .object({
        enabled: z.boolean(),
        maxLabelLength: z.number().int().min(0),
        entropyThreshold: z.number().min(0),
        windowSeconds: z.number().int().min(0),
        maxQueriesPerDomain: z.number().int().min(0),
        maxUniqueSubdomains: z.number().int().min(0),
        ignoreDomains: z.array(z.string()),
        alertThreshold: z.number().min(0).max(1),
        blockThreshold: z.number().min(0).max(1),
      })
      .strict(),
    dnssec: z
      .object({
        enabled: z.boolean(),
        maxLookupsPerPacket: z.number().int().min(0),
        defaultOnResolverFailure: z.enum(["allow", "alert", "block"]),
        resolver: z
          .object({
            primary: resolverEndpointSchema
              .extend({
                address: ipRequiredSchema,
              })
              .strict(),
            secondary: resolverEndpointSchema
              .extend({
                address: ipOrEmptySchema,
              })
              .strict(),
            transport: z.enum(["udp", "tcp", "udpWithTcpFallback"]),
            timeoutMs: z.number().int().min(0),
            retries: z.number().int().min(0),
          })
          .strict(),
        cache: z
          .object({
            enabled: z.boolean(),
            maxEntries: z.number().int().min(0),
            ttlSeconds: z
              .object({
                secure: z.number().int().min(0),
                insecure: z.number().int().min(0),
                bogus: z.number().int().min(0),
                failure: z.number().int().min(0),
              })
              .strict(),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

export type DnsInspectionRecord = z.infer<typeof DnsInspectionRecordSchema>;

export const defaultDnsInspectionRecord: DnsInspectionRecord = {
  general: { enabled: false },
  blocklist: { enabled: false, domains: [] },
  dnsTunneling: {
    enabled: false,
    maxLabelLength: 40,
    entropyThreshold: 3.5,
    windowSeconds: 60,
    maxQueriesPerDomain: 100,
    maxUniqueSubdomains: 20,
    ignoreDomains: [],
    alertThreshold: 0.6,
    blockThreshold: 0.85,
  },
  dnssec: {
    enabled: false,
    maxLookupsPerPacket: 1,
    defaultOnResolverFailure: "allow",
    resolver: {
      primary: { address: "127.0.0.1", port: 53 },
      secondary: { address: "", port: 53 },
      transport: "udpWithTcpFallback",
      timeoutMs: 2000,
      retries: 1,
    },
    cache: {
      enabled: true,
      maxEntries: 4096,
      ttlSeconds: {
        secure: 300,
        insecure: 300,
        bogus: 60,
        failure: 15,
      },
    },
  },
};
