export type NatActionKind = "snat" | "dnat" | "pat" | "masquerade";
export type NatType = "SNAT" | "DNAT" | "PAT" | "MASQUERADE";

export type NatProtocolName =
  | "NAT_PROTOCOL_ALL"
  | "NAT_PROTOCOL_TCP"
  | "NAT_PROTOCOL_UDP"
  | "NAT_PROTOCOL_ICMP";

export type NatProtocolCode = 0 | 1 | 2 | 3 | -1;
export type NatProtocol = NatProtocolName | NatProtocolCode;

export type NatRuleAction =
  | {
      $case: "snat";
      snat: {
        srcCidr: string;
        translatedIp: string;
        srcPortMin?: number | null;
        srcPortMax?: number | null;
      };
    }
  | { $case: "dnat"; dnat: { dstCidr: string; translatedIp: string } }
  | {
      $case: "pat";
      pat: {
        dstIp: string;
        dstPort: number;
        translatedIp: string;
        translatedPort: number;
      };
    }
  | {
      $case: "masquerade";
      masquerade: {
        srcCidr?: string | null;
        srcPortMin?: number | null;
        srcPortMax?: number | null;
      };
    };

export interface NatRule {
  id: string;
  isActive: boolean;
  priority: number;
  protocol: NatProtocol;
  inInterface: string | null;
  outInterface: string | null;
  inZone: string | null;
  outZone: string | null;
  matchSrcPortMin: number | null;
  matchSrcPortMax: number | null;
  matchDstPortMin: number | null;
  matchDstPortMax: number | null;
  action: NatRuleAction;
  createdAt: string;
  updatedAt: string;
}

export type NatRuleUpsertBody = {
  isActive: boolean;
  priority: number;
  protocol: NatProtocolName;
  inInterface?: string | null;
  outInterface?: string | null;
  inZone?: string | null;
  outZone?: string | null;
  matchSrcPortMin?: number | null;
  matchSrcPortMax?: number | null;
  matchDstPortMin?: number | null;
  matchDstPortMax?: number | null;
  action: NatRuleAction;
};

export function getNatRuleType(rule: NatRule): NatType {
  return actionKindToType(rule.action.$case);
}

export function actionKindToType(kind: NatActionKind): NatType {
  switch (kind) {
    case "snat":
      return "SNAT";
    case "dnat":
      return "DNAT";
    case "pat":
      return "PAT";
    case "masquerade":
      return "MASQUERADE";
  }
}

export function typeToActionKind(type: NatType): NatActionKind {
  switch (type) {
    case "SNAT":
      return "snat";
    case "DNAT":
      return "dnat";
    case "PAT":
      return "pat";
    case "MASQUERADE":
      return "masquerade";
  }
}

export function protocolLabel(protocol: NatProtocol): string {
  switch (protocol) {
    case 0:
    case "NAT_PROTOCOL_ALL":
      return "ALL";
    case 1:
    case "NAT_PROTOCOL_TCP":
      return "TCP";
    case 2:
    case "NAT_PROTOCOL_UDP":
      return "UDP";
    case 3:
    case "NAT_PROTOCOL_ICMP":
      return "ICMP";
    default:
      return "UNKNOWN";
  }
}
