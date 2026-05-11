import type { NatProtocol } from "../../infrastructure/grpc/generated/common/common.js";

export type CreateNatRuleActionDto =
  | {
      $case: "snat";
      snat: {
        srcCidr: string;
        translatedIp: string;
        srcPortMin?: number | null;
        srcPortMax?: number | null;
      };
    }
  | {
      $case: "dnat";
      dnat: {
        dstCidr: string;
        translatedIp: string;
        translatedPort?: number | null;
      };
    }
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

export class CreateNatRuleDto {
  isActive: boolean;
  priority: number;
  protocol: NatProtocol;
  inInterface?: string | null;
  outInterface?: string | null;
  inZone?: string | null;
  outZone?: string | null;
  matchSrcPortMin?: number | null;
  matchSrcPortMax?: number | null;
  matchDstPortMin?: number | null;
  matchDstPortMax?: number | null;
  action: CreateNatRuleActionDto;
  accessToken: string;
}
