export type NatType = "SNAT" | "DNAT" | "PAT";

export interface NatRule {
  id: string;
  type: NatType;
  isActive: boolean;
  sourceIp: string | null;
  sourcePort: number | null;
  destinationIp: string | null;
  destinationPort: number | null;
  translatedIp: string | null;
  translatedPort: number | null;
  priority: number;
  createdAt: string;
  updatedAt: string;
}
