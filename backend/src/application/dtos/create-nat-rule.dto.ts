export class CreateNatRuleDto {
  type: string;
  isActive: boolean;
  sourceIp: string | null;
  destinationIp: string | null;
  sourcePort: number | null;
  destinationPort: number | null;
  translatedIp: string | null;
  translatedPort: number | null;
  priority: number;
  accessToken: string;
}
