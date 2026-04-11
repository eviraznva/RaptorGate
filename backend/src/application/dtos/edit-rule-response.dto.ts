export class EditRuleResponseDto {
  id: string;
  name: string;
  description: string | null;
  zonePairId: string;
  isActive: boolean;
  content: string;
  priority: number;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}
