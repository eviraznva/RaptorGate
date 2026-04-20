export interface Rule {
  id: string;
  name: string;
  priority: number;
  content: string;
  description: string;
  isActive: boolean;
  zonePairId: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}
