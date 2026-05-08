import { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';
import { NatConfigIsInvalidException } from '../exceptions/nat-config-is-invalid.exception.js';
import { Port } from '../value-objects/port.vo.js';
import { Priority } from '../value-objects/priority.vo.js';

export interface SnatRuleAction {
  srcCidr: string;
  translatedIp: string;
  srcPortMin?: Port;
  srcPortMax?: Port;
}

export interface DnatRuleAction {
  dstCidr: string;
  translatedIp: string;
}

export interface PatRuleAction {
  dstIp: string;
  dstPort: Port;
  translatedIp: string;
  translatedPort: Port;
}

export interface MasqueradeRuleAction {
  srcCidr?: string;
  srcPortMin?: Port;
  srcPortMax?: Port;
}

export type NatRuleAction =
  | { $case: 'snat'; snat: SnatRuleAction }
  | { $case: 'dnat'; dnat: DnatRuleAction }
  | { $case: 'pat'; pat: PatRuleAction }
  | { $case: 'masquerade'; masquerade: MasqueradeRuleAction };

export interface NatRuleBaseProps {
  id: string;
  isActive: boolean;
  priority: Priority;
  protocol: NatProtocol;
  inInterface?: string | null;
  outInterface?: string | null;
  inZone?: string | null;
  outZone?: string | null;
  matchSrcPortMin?: Port | null;
  matchSrcPortMax?: Port | null;
  matchDstPortMin?: Port | null;
  matchDstPortMax?: Port | null;
  createdAt: Date;
  updatedAt: Date;
}

export class NatRule {
  private constructor(
    private readonly id: string,
    private isActive: boolean,
    private priority: Priority,
    private protocol: NatProtocol,
    private inInterface: string | null,
    private outInterface: string | null,
    private inZone: string | null,
    private outZone: string | null,
    private matchSrcPortMin: Port | null,
    private matchSrcPortMax: Port | null,
    private matchDstPortMin: Port | null,
    private matchDstPortMax: Port | null,
    private action: NatRuleAction,
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static createSnatRule(
    props: NatRuleBaseProps & {
      snat: {
        srcCidr: string;
        translatedIp: string;
        srcPortMin?: number | null;
        srcPortMax?: number | null;
      };
    },
  ): NatRule {
    return this.createWithAction(props, {
      $case: 'snat',
      snat: {
        srcCidr: props.snat.srcCidr,
        translatedIp: props.snat.translatedIp,
        srcPortMin:
          props.snat.srcPortMin != null
            ? Port.create(props.snat.srcPortMin)
            : undefined,
        srcPortMax:
          props.snat.srcPortMax != null
            ? Port.create(props.snat.srcPortMax)
            : undefined,
      },
    });
  }

  public static createDnatRule(
    props: NatRuleBaseProps & {
      dnat: { dstCidr: string; translatedIp: string };
    },
  ): NatRule {
    return this.createWithAction(props, {
      $case: 'dnat',
      dnat: props.dnat,
    });
  }

  public static createPatRule(
    props: NatRuleBaseProps & {
      pat: {
        dstIp: string;
        dstPort: number;
        translatedIp: string;
        translatedPort: number;
      };
    },
  ): NatRule {
    return this.createWithAction(props, {
      $case: 'pat',
      pat: {
        dstIp: props.pat.dstIp,
        dstPort: Port.create(props.pat.dstPort),
        translatedIp: props.pat.translatedIp,
        translatedPort: Port.create(props.pat.translatedPort),
      },
    });
  }

  public static createMasqueradeRule(
    props: NatRuleBaseProps & {
      masquerade: {
        srcCidr?: string | null;
        srcPortMin?: number | null;
        srcPortMax?: number | null;
      };
    },
  ): NatRule {
    return this.createWithAction(props, {
      $case: 'masquerade',
      masquerade: {
        srcCidr: props.masquerade.srcCidr ?? undefined,
        srcPortMin:
          props.masquerade.srcPortMin != null
            ? Port.create(props.masquerade.srcPortMin)
            : undefined,
        srcPortMax:
          props.masquerade.srcPortMax != null
            ? Port.create(props.masquerade.srcPortMax)
            : undefined,
      },
    });
  }

  public static createWithAction(
    props: NatRuleBaseProps,
    action: NatRuleAction,
  ): NatRule {
    const rule = new NatRule(
      props.id,
      props.isActive,
      props.priority,
      props.protocol,
      props.inInterface ?? null,
      props.outInterface ?? null,
      props.inZone ?? null,
      props.outZone ?? null,
      props.matchSrcPortMin ?? null,
      props.matchSrcPortMax ?? null,
      props.matchDstPortMin ?? null,
      props.matchDstPortMax ?? null,
      action,
      props.createdAt,
      props.updatedAt,
    );

    rule.validate();

    return rule;
  }

  public getId(): string {
    return this.id;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getPriority(): Priority {
    return this.priority;
  }

  public getProtocol(): NatProtocol {
    return this.protocol;
  }

  public getInInterface(): string | null {
    return this.inInterface;
  }

  public getOutInterface(): string | null {
    return this.outInterface;
  }

  public getInZone(): string | null {
    return this.inZone;
  }

  public getOutZone(): string | null {
    return this.outZone;
  }

  public getMatchSrcPortMin(): Port | null {
    return this.matchSrcPortMin;
  }

  public getMatchSrcPortMax(): Port | null {
    return this.matchSrcPortMax;
  }

  public getMatchDstPortMin(): Port | null {
    return this.matchDstPortMin;
  }

  public getMatchDstPortMax(): Port | null {
    return this.matchDstPortMax;
  }

  public getAction(): NatRuleAction {
    return this.action;
  }

  public getActionKind(): NatRuleAction['$case'] {
    return this.action.$case;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public setIsActive(isActive: boolean): void {
    this.isActive = isActive;
  }

  public setPriority(priority: number): void {
    this.priority = Priority.create(priority);
  }

  public setUpdatedAt(updatedAt: Date): void {
    this.updatedAt = updatedAt;
  }

  private validate(): void {
    this.validateActionShape();

    if (this.action.$case === 'snat') {
      this.requireText(this.action.snat.srcCidr, 'snat', 'srcCidr');
      this.requireText(this.action.snat.translatedIp, 'snat', 'translatedIp');
      this.validatePortRange(
        this.action.snat.srcPortMin,
        this.action.snat.srcPortMax,
        'snat',
        'srcPort',
      );
    }

    if (this.action.$case === 'dnat') {
      this.requireText(this.action.dnat.dstCidr, 'dnat', 'dstCidr');
      this.requireText(this.action.dnat.translatedIp, 'dnat', 'translatedIp');
    }

    if (this.action.$case === 'pat') {
      this.requireText(this.action.pat.dstIp, 'pat', 'dstIp');
      this.requireText(this.action.pat.translatedIp, 'pat', 'translatedIp');
    }

    if (this.action.$case === 'masquerade') {
      this.requireText(this.outInterface, 'masquerade', 'outInterface');
      this.validatePortRange(
        this.action.masquerade.srcPortMin,
        this.action.masquerade.srcPortMax,
        'masquerade',
        'srcPort',
      );
    }

    this.validatePortRange(
      this.matchSrcPortMin,
      this.matchSrcPortMax,
      this.action.$case,
      'matchSrcPort',
    );
    this.validatePortRange(
      this.matchDstPortMin,
      this.matchDstPortMax,
      this.action.$case,
      'matchDstPort',
    );
  }

  private validateActionShape(): void {
    const action = this.action as
      | {
          $case?: string;
          snat?: unknown;
          dnat?: unknown;
          pat?: unknown;
          masquerade?: unknown;
        }
      | undefined;

    if (!action?.$case) {
      throw new NatConfigIsInvalidException('unknown', 'action', 'action is required');
    }

    switch (action.$case) {
      case 'snat':
        if (!action.snat) {
          throw new NatConfigIsInvalidException('snat', 'action', 'snat payload is required');
        }
        return;
      case 'dnat':
        if (!action.dnat) {
          throw new NatConfigIsInvalidException('dnat', 'action', 'dnat payload is required');
        }
        return;
      case 'pat':
        if (!action.pat) {
          throw new NatConfigIsInvalidException('pat', 'action', 'pat payload is required');
        }
        return;
      case 'masquerade':
        if (!action.masquerade) {
          throw new NatConfigIsInvalidException(
            'masquerade',
            'action',
            'masquerade payload is required',
          );
        }
        return;
      default:
        throw new NatConfigIsInvalidException(
          action.$case,
          'action',
          'unsupported action case',
        );
    }
  }

  private requireText(
    value: string | null | undefined,
    type: string,
    field: string,
  ): void {
    if (!value || value.trim().length === 0) {
      throw new NatConfigIsInvalidException(type, field, `${field} is required`);
    }
  }

  private validatePortRange(
    min: Port | null | undefined,
    max: Port | null | undefined,
    type: string,
    field: string,
  ): void {
    if (min && max && min.getValue > max.getValue) {
      throw new NatConfigIsInvalidException(
        type,
        field,
        `${field} min cannot be greater than max`,
      );
    }
  }
}
