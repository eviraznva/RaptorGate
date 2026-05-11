import { Priority } from '../value-objects/priority.vo.js';
import {
  SmtpMatchers,
  createEmptySmtpMatchers,
} from '../value-objects/smtp-matchers.vo.js';

export class FirewallRule {
  private constructor(
    private readonly id: string,
    private name: string,
    private description: string | null,
    private zonePairId: string,
    private isActive: boolean,
    private content: string,
    private priority: Priority,
    private readonly createdAt: Date,
    private updatedAt: Date,
    private readonly createdBy: string,
    private smtpMatchers: SmtpMatchers,
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null,
    zonePairId: string,
    isActive: boolean,
    content: string,
    priority: Priority,
    createdAt: Date,
    updatedAt: Date,
    createdBy: string,
    smtpMatchers?: SmtpMatchers,
  ): FirewallRule {
    return new FirewallRule(
      id,
      name,
      description,
      zonePairId,
      isActive,
      content,
      priority,
      createdAt,
      updatedAt,
      createdBy,
      smtpMatchers ?? createEmptySmtpMatchers(),
    );
  }

  public getId(): string {
    return this.id;
  }

  public getName(): string {
    return this.name;
  }

  public getDescription(): string | null {
    return this.description;
  }

  public getZonePairId(): string {
    return this.zonePairId;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getContent(): string {
    return this.content;
  }

  public getPriority(): Priority {
    return this.priority;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public getCreatedBy(): string {
    return this.createdBy;
  }

  public getSmtpMatchers(): SmtpMatchers {
    return this.smtpMatchers;
  }

  public setName(name: string): void {
    this.name = name;
  }

  public setDescription(description: string | null): void {
    this.description = description;
  }

  public setZonePairId(zonePairId: string): void {
    this.zonePairId = zonePairId;
  }

  public setIsActive(isActive: boolean): void {
    this.isActive = isActive;
  }

  public setContent(content: string): void {
    this.content = content;
  }

  public setPriority(priority: Priority): void {
    this.priority = priority;
  }

  public setUpdatedAt(updatedAt: Date): void {
    this.updatedAt = updatedAt;
  }

  public setSmtpMatchers(smtpMatchers: SmtpMatchers): void {
    this.smtpMatchers = smtpMatchers;
  }
}
