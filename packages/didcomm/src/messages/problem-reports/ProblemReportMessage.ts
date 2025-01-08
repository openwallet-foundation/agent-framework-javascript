// Create a base ProblemReportMessage message class and add it to the messages directory
import { Expose } from 'class-transformer'
import { IsEnum, IsOptional, IsString } from 'class-validator'

import { AgentMessage } from '../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../util/messageType'

export enum WhoRetriesStatus {
  You = 'YOU',
  Me = 'ME',
  Both = 'BOTH',
  None = 'NONE',
}

export enum ImpactStatus {
  Message = 'MESSAGE',
  Thread = 'THREAD',
  Connection = 'CONNECTION',
}

export enum WhereStatus {
  Cloud = 'CLOUD',
  Edge = 'EDGE',
  Wire = 'WIRE',
  Agency = 'AGENCY',
}

export enum OtherStatus {
  You = 'YOU',
  Me = 'ME',
  Other = 'OTHER',
}

export interface DescriptionOptions {
  en: string
  code: string
}

export interface FixHintOptions {
  en: string
}

export interface ProblemReportMessageOptions {
  id?: string
  description: DescriptionOptions
  problemItems?: string[]
  whoRetries?: WhoRetriesStatus
  fixHint?: FixHintOptions
  impact?: ImpactStatus
  where?: WhereStatus
  noticedTime?: string
  trackingUri?: string
  escalationUri?: string
}

/**
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md
 */
export class ProblemReportMessage extends AgentMessage {
  /**
   * Create new ReportProblem instance.
   * @param options
   */
  public constructor(options: ProblemReportMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.description = options.description
      this.problemItems = options.problemItems
      this.whoRetries = options.whoRetries
      this.fixHint = options.fixHint
      this.impact = options.impact
      this.where = options.where
      this.noticedTime = options.noticedTime
      this.trackingUri = options.trackingUri
      this.escalationUri = options.escalationUri
    }
  }

  @IsValidMessageType(ProblemReportMessage.type)
  public readonly type: string = ProblemReportMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/notification/1.0/problem-report')

  public description!: DescriptionOptions

  @IsOptional()
  @Expose({ name: 'problem_items' })
  public problemItems?: string[]

  @IsOptional()
  @IsEnum(WhoRetriesStatus)
  @Expose({ name: 'who_retries' })
  public whoRetries?: WhoRetriesStatus

  @IsOptional()
  @Expose({ name: 'fix_hint' })
  public fixHint?: FixHintOptions

  @IsOptional()
  @IsEnum(WhereStatus)
  public where?: WhereStatus

  @IsOptional()
  @IsEnum(ImpactStatus)
  public impact?: ImpactStatus

  @IsOptional()
  @IsString()
  @Expose({ name: 'noticed_time' })
  public noticedTime?: string

  @IsOptional()
  @IsString()
  @Expose({ name: 'tracking_uri' })
  public trackingUri?: string

  @IsOptional()
  @IsString()
  @Expose({ name: 'escalation_uri' })
  public escalationUri?: string
}
