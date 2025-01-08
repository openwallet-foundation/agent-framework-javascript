import { IsOptional, IsString } from 'class-validator'

export class PublicKey {
  public constructor(options: { id: string; controller: string; type: string; value?: string }) {
    if (options) {
      this.id = options.id
      this.controller = options.controller
      this.type = options.type
      this.value = options.value
    }
  }

  @IsString()
  public id!: string

  @IsString()
  public controller!: string

  @IsString()
  public type!: string

  @IsString()
  @IsOptional()
  public value?: string
}
