/**
 * Represents `~l10n` decorator
 */
export class L10nDecorator {
  public constructor(partial?: Partial<L10nDecorator>) {
    this.locale = partial?.locale
  }

  public locale?: string
}
