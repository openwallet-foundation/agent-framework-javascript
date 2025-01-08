/**
 * Connection error code in RFC 0023.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0023-did-exchange/README.md#errors
 */
export enum DidExchangeProblemReportReason {
  RequestNotAccepted = 'request_not_accepted',
  RequestProcessingError = 'request_processing_error',
  ResponseNotAccepted = 'response_not_accepted',
  ResponseProcessingError = 'response_processing_error',
  CompleteRejected = 'complete_rejected',
}
