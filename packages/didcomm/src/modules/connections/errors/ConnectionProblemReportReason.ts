/**
 * Connection error code in RFC 160.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0160-connection-protocol/README.md#errors
 */
export enum ConnectionProblemReportReason {
  RequestNotAccepted = 'request_not_accepted',
  RequestProcessingError = 'request_processing_error',
  ResponseNotAccepted = 'response_not_accepted',
  ResponseProcessingError = 'response_processing_error',
}
