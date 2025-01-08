export enum MediatorPickupStrategy {
  // Use PickUp v1 protocol to periodically retrieve messages
  PickUpV1 = 'PickUpV1',

  // Use PickUp v2 protocol to periodically retrieve messages
  PickUpV2 = 'PickUpV2',

  // Use PickUp v2 protocol in Live Mode to get incoming messages as soon as they arrive
  // to mediator
  PickUpV2LiveMode = 'PickUpV2LiveMode',

  // Implicit pickup strategy means picking up messages only using return route
  // decorator. This is what ACA-Py currently uses
  Implicit = 'Implicit',

  // Do not pick up messages
  None = 'None',
}
