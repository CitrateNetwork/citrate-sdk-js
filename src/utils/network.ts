/** Network guard (red-phase stub: no check yet). */
import { CitrateError } from '../errors/CitrateError';

export const EXPECTED_GENESIS_HASH: string = '';

export class WrongNetworkError extends CitrateError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'WRONG_NETWORK', details);
    this.name = 'WrongNetworkError';
  }
}
