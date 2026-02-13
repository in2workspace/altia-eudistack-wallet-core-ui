export interface VerifiablePresentation {
  /**
   * JSON-LD context (maps to "@context")
   */
  '@context': string[];

  id: string;

  type: string[];

  holder: string;

  verifiableCredential: string[];
}
