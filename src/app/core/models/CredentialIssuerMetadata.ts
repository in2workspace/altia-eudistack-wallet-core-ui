export interface CredentialIssuerMetadata {
  credentialIssuer?: string;
  credentialEndpoint?: string;
  deferredCredentialEndpoint?: string;
  credentialsSupported?: unknown;
  credentialsConfigurationsSupported: {[key: string]: CredentialsConfigurationsSuppported}; 

  /** Field that is hardcoded in the deprecated backend method. */
  authorizationServer?: string;

  /** Backward-compat check field. */
  credentialToken?: unknown;

  [key: string]: unknown;
}

export interface CredentialsConfigurationsSuppported{
  format: string;
  cryptographicBindingMethodsSupported?: string[];
}

export interface CredentialsSupported{
  format: string;
  type: string;
  trustFramework: TrustFramework;
  display: Display[];
}

export interface TrustFramework{
  name: string;
  type: string;
  uri: string;
}

export interface Display{
  name: string;
  locale: string;
}