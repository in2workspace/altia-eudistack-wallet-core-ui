import { JWT_PROOF_CLAIM } from "src/app/constants/jwt-proof.constants";

export interface JwtProofHeaderAndPayload {
  header: JwtProofHeader;
  payload: JwtProofPayload;
}

export interface JwtProofPayload {
  aud: string[];
  iat: number;
  exp: number;
  nonce: string;
}

export interface JwtProofHeader {
  alg: 'ES256';
  typ: typeof JWT_PROOF_CLAIM;
  jwk: JsonWebKey;
}