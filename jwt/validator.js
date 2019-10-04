import AuthError from '../auth/authError';
import { verifySignature } from './signatureVerifier';

const DEFAULT_LEEWAY = 60; //default clock-skew, in seconds

export const verifyToken = (credentials, clientInfo) => {
  if (!tokenValidationRequired(credentials, clientInfo)) {
    return Promise.resolve(credentials);
  }

  if (!credentials.idToken) {
    return Promise.reject(
      idTokenError({
        error: 'missing_id_token',
        desc: 'ID token is required but missing'
      })
    );
  }

  return verifySignature(credentials, clientInfo)
    .then(decoded => validateClaims(decoded, clientInfo))
    .then(() => Promise.resolve(credentials));
};

const tokenValidationRequired = (credentials, clientInfo) => {
  // If client did not specify scope of "openid", we do not expect an ID token thus no validation is needed
  if (clientInfo.scope && typeof clientInfo.scope === 'string') {
    const scopes = clientInfo.scope.split(/(\s+)/);
    if (scopes.includes('openid')) {
      return true;
    }
  }
  return false;
};

const validateClaims = (decoded, opts) => {
  // Issuer
  if (typeof decoded.iss !== 'string') {
    return Promise.reject(
      idTokenError({
        error: 'missing_issuer_claim',
        desc: 'Issuer (iss) claim must be a string present in the ID token'
      })
    );
  }

  if (decoded.iss !== 'https://' + opts.domain + '/') {
    return Promise.reject(
      idTokenError({
        error: 'invalid_issuer_claim',
        desc: `Issuer (iss) claim mismatch; expected "https://${opts.domain}/", found "${decoded.iss}"`
      })
    );
  }

  // Subject
  if (typeof decoded.sub !== 'string') {
    return Promise.reject(
      idTokenError({
        error: 'missing_subject_claim',
        desc: 'Subject (sub) claim must be a string present in the ID token'
      })
    );
  }

  // Audience
  if (!(typeof decoded.aud === 'string' || Array.isArray(decoded.aud))) {
    return Promise.reject(
      idTokenError({
        error: 'missing_audience_claim',
        desc:
          'Audience (aud) claim must be a string or array of strings present in the ID token'
      })
    );
  }

  if (Array.isArray(decoded.aud) && !decoded.aud.includes(opts.clientId)) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_audience_claim',
        desc: `Audience (aud) claim mismatch; expected "${
          opts.clientId
        }" but was not one of "${decoded.aud.join(', ')}"`
      })
    );
  } else if (typeof decoded.aud === 'string' && decoded.aud !== opts.clientId) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_audience_claim',
        desc: `Audience (aud) claim mismatch; expected "${opts.clientId}" but found "${decoded.aud}"`
      })
    );
  }

  //--Time validation (epoch)--
  const now = opts._clock ? opts._clock : new Date();
  const leeway = typeof opts.leeway === 'number' ? opts.leeway : DEFAULT_LEEWAY;

  //Expires at
  if (typeof decoded.exp !== 'number') {
    return Promise.reject(
      idTokenError({
        error: 'missing_expires_at_claim',
        desc:
          'Expiration Time (exp) claim must be a number present in the ID token'
      })
    );
  }

  const expDate = new Date((decoded.exp + leeway) * 1000);

  if (now > expDate) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_expires_at_claim',
        desc: `Expiration Time (exp) claim error; current time (${now.getTime() /
          1000}) is after expiration time (${decoded.exp + leeway})`
      })
    );
  }

  //Issued at
  if (typeof decoded.iat !== 'number') {
    return Promise.reject(
      idTokenError({
        error: 'missing_issued_at_claim',
        desc: 'Issued At (iat) claim must be a number present in the ID token'
      })
    );
  }

  const iatDate = new Date((decoded.iat - leeway) * 1000);

  if (now < iatDate) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_issued_at_claim',
        desc: `Issued At (iat) claim error; current time (${now.getTime() /
          1000}) is before issued at time (${decoded.iat - leeway})`
      })
    );
  }

  //Nonce
  if (opts.nonce) {
    if (typeof decoded.nonce !== 'string') {
      return Promise.reject(
        idTokenError({
          error: 'missing_nonce_claim',
          desc: 'Nonce (nonce) claim must be a string present in the ID token'
        })
      );
    }
    if (decoded.nonce !== opts.nonce) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_nonce_claim',
          desc: `Nonce (nonce) claim mismatch; expected "${opts.nonce}", found "${decoded.nonce}"`
        })
      );
    }
  }

  //Authorized party
  if (Array.isArray(decoded.aud) && decoded.aud.length > 1) {
    if (typeof decoded.azp !== 'string') {
      return Promise.reject(
        idTokenError({
          error: 'missing_authorized_party_claim',
          desc:
            'Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values'
        })
      );
    }

    if (decoded.azp !== opts.clientId) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_authorized_party_claim',
          desc: `Authorized Party (azp) claim mismatch; expected "${opts.clientId}", found "${decoded.azp}"`
        })
      );
    }
  }

  //Authentication time
  if (typeof opts.maxAge === 'number') {
    if (typeof decoded.auth_time !== 'number') {
      return Promise.reject(
        idTokenError({
          error: 'missing_authorization_time_claim',
          desc:
            'Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified'
        })
      );
    }

    const authValidUntil = decoded.auth_time + opts.maxAge + leeway;
    const authTimeDate = new Date(authValidUntil * 1000);

    if (now > authTimeDate) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_authorization_time_claim',
          desc: `Authentication Time (auth_time) claim indicates that too much time has passed since the last end-user authentication. Current time (${now.getTime() /
            1000}) is after last auth at ${authValidUntil}`
        })
      );
    }
  }

  return Promise.resolve();
};

const idTokenError = ({
  error = 'verification_error',
  desc = 'Error verifying ID token'
} = {}) => {
  return new AuthError({
    json: {
      error: `a0.idtoken.${error}`,
      error_description: desc
    },
    status: 0
  });
};
