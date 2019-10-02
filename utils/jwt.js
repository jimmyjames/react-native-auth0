import AuthError from '../auth/authError';
import { KEYUTIL, KJUR } from 'jsrsasign';
const jwtDecoder = require('jwt-decode');

const DEFAULT_LEEWAY = 60; //default clock-skew, in seconds
const ALLOWED_ALGORITHMS = ['RS256', 'HS256'];

export const verifyToken = (credentials, clientInfo) => {
  if (!tokenValidationRequired(credentials, clientInfo)) {
    return Promise.resolve(credentials);
  }

  if (!credentials.idToken) {
    return Promise.reject(
      idTokenError({
        desc: 'ID token missing'
      })
    );
  }

  return verifySignature(credentials, clientInfo)
    .then(decoded => validateClaims(decoded, clientInfo))
    .then(() => Promise.resolve(credentials));
};

const verifySignature = (credentials, clientInfo) => {
  let header, payload;

  try {
    header = jwtDecoder(credentials.idToken, { header: true });
    payload = jwtDecoder(credentials.idToken);
  } catch (err) {
    return Promise.reject(
      idTokenError({
        error: 'token_decoding_error',
        desc: 'Error decoding token'
      })
    );
  }

  const alg = header.alg;

  if (!ALLOWED_ALGORITHMS.includes(alg)) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_algorithm',
        desc: 'Token signing algorithm must be either RS256 or HS256'
      })
    );
  }

  // HS256 tokens require private key, which cannot be stored securely in public clients.
  // Since the ID token exchange is done via CODE with PKCE flow, skip signature verification in this case.
  if (alg === 'HS256') {
    return Promise.resolve(payload);
  }

  return getJwk(clientInfo.domain, header.kid)
    .then(jwk => {
      const pubKey = KEYUTIL.getKey(jwk);
      const signatureValid = KJUR.jws.JWS.verify(credentials.idToken, pubKey, [
        'RS256'
      ]);

      if (signatureValid) {
        return Promise.resolve(payload);
      } else {
        return Promise.reject(
          idTokenError({
            error: 'invalid_signature',
            desc: 'Token signature is not valid'
          })
        );
      }
    })
    .catch(err => {
      if (err.json && err.status === 0) {
        return Promise.reject(err);
      } else {
        return Promise.reject(
          idTokenError({
            error: 'key_retrieval_error',
            desc: 'Unable to retrieve public keyset needed to verify token'
          })
        );
      }
    });
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

const getJwk = (domain, kid) => {
  return getJwksUri(domain)
    .then(uri => getJwkFromUri(uri))
    .then(jwk => {
      const keys = jwk.keys;
      const key = keys
        .filter(
          k => k.use === 'sig' && k.kty === 'RSA' && k.kid && (k.n && k.e)
        )
        .find(k => k.kid == kid);
      return Promise.resolve(key);
    });
};

const getJwksUri = domain => {
  return fetch(`https://${domain}/.well-known/openid-configuration`)
    .then(resp => resp.json())
    .then(openIdConfig => openIdConfig.jwks_uri);
};

const getJwkFromUri = uri => {
  return fetch(uri).then(resp => resp.json());
};

const validateClaims = (decoded, opts) => {
  // Issuer
  if (!decoded.iss) {
    return Promise.reject(
      idTokenError({
        error: 'missing_issuer_claim',
        desc: 'Issuer (iss) claim must be present'
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
  if (!decoded.sub) {
    return Promise.reject(
      idTokenError({
        error: 'invlid_sub_claim',
        desc: '"sub" claim is not present'
      })
    );
  }

  // Audience
  if (!decoded.aud) {
    return Promise.reject(
      idTokenError({
        error: 'missing_aud_claim',
        desc: 'Audience (aud) claim must be present'
      })
    );
  }

  if (Array.isArray(decoded.aud) && !decoded.aud.includes(opts.clientId)) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_aud_claim',
        desc: `Audience (aud) claim mismatch; expected "${
          opts.clientId
        }" but was not one of "${decoded.aud.join(', ')}"`
      })
    );
  } else if (typeof decoded.aud === 'string' && decoded.aud !== opts.clientId) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_aud_claim',
        desc: `Audience (aud) claim mismatch; expected "${opts.clientId}" but found "${decoded.aud}"`
      })
    );
  }

  //--Time validation (epoch)--
  const now = new Date();
  const leeway = typeof opts.leeway === 'number' ? opts.leeway : DEFAULT_LEEWAY;

  //Expires at
  if (typeof decoded.exp !== 'number') {
    return Promise.reject(
      idTokenError({
        error: 'missing_exp_claim',
        desc: 'Expiration time (exp) claim must be present'
      })
    );
  }

  const expDate = new Date((decoded.exp + leeway) * 1000);

  if (now > expDate) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_exp_claim',
        desc: `Expiration Time (exp) claim error; current time (${now.getTime() /
          1000}) is after expiration time (${decoded.exp + leeway})`
      })
    );
  }

  //Issued at
  if (typeof decoded.iat !== 'number') {
    return Promise.reject(
      idTokenError({
        error: 'missing_iat_claim',
        desc: 'Issued At (iat) claim must be present'
      })
    );
  }

  const iatDate = new Date((decoded.iat - leeway) * 1000);

  if (now < iatDate) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_iat_claim',
        desc: `Issued At (iat) claim error; current time (${now.getTime() /
          1000}) is before issued at time (${decoded.iat - leeway})`
      })
    );
  }

  //Nonce
  if (opts.nonce) {
    if (!decoded.nonce) {
      return Promise.reject(
        idTokenError({
          error: 'missing_nonce_claim',
          desc: 'Nonce (nonce) claim must be present'
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
    if (!decoded.azp) {
      return Promise.reject(
        idTokenError({
          error: 'missing_azp_claim',
          desc:
            'Authorized Party (azp) claim must be present when Audience (aud) claim has multiple values'
        })
      );
    }

    if (decoded.azp !== opts.clientId) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_azp_claim',
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
          error: 'missing_auth_time_claim',
          desc:
            'Authentication Time (auth_time) claim must be present when Max Age (max_age) is specified'
        })
      );
    }

    const authValidUntil = decoded.auth_time + opts.maxAge + leeway;
    const authTimeDate = new Date(authValidUntil * 1000);

    if (now > authTimeDate) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_auth_time_claim',
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
