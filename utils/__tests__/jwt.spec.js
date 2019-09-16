import { verifyToken } from '../jwt';
import pem from 'pem';
import { KEYUTIL } from 'jsrsasign';
import jws from 'jws';
import fetchMock from 'fetch-mock';

describe('ID token verification tests', () => {
  let certificate;

  beforeAll(async () => {
    certificate = await createCertificate();
  });

  beforeEach(() => {
    fetchMock.restore();
  });

  it('returns credentials when scope not specified', async () => {
    const credentials = getCredentials();
    await expect(verify(credentials, { scope: undefined })).resolves.toEqual(
      credentials
    );
  });

  it('returns credentials when scope does not include "openid"', async () => {
    const credentials = getCredentials();
    await expect(
      verify(credentials, {
        scope: 'profile email'
      })
    ).resolves.toEqual(credentials);
  });

  it('fails when "openid" scope used but no ID token is present', async () => {
    const credentials = getCredentials();
    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.verification_error'
    );
  });

  it('fails when token not signed with RS256 or HS256', async () => {
    const badAlgToken =
      'eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL3Rva2Vucy10ZXN0LmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJhdWQiOlsidG9rZW5zLXRlc3QtMTIzIiwiZXh0ZXJuYWwtdGVzdC05OTkiXSwiZXhwIjoxODEzMS42MjAzNTMxNTk3MjQsImlhdCI6LTE4MTMxLjYyMDM1MzE1OTcyNCwibm9uY2UiOiJhMWIyYzNkNGU1IiwiYXpwIjoidG9rZW5zLXRlc3QtMTIzIiwiYXV0aF90aW1lIjoxNTY2NTcxOTk4LjUxM30.';
    const credentials = getCredentials(badAlgToken);

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_algorithm'
    );
  });

  it('fails when unable to decode token', async () => {
    const testJwt = "won't work";
    const credentials = getCredentials(testJwt);

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.token_decoding_error'
    );
  });

  it('fails when discovery endpoint returns error', async () => {
    const testJwt = createJwt();
    const credentials = getCredentials(testJwt);

    fetchMock.get(
      `${BASE_EXPECTATIONS.issuer}.well-known/openid-configuration`,
      500
    );

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.key_retrieval_error'
    );
  });

  it('fails when signature is not verified', async () => {
    const testJwt = createJwt();
    const jwks = getJWKS();
    jwks.keys[0].n += 'bad';

    const credentials = getCredentials(testJwt);

    setupFetchMock({ jwks });

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_signature'
    );
  });

  it('does not verify signature when signed with HS256', async () => {
    const testJwt = createJwt({}, {}, 'HS256');
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    const result = await verify(credentials);

    expect(fetchMock.called()).toBe(false);
    expect(result).toMatchObject(credentials);
  });

  it('fails when "exp" is missing', async () => {
    const testJwt = createJwt({ exp: undefined });
    // const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_exp_claim'
    );
  });

  it('fails when "exp" is invalid', async () => {
    const testJwt = createJwt({ exp: yesterday() });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_exp_claim'
    );
  });

  it('fails when "iss" is missing', async () => {
    const testJwt = createJwt({ iss: undefined });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_issuer_claim'
    );
  });

  it('fails when "iss" is invalid', async () => {
    const testJwt = createJwt({ iss: 'some.other.issuer' });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_issuer_claim'
    );
  });

  it('fails when "sub" is missing', async () => {
    const testJwt = createJwt({ sub: undefined });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invlid_sub_claim'
    );
  });

  it('fails when "aud" is missing', async () => {
    const testJwt = createJwt({ aud: undefined });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_aud_claim'
    );
  });

  it('fails when "aud" does not contain the client ID', async () => {
    const testJwt = createJwt({ aud: BASE_EXPECTATIONS.clientIdAlt });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_aud_claim'
    );
  });

  it('fails when "aud" is an array and does not contain the client ID', async () => {
    const testJwt = createJwt({ aud: [BASE_EXPECTATIONS.clientIdAlt] });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_aud_claim'
    );
  });

  it('fails when "aud" is array with multiple items, and azp is missing', async () => {
    const testJwt = createJwt({ azp: undefined });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_azp_claim'
    );
  });

  it('fails when "max_age" was sent on the authentication request but "auth_time" is missing', async () => {
    const testJwt = createJwt({ auth_time: undefined });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(
      verify(credentials, {
        maxAge: 200
      })
    ).rejects.toHaveProperty('name', 'a0.idtoken.invalid_auth_time_claim');
  });

  it('fails when "max_age" was sent on the authentication request but "auth_time" is invalid', async () => {
    const testJwt = createJwt({ auth_time: yesterday() });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(
      verify(credentials, {
        maxAge: 1
      })
    ).rejects.toHaveProperty('name', 'a0.idtoken.invalid_max_age_claim');
  });

  it('fails when "nonce" sent on authentication request but missing from token claims', async () => {
    const testJwt = createJwt({ nonce: undefined });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_nonce_claim'
    );
  });

  it('fails when "nonce" sent on authentication request but token claim is invalid', async () => {
    const testJwt = createJwt();
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(
      verify(credentials, {
        nonce: 'nonce-on-authrequest'
      })
    ).rejects.toHaveProperty('name', 'a0.idtoken.invalid_nonce_claim');
  });

  it('fails when "iat" is missing', async () => {
    const testJwt = createJwt({ iat: undefined });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_iat_claim'
    );
  });

  it('fails when "iat" is invalid', async () => {
    const testJwt = createJwt({ iat: tomorrow() });
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    await expect(verify(credentials)).rejects.toHaveProperty(
      'name',
      'a0.idtoken.invalid_iat_claim'
    );
  });

  it('succeeds with good token', async () => {
    const testJwt = createJwt();
    const jwks = getJWKS();
    const credentials = getCredentials(testJwt);

    setupFetchMock();

    const result = await verify(credentials);

    expect(
      fetchMock.done(
        BASE_EXPECTATIONS.issuer + '.well-known/openid-configuration'
      )
    ).toBe(true);
    expect(
      fetchMock.done(BASE_EXPECTATIONS.issuer + '.well-known/jwks.json')
    ).toBe(true);
    expect(result).toMatchObject(credentials);
  });

  const createJwt = (
    payloadOverrides = {},
    headerOverrides = {},
    alg = 'RS256'
  ) => {
    const defaultHeader = { alg, kid: BASE_EXPECTATIONS.kid };
    // good id token payload
    const defaultPayload = {
      iss: BASE_EXPECTATIONS.issuer,
      sub: 'auth0|123456789',
      aud: [BASE_EXPECTATIONS.clientId, BASE_EXPECTATIONS.clientIdAlt],
      exp: tomorrow(),
      iat: yesterday(),
      nonce: BASE_EXPECTATIONS.nonce,
      azp: BASE_EXPECTATIONS.clientId,
      auth_time: BASE_EXPECTATIONS.clock / 1000
    };

    const header = Object.assign({}, defaultHeader, headerOverrides);
    const payload = Object.assign({}, defaultPayload, payloadOverrides);

    const opts = {
      header,
      payload,
      ...(alg === 'RS256'
        ? { privateKey: certificate.serviceKey }
        : { secret: 'secret' })
    };

    return jws.sign(opts);
  };

  const getJWKS = () => {
    const publicKey = KEYUTIL.getKey(certificate.publicKey);
    const jwkFromKey = KEYUTIL.getJWKFromKey(publicKey);

    jwkFromKey.kid = BASE_EXPECTATIONS.kid;
    jwkFromKey.alg = 'RS256';
    jwkFromKey.use = 'sig';

    return { keys: [jwkFromKey] };
  };

  const setupFetchMock = ({
    domain = BASE_EXPECTATIONS.domain,
    jwks = getJWKS()
  } = {}) => {
    const expectedDiscoveryUri = `https://${domain}/.well-known/openid-configuration`;
    const expectedJwksUri = `https://${domain}/.well-known/jwks.json`;

    fetchMock.get(expectedDiscoveryUri, { jwks_uri: expectedJwksUri });
    fetchMock.get(expectedJwksUri, jwks);
  };
});

const verify = (credentials, clientInfoOverrides = {}) => {
  const clientInfoDefaults = {
    domain: BASE_EXPECTATIONS.domain,
    clientId: BASE_EXPECTATIONS.clientId,
    scope: 'openid profile email',
    nonce: BASE_EXPECTATIONS.nonce
  };

  const clientInfo = Object.assign({}, clientInfoDefaults, clientInfoOverrides);
  return verifyToken(credentials, clientInfo);
};

const createCertificate = () => {
  return new Promise((res, rej) => {
    pem.createCertificate({ days: 1, selfSigned: true }, function(err, keys) {
      if (err) {
        return rej(err);
      }
      pem.getPublicKey(keys.certificate, function(e, p) {
        if (e) {
          return rej(e);
        }
        res({
          serviceKey: keys.serviceKey,
          certificate: keys.certificate,
          publicKey: p.publicKey
        });
      });
    });
  });
};

const BASE_EXPECTATIONS = {
  clientId: 'tokens-test-123',
  clientIdAlt: 'external-test-123',
  domain: 'tokens-test.auth0.com',
  issuer: 'https://tokens-test.auth0.com/',
  nonce: 'a59vk592',
  clock: Date.now(),
  kid: '1234'
};

const yesterday = () => {
  return Math.round(BASE_EXPECTATIONS.clock / 1000 - 3600 * 24);
};

const tomorrow = () => {
  return Math.round(BASE_EXPECTATIONS.clock / 1000 + 3600 * 24);
};

const getCredentials = idToken => {
  return {
    accessToken: 'abc',
    expiresIn: 86400,
    tokenType: 'Bearer',
    ...(idToken ? { idToken: idToken } : {})
  };
};
