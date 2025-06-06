import { Router } from 'express';
import {
  JwtAuthGrantResponse as AccessTokenResponse,
  AccessTokenResult,
  HttpResponse,
  OAuthBadRequest,
} from 'id-assert-authz-grant-client';
import passport from 'passport';
import OpenIDConnectStrategy, { Profile, VerifyCallback } from 'passport-openidconnect';
import qs from 'qs';
import prisma from '../prisma';

// Most of the code below comes from https://developer.okta.com/blog/2023/07/28/oidc_workshop
export const WIKI_COOKIE_NAME = 'wiki.sid';
const controller = Router();

async function getApiAccessToken(opts: {
  tokenUrl: string;
  subjectToken: string;
  resource: string;
  scopes: string[] | undefined;
}): Promise<AccessTokenResult> {
  const { tokenUrl, subjectToken, resource, scopes } = opts;
  const requestData = {
    grant_type: 'urn:auth0:params:oauth:grant-type:token-exchange:cross-app-authorization',
    requested_token_type: 'http://auth0.com/oauth/token-type/cross-app-authorization-access-token',
    client_id: process.env.CLIENT1_CLIENT_ID!,
    client_secret: process.env.CLIENT1_CLIENT_SECRET!,
    resource,
    scope: (scopes || []).join(' '),
    subject_token: subjectToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
  };

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: qs.stringify(requestData),
  });

  const resStatus = response.status;
  if (resStatus === 400) {
    return {
      error: new OAuthBadRequest((await response.json()) as Record<string, any>),
    };
  }

  if (resStatus > 200 && resStatus < 600) {
    return {
      error: new HttpResponse(
        response.url,
        response.status,
        response.statusText,
        await response.text()
      ),
    };
  }

  const payload = new AccessTokenResponse((await response.json()) as Record<string, any>);
  return { payload };
}

async function orgFromDomain(domain: string) {
  const org = await prisma.organization.findFirst({
    where: {
      domain: domain,
    },
  });
  return org;
}

async function orgFromAuthServerOrgKey(key: string) {
  const org = await prisma.organization.findFirst({
    where: {
      auth_server_key: key,
    },
  });
  return org;
}

function getDomainFromEmail(email: string | undefined | null) {
  if (!email) {
    return null;
  }
  const [, domain] = email.split('@');
  return domain;
}

const verify = async (
  _issuer: string,
  uiProfile: { _json: { org_id: string }; _raw: string },
  profile: Profile,
  _context: object,
  idToken: object | string,
  _accessToken: string,
  _refreshToken: string,
  _params: object,
  done: VerifyCallback
) => {
  // Using a hardcoded external org id just for demo purposes
  // In a real world scenario, use uiProfile._json.org_id
  const externalOrgId = 'customer1'; // TODO: uiProfile._json.org_id;
  if (!externalOrgId) {
    // eslint-disable-next-line no-underscore-dangle
    return done(new Error(`No external org id found, profile: ${uiProfile._raw}`));
  }

  const org = await orgFromAuthServerOrgKey(externalOrgId);
  if (!org) {
    // eslint-disable-next-line no-underscore-dangle
    return done(new Error(`No org found for key=${externalOrgId}, profile: ${uiProfile._raw}`));
  }

  // Passport.js runs this verify function after successfully completing
  // the OIDC flow, and gives this app a chance to do something with
  // the response from the OIDC server, like create users on the fly.

  const externalUserId = profile.id;
  let user = await prisma.user.findFirst({
    where: {
      orgId: org.id,
      externalId: externalUserId,
    },
  });

  if (!user) {
    // Ensure the profile response has the correct fields present to update or create a new user

    if (!profile.emails) {
      return done(new Error(`Invalid profile response: ${JSON.stringify(profile)}`));
    }

    user = await prisma.user.findFirst({
      where: {
        orgId: org.id,
        email: profile.emails[0].value,
      },
    });
    if (user) {
      await prisma.user.update({
        where: { id: user.id },
        data: { externalId: externalUserId },
      });
    }

    if (!user) {
      user = await prisma.user.create({
        data: {
          org: { connect: { id: org.id } },
          externalId: externalUserId,
          email: profile.emails![0].value,
          name: profile.displayName ?? profile.emails[0]?.value,
        },
      });
    }
  }

  // use Auth0 Token Vault to fetch Resource Server API Access Token
  let accessTokenResponse: AccessTokenResult;

  try {
    accessTokenResponse = await getApiAccessToken({
      tokenUrl: `${process.env.AUTH_SERVER}/oauth/token`,
      subjectToken: idToken.toString(),
      resource: process.env.TODO_SERVER!,
      scopes: ['read', 'write'],
    });
  } catch (error: unknown) {
    // Errors if there was an issue making the request or parsing the response.
    console.log('Failed to fetch Resource Server Access Token using Auth0 Token Vault', {
      error,
    });

    return done(null, user);
  }

  if ('error' in accessTokenResponse) {
    console.log('Failed to fetch Resource Server Access Token using Auth0 Token Vault', {
      error: accessTokenResponse.error,
    });

    return done(null, user);
  }

  const accessToken = accessTokenResponse.payload;

  try {
    await prisma.authorizationToken.upsert({
      where: {
        orgId_userId_resource: {
          userId: user.id,
          orgId: user.orgId,
          resource: 'CLIENT2',
        },
      },
      create: {
        userId: user.id,
        orgId: user.orgId,
        resource: 'CLIENT2',
        accessToken: accessToken.access_token,
        refreshToken: accessToken.refresh_token,
        // jagToken: authGrantToken.access_token,
        idToken: idToken.toString(),
        expiresAt: new Date(Date.now() + (accessToken.expires_in ?? 0) * 1000),
        status: 'ACTIVE',
      },
      update: {
        accessToken: accessToken.access_token,
        refreshToken: accessToken.refresh_token,
        // jagToken: authGrantToken.access_token,
        idToken: idToken.toString(),
        expiresAt: new Date(Date.now() + (accessToken.expires_in ?? 0) * 1000),
        status: 'ACTIVE',
      },
    });
  } catch (error: unknown) {
    if (error instanceof Error) {
      return done(error);
    }
    throw error;
  }

  return done(null, user);
};

function createStrategy(username: string) {
  return new OpenIDConnectStrategy(
    {
      issuer: `${process.env.AUTH_SERVER}/`,
      authorizationURL: `${process.env.AUTH_SERVER}/authorize`,
      tokenURL: `${process.env.AUTH_SERVER}/oauth/token`,
      userInfoURL: `${process.env.AUTH_SERVER}/userinfo`,
      clientID: process.env.CLIENT1_CLIENT_ID!,
      clientSecret: process.env.CLIENT1_CLIENT_SECRET!,
      scope: 'profile email openid',
      callbackURL: `${process.env.WIKI_SERVER}/api/openid/callback/`,
      loginHint: username,
      skipUserProfile: false,
    },
    verify
  );
}

/**
 * Frontend UI can call this to see if the domain matches an Organization in the database.
 */
controller.post('/check', async (req, res) => {
  const { username } = req.body;

  const domain = getDomainFromEmail(username);
  if (domain) {
    let org = await prisma.organization.findFirst({
      where: {
        domain: domain,
      },
    });
    if (!org) {
      org = await prisma.organization.findFirst({
        where: {
          User: {
            some: {
              email: username,
            },
          },
        },
      });
    }
    if (org) {
      res.json({ orgId: org.id });
      return;
    }
  }

  res.json({ orgId: null });
});

controller.post('/signout', async (req, res, next) => {
  req.logout((err) => {
    if (err) {
      next(err);
    }
  });

  req.session.destroy((err) => {
    if (!err) {
      res.status(200).clearCookie(WIKI_COOKIE_NAME, { path: '/' }).json({ status: 'Success' });
    } else {
      next(err);
    }
  });
});

/**

/**
 * The frontend then redirects here to have the backend start the OIDC flow.
 * (You should probably use random IDs, not auto-increment integers
 * to avoid revealing how many enterprise customers you have.)
 */
controller.get('/start/:username', async (req, res, next) => {
  const domain = getDomainFromEmail(req.params.username);
  if (!domain) {
    res.sendStatus(404);
    return;
  }

  const org = await orgFromDomain(domain);
  if (!org) {
    res.sendStatus(404);
    return;
  }

  const strategy = createStrategy(req.params.username);
  if (!strategy) {
    res.sendStatus(404);
    return;
  }

  passport.authenticate(strategy)(req, res, next);
});

/**
 * Callback called from the Oauth server on succesful authentication.
 */
controller.get('/callback/', async (req, res, next) => {
  passport.authenticate(createStrategy(''), {
    successRedirect: '/',
    failureRedirect: '/',
    failureMessage: true,
  })(req, res, next);
});

export default controller;
