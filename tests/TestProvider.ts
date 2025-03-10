import type { POJO } from 'polykey/dist/types';
import type {
  ProviderId,
  IdentityId,
  ProviderToken,
  IdentityData,
  ProviderAuthenticateRequest,
  ProviderPaginationToken,
} from 'polykey/dist/identities/types';
import type {
  IdentitySignedClaim,
  ProviderIdentityClaimId,
} from 'polykey/dist/identities/types';
import type { SignedClaim } from 'polykey/dist/claims/types';
import type { ClaimLinkIdentity } from 'polykey/dist/claims/payloads';
import { Provider } from 'polykey/dist/identities';
import * as identitiesUtils from 'polykey/dist/identities/utils';
import * as identitiesErrors from 'polykey/dist/identities/errors';
import * as tokenUtils from 'polykey/dist/tokens/utils';

class TestProvider extends Provider {
  public readonly id: ProviderId;
  public readonly pageSize = 10;

  public linkIdCounter: number = 0;
  public users: Record<IdentityId, POJO>;
  public links: Record<ProviderIdentityClaimId, string>;
  protected userLinks: Record<IdentityId, Array<ProviderIdentityClaimId>>;
  protected userTokens: Record<string, IdentityId>;

  public constructor(providerId: ProviderId = 'test-provider' as ProviderId) {
    super();
    this.id = providerId;
    const testUser = 'test_user' as IdentityId;
    this.users = {
      [testUser]: {
        email: 'test_user@test.com',
        connected: ['connected_identity'],
      },
    };
    this.userTokens = {
      abc123: testUser,
    };
    this.links = {};
    this.userLinks = {
      [testUser]: ['test_link' as ProviderIdentityClaimId],
    };
  }

  public async *authenticate(): AsyncGenerator<
    ProviderAuthenticateRequest,
    IdentityId
  > {
    yield {
      url: 'test.com',
      data: {
        userCode: 'randomtestcode',
      },
    };
    // Always gives back the abc123 token
    const providerToken = { accessToken: 'abc123' };
    const identityId = await this.getIdentityId(providerToken);
    await this.putToken(identityId, providerToken);
    return identityId;
  }

  public async refreshToken(): Promise<ProviderToken> {
    // Always gives back the abc123 token
    return { accessToken: 'abc123' };
  }

  public async getAuthIdentityIds(): Promise<Array<IdentityId>> {
    const providerTokens = await this.getTokens();
    return Object.keys(providerTokens) as Array<IdentityId>;
  }

  public async getIdentityId(
    providerToken: ProviderToken,
  ): Promise<IdentityId> {
    providerToken = await this.checkToken(providerToken);
    return this.userTokens[providerToken.accessToken];
  }

  public async getIdentityData(
    authIdentityId: IdentityId,
    identityId: IdentityId,
  ): Promise<IdentityData | undefined> {
    const providerToken = await this.getToken(authIdentityId);
    if (!providerToken) {
      throw new identitiesErrors.ErrorProviderUnauthenticated(
        `${authIdentityId} has not been authenticated`,
      );
    }
    await this.checkToken(providerToken, authIdentityId);
    const user = this.users[identityId];
    if (!user) {
      return;
    }
    return {
      providerId: this.id,
      identityId: identityId,
      name: user.name ?? undefined,
      email: user.email ?? undefined,
      url: user.url ?? undefined,
    };
  }

  public async *getConnectedIdentityDatas(
    authIdentityId: IdentityId,
    searchTerms: Array<string> = [],
  ): AsyncGenerator<IdentityData> {
    const providerToken = await this.getToken(authIdentityId);
    if (!providerToken) {
      throw new identitiesErrors.ErrorProviderUnauthenticated(
        `${authIdentityId} has not been authenticated`,
      );
    }
    await this.checkToken(providerToken, authIdentityId);
    for (const [k, v] of Object.entries(this.users) as Array<
      [
        IdentityId,
        { name: string; email: string; url: string; connected: Array<string> },
      ]
    >) {
      if (k === authIdentityId) {
        continue;
      }
      if (!this.users[authIdentityId].connected.includes(k)) {
        continue;
      }
      const data: IdentityData = {
        providerId: this.id,
        identityId: k,
        name: v.name ?? undefined,
        email: v.email ?? undefined,
        url: v.url ?? undefined,
      };
      if (identitiesUtils.matchIdentityData(data, searchTerms)) {
        yield data;
      }
    }
    return;
  }

  public async publishClaim(
    authIdentityId: IdentityId,
    identityClaim: SignedClaim<ClaimLinkIdentity>,
  ): Promise<IdentitySignedClaim> {
    const providerToken = await this.getToken(authIdentityId);
    if (!providerToken) {
      throw new identitiesErrors.ErrorProviderUnauthenticated(
        `${authIdentityId} has not been authenticated`,
      );
    }
    await this.checkToken(providerToken, authIdentityId);
    const linkId = this.linkIdCounter.toString() as ProviderIdentityClaimId;
    this.linkIdCounter++;
    const identityClaimEncoded = tokenUtils.generateSignedToken(identityClaim);
    this.links[linkId] = JSON.stringify(identityClaimEncoded);
    // Checking if the `authIdentityId` exists explicitly as an array, otherwise we could end up with
    // `toString` identity causing us to insert a function into the `userLinks`
    this.userLinks[authIdentityId] = Array.isArray(
      this.userLinks[authIdentityId],
    )
      ? this.userLinks[authIdentityId]
      : [];
    const links = this.userLinks[authIdentityId];
    links.push(linkId);
    return {
      id: linkId,
      url: 'test.com',
      claim: identityClaim,
    };
  }

  public async *getClaimIdsPage(
    authIdentityId: IdentityId,
    identityId: IdentityId,
    paginationToken?: ProviderPaginationToken | undefined,
  ): AsyncGenerator<{
    claimId: ProviderIdentityClaimId;
    nextPaginationToken?: ProviderPaginationToken;
  }> {
    const providerToken = await this.getToken(authIdentityId);
    let startIndex = paginationToken == null ? 0 : parseInt(paginationToken);
    if (isNaN(startIndex)) {
      startIndex = 0;
    }
    if (!providerToken) {
      throw new identitiesErrors.ErrorProviderUnauthenticated(
        `${authIdentityId} has not been authenticated`,
      );
    }
    await this.checkToken(providerToken, authIdentityId);
    const claimIds =
      this.userLinks[identityId].slice(
        startIndex,
        this.pageSize + startIndex,
      ) ?? [];
    for (const [i, claimId] of claimIds.entries()) {
      yield {
        claimId,
        nextPaginationToken:
          i === claimIds.length - 1
            ? ((
                startIndex + this.pageSize
              ).toString() as ProviderPaginationToken)
            : undefined,
      };
    }
  }

  public async getClaim(
    authIdentityId: IdentityId,
    claimId: ProviderIdentityClaimId,
  ): Promise<IdentitySignedClaim | undefined> {
    const providerToken = await this.getToken(authIdentityId);
    if (!providerToken) {
      throw new identitiesErrors.ErrorProviderUnauthenticated(
        `${authIdentityId} has not been authenticated`,
      );
    }
    await this.checkToken(providerToken, authIdentityId);
    const linkClaimData = this.links[claimId];
    if (!linkClaimData) {
      return;
    }
    const linkClaim = this.parseClaim(linkClaimData);
    if (!linkClaim) {
      return;
    }
    return {
      claim: linkClaim,
      id: claimId,
      url: 'test.com',
    };
  }
}

export default TestProvider;
