package autonoma

import (
	"fmt"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"
)

// registry lists every model a recipe may seed. The name on the left is the key
// a recipe's "create" object uses; the InputStruct behind each definition is
// what `discover` reports and what incoming records are validated against.
//
// Creation order is derived by the SDK from the _alias/_ref graph, and teardown
// runs in reverse, so an Account seeded first is deleted last and its cascade
// mops up anything a child factory's own teardown already handled.
func (f *factories) registry() sdk.FactoryRegistry {
	return sdk.FactoryRegistry{
		// Tenancy and people.
		"Account":             f.accountFactory(),
		"User":                f.userFactory(),
		"PersonalAccessToken": f.personalAccessTokenFactory(),
		"UserInviteRecord":    f.userInviteFactory(),

		// Overlay network.
		"Group":           f.groupFactory(),
		"SetupKey":        f.setupKeyFactory(),
		"Peer":            f.peerFactory(),
		"Policy":          f.policyFactory(),
		"Checks":          f.postureChecksFactory(),
		"Route":           f.routeFactory(),
		"NameServerGroup": f.nameServerGroupFactory(),
		"Network":         f.networkFactory(),
		"NetworkRouter":   f.networkRouterFactory(),
		"NetworkResource": f.networkResourceFactory(),
		"Job":             f.jobFactory(),
		"Zone":            f.zoneFactory(),
		"Record":          f.recordFactory(),

		// Reverse proxy.
		"Proxy":            f.proxyFactory(),
		"Domain":           f.domainFactory(),
		"Service":          f.serviceFactory(),
		"ProxyAccessToken": f.proxyAccessTokenFactory(),
		"AccessLogEntry":   f.accessLogFactory(),

		// Agent network.
		"AgentNetworkSettings": f.agentNetworkSettingsFactory(),
		"Provider":             f.providerFactory(),
		"Guardrail":            f.guardrailFactory(),
		"AccountBudgetRule":    f.budgetRuleFactory(),
		"Consumption":          f.consumptionFactory(),
	}
}

// auth hands the test runner credentials that actually work against this
// deployment: the account owner's email and password for the embedded IdP's
// login screen, plus a real Personal Access Token for direct API calls.
//
// The SDK offers the first seeded User, but the account owner is the identity
// the run should drive: it is created by the Account factory with a password we
// chose, it holds the owner role, and it exists in every scenario. The offered
// user is used only when a recipe seeds users without an account of its own.
func (f *factories) auth(user map[string]any, actx sdk.AuthContext) (map[string]any, error) {
	ctx := f.ctx

	account := firstRecord(actx.Refs, "Account")
	if account == nil {
		if user == nil {
			return map[string]any{}, nil
		}
		return map[string]any{
			"credentials": map[string]any{
				"email":    str(user, "email"),
				"password": str(user, "password"),
			},
		}, nil
	}

	accountID := str(account, "id")
	ownerID := str(account, "ownerUserId")

	result := map[string]any{
		"credentials": map[string]any{
			"email":    str(account, "ownerEmail"),
			"password": str(account, "ownerPassword"),
		},
	}

	// A token minted here rather than reused from the recipe, so the run always
	// gets a live one even when the recipe seeds no PersonalAccessToken.
	pat, err := f.deps.AccountManager.CreatePAT(ctx, accountID, ownerID, ownerID, "autonoma-test-run", authTokenExpiryDays)
	if err != nil {
		return nil, fmt.Errorf("mint an API token for the seeded owner: %w", err)
	}
	result["headers"] = map[string]any{"Authorization": "Token " + pat.PlainToken}

	return result, nil
}

// authTokenExpiryDays outlives any single run by a wide margin while staying
// well inside the PAT maximum, so a long suite never trips over its own token.
const authTokenExpiryDays = 7

func firstRecord(refs map[string][]map[string]any, model string) map[string]any {
	if records := refs[model]; len(records) > 0 {
		return records[0]
	}
	return nil
}
