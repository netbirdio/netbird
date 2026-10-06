package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestSqlStore_GetAccountOnboarding(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "9439-34653001fc3b-bf1c8084-ba50-4ce7"
	a, err := store.GetAccount(context.Background(), accountID)
	require.NoError(t, err)
	t.Logf("Onboarding: %+v", a.Onboarding)
	err = store.SaveAccount(context.Background(), a)
	require.NoError(t, err)
	onboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
	require.NoError(t, err)
	require.NotNil(t, onboarding)
	require.Equal(t, accountID, onboarding.AccountID)
	require.Equal(t, time.Date(2024, time.October, 2, 14, 1, 38, 210000000, time.UTC), onboarding.CreatedAt.UTC())
}

func TestSqlStore_SaveAccountOnboarding(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)
	t.Run("New onboarding should be saved correctly", func(t *testing.T) {
		accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		onboarding := &types.AccountOnboarding{
			AccountID:             accountID,
			SignupFormPending:     true,
			OnboardingFlowPending: true,
		}

		err = store.SaveAccountOnboarding(context.Background(), onboarding)
		require.NoError(t, err)

		savedOnboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
		require.NoError(t, err)
		require.Equal(t, onboarding.SignupFormPending, savedOnboarding.SignupFormPending)
		require.Equal(t, onboarding.OnboardingFlowPending, savedOnboarding.OnboardingFlowPending)
	})

	t.Run("Existing onboarding should be updated correctly", func(t *testing.T) {
		accountID := "9439-34653001fc3b-bf1c8084-ba50-4ce7"
		onboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
		require.NoError(t, err)

		onboarding.OnboardingFlowPending = !onboarding.OnboardingFlowPending
		onboarding.SignupFormPending = !onboarding.SignupFormPending

		err = store.SaveAccountOnboarding(context.Background(), onboarding)
		require.NoError(t, err)

		savedOnboarding, err := store.GetAccountOnboarding(context.Background(), accountID)
		require.NoError(t, err)
		require.Equal(t, onboarding.SignupFormPending, savedOnboarding.SignupFormPending)
		require.Equal(t, onboarding.OnboardingFlowPending, savedOnboarding.OnboardingFlowPending)
	})
}
