package profilemanager

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The daemon reads the active profile state on every RPC (the authz gate
// resolves the request's target against it) while a profile switch writes it.
// The write is a temp file renamed over the real one, and Windows refuses to
// replace a file another handle holds open, so an unserialized read fails the
// switch with "Access is denied". Every caller goes through ServiceManager, so
// serializing there is what keeps the two apart.
func TestActiveProfileState_ReadsDoNotBreakAConcurrentWrite(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())
			require.NoError(t, sm.SetActiveProfileStateToDefault())

			// Two IDs, so a reader either sees one whole state or the other
			// and never a half-written file.
			const switched = ID("0123456789abcdef0123456789abcdef")
			const rounds = 50

			var wg sync.WaitGroup
			errs := make(chan error, 128)

			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for r := 0; r < rounds; r++ {
						state, err := sm.GetActiveProfileState()
						if err != nil {
							errs <- fmt.Errorf("read: %w", err)
							return
						}
						if state.ID != defaultProfileName && state.ID != switched {
							errs <- fmt.Errorf("read: active profile is %q, which no writer wrote", state.ID)
							return
						}
					}
				}()
			}

			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for r := 0; r < rounds; r++ {
						id := switched
						if r%2 == 0 {
							id = defaultProfileName
						}
						if err := sm.SetActiveProfileState(&ActiveProfileState{ID: id}); err != nil {
							errs <- fmt.Errorf("switch: %w", err)
							return
						}
					}
				}()
			}

			wg.Wait()
			close(errs)

			for err := range errs {
				assert.NoError(t, err, "a switch and a read of the active profile state must not collide")
			}

			state, err := sm.GetActiveProfileState()
			require.NoError(t, err)
			assert.Contains(t, []ID{defaultProfileName, switched}, state.ID,
				"the file holds whichever switch landed last, not a mix of the two")
		})
	})
}

// The lock is the whole mechanism, so each entry point has to take it: one
// that reads or writes the file outside it can still collide with a switch.
// Holding it here must block every one of them.
func TestActiveProfileState_EntryPointsTakeTheLock(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())

			for _, tc := range []struct {
				name string
				call func()
			}{
				{"GetActiveProfileState", func() { _, _ = sm.GetActiveProfileState() }},
				{"SetActiveProfileStateToDefault", func() { _ = sm.SetActiveProfileStateToDefault() }},
				{"SetActiveProfileState", func() {
					_ = sm.SetActiveProfileState(&ActiveProfileState{ID: defaultProfileName})
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					done := make(chan struct{})
					activeStateMu.Lock()
					go func() {
						defer close(done)
						tc.call()
					}()

					select {
					case <-done:
						activeStateMu.Unlock()
						t.Fatalf("%s ran while activeStateMu was held, so it can touch the state file during a switch", tc.name)
					case <-time.After(50 * time.Millisecond):
					}

					activeStateMu.Unlock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatalf("%s did not finish after the lock was released", tc.name)
					}
				})
			}
		})
	})
}
