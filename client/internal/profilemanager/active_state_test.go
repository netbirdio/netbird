package profilemanager

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression test: a concurrent Get and Set of the ActiveProfileState will
// fail on Windows since the write is a temp file renamed over an open file.
// Windows will refuse to replace a file another handle holds open by default.
func TestActiveProfileState_ReadsDoNotBreakAConcurrentWrite(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			require.NoError(t, sm.CreateDefaultProfile())
			require.NoError(t, sm.SetActiveProfileStateToDefault())

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
						if err := sm.SetActiveProfileState(&ActiveProfileState{ID: id, Username: "testuser"}); err != nil {
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
