package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Concurrent writers share one temporary file name, so each must finish its write and
// rename before the next starts, and none may lose its update to an exclusive-create error.
func TestWriteSSHConfigConcurrent(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{sshConfigDir: dir, sshConfigFile: "99-netbird.conf"}

	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- m.writeSSHConfig(fmt.Sprintf("Host writer-%d\n", i))
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err, "no writer may fail because another holds the temporary file")
	}

	data, err := os.ReadFile(filepath.Join(dir, "99-netbird.conf"))
	require.NoError(t, err)
	assert.Regexp(t, `^Host writer-\d+\n$`, string(data), "the file holds exactly one writer's content")
	assert.NoFileExists(t, filepath.Join(dir, "99-netbird.conf.tmp"), "the temporary file is renamed away")
}
