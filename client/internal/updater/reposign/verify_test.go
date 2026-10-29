package reposign

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test ArtifactVerify construction

func TestArtifactVerify_Construction(t *testing.T) {
	// Generate test root key
	rootKey, _, rootPubPEM, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	rootPubKey, _, err := parsePublicKey(rootPubPEM, tagRootPublic)
	require.NoError(t, err)

	keysBaseURL := "http://localhost:8080/artifact-signatures"

	av, err := newArtifactVerify(keysBaseURL, []PublicKey{rootPubKey})
	require.NoError(t, err)

	assert.NotNil(t, av)
	assert.NotEmpty(t, av.rootKeys)
	assert.Equal(t, keysBaseURL, av.keysBaseURL.String())

	// Verify root key structure
	assert.NotEmpty(t, av.rootKeys[0].Key)
	assert.Equal(t, rootKey.Metadata.ID, av.rootKeys[0].Metadata.ID)
	assert.False(t, av.rootKeys[0].Metadata.CreatedAt.IsZero())
}

func TestArtifactVerify_MultipleRootKeys(t *testing.T) {
	// Generate multiple test root keys
	rootKey1, _, rootPubPEM1, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)
	rootPubKey1, _, err := parsePublicKey(rootPubPEM1, tagRootPublic)
	require.NoError(t, err)

	rootKey2, _, rootPubPEM2, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)
	rootPubKey2, _, err := parsePublicKey(rootPubPEM2, tagRootPublic)
	require.NoError(t, err)

	keysBaseURL := "http://localhost:8080/artifact-signatures"

	av, err := newArtifactVerify(keysBaseURL, []PublicKey{rootPubKey1, rootPubKey2})
	assert.NoError(t, err)
	assert.Len(t, av.rootKeys, 2)
	assert.NotEqual(t, rootKey1.Metadata.ID, rootKey2.Metadata.ID)
}

// Test Verify workflow with mock HTTP server

func TestArtifactVerify_FullWorkflow(t *testing.T) {
	// Create temporary test directory
	tempDir := t.TempDir()

	// Step 1: Generate root key
	rootKey, _, _, err := GenerateRootKey(10 * 365 * 24 * time.Hour)
	require.NoError(t, err)

	// Step 2: Generate artifact key
	artifactKey, _, artifactPubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	artifactPubKey, err := ParseArtifactPubKey(artifactPubPEM)
	require.NoError(t, err)

	// Step 3: Create revocation list
	revocationData, revocationSig, err := CreateRevocationList(*rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Step 4: Bundle artifact keys
	artifactKeysBundle, artifactKeysSig, err := BundleArtifactKeys(rootKey, []PublicKey{artifactPubKey})
	require.NoError(t, err)

	// Step 5: Create test artifact
	artifactPath := filepath.Join(tempDir, "test-artifact.bin")
	artifactData := []byte("This is test artifact data for verification")
	err = os.WriteFile(artifactPath, artifactData, 0644)
	require.NoError(t, err)

	// Step 6: Sign artifact
	artifactSigData, err := SignData(*artifactKey, artifactData)
	require.NoError(t, err)

	// Step 7: Setup mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact-signatures/keys/" + revocationFileName:
			_, _ = w.Write(revocationData)
		case "/artifact-signatures/keys/" + revocationSignFileName:
			_, _ = w.Write(revocationSig)
		case "/artifact-signatures/keys/" + artifactPubKeysFileName:
			_, _ = w.Write(artifactKeysBundle)
		case "/artifact-signatures/keys/" + artifactPubKeysSigFileName:
			_, _ = w.Write(artifactKeysSig)
		case "/artifacts/v1.0.0/test-artifact.bin":
			_, _ = w.Write(artifactData)
		case "/artifact-signatures/tag/v1.0.0/test-artifact.bin.sig":
			_, _ = w.Write(artifactSigData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Step 8: Create ArtifactVerify with test root key
	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	av, err := newArtifactVerify(server.URL+"/artifact-signatures", []PublicKey{rootPubKey})
	require.NoError(t, err)

	// Step 9: Verify artifact
	ctx := context.Background()
	err = av.Verify(ctx, "1.0.0", artifactPath)
	assert.NoError(t, err)
}

func TestArtifactVerify_InvalidRevocationList(t *testing.T) {
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "test.bin")
	err := os.WriteFile(artifactPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Setup server with invalid revocation list
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact-signatures/keys/" + revocationFileName:
			_, _ = w.Write([]byte("invalid data"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	av, err := newArtifactVerify(server.URL+"/artifact-signatures", []PublicKey{rootPubKey})
	require.NoError(t, err)

	ctx := context.Background()
	err = av.Verify(ctx, "1.0.0", artifactPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load revocation list")
}

func TestArtifactVerify_MissingArtifactFile(t *testing.T) {
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	// Create revocation list
	revocationData, revocationSig, err := CreateRevocationList(*rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	artifactKey, _, artifactPubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	artifactPubKey, err := ParseArtifactPubKey(artifactPubPEM)
	require.NoError(t, err)

	artifactKeysBundle, artifactKeysSig, err := BundleArtifactKeys(rootKey, []PublicKey{artifactPubKey})
	require.NoError(t, err)

	// Create signature for non-existent file
	testData := []byte("test")
	artifactSigData, err := SignData(*artifactKey, testData)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact-signatures/keys/" + revocationFileName:
			_, _ = w.Write(revocationData)
		case "/artifact-signatures/keys/" + revocationSignFileName:
			_, _ = w.Write(revocationSig)
		case "/artifact-signatures/keys/" + artifactPubKeysFileName:
			_, _ = w.Write(artifactKeysBundle)
		case "/artifact-signatures/keys/" + artifactPubKeysSigFileName:
			_, _ = w.Write(artifactKeysSig)
		case "/artifact-signatures/tag/v1.0.0/missing.bin.sig":
			_, _ = w.Write(artifactSigData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	av, err := newArtifactVerify(server.URL+"/artifact-signatures", []PublicKey{rootPubKey})
	require.NoError(t, err)

	ctx := context.Background()
	err = av.Verify(ctx, "1.0.0", "file.bin")
	assert.Error(t, err)
}

func TestArtifactVerify_ServerUnavailable(t *testing.T) {
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "test.bin")
	err := os.WriteFile(artifactPath, []byte("test"), 0644)
	require.NoError(t, err)

	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	// Use URL that doesn't exist
	av, err := newArtifactVerify("http://localhost:19999/keys", []PublicKey{rootPubKey})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = av.Verify(ctx, "1.0.0", artifactPath)
	assert.Error(t, err)
}

func TestArtifactVerify_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()
	artifactPath := filepath.Join(tempDir, "test.bin")
	err := os.WriteFile(artifactPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte("data"))
	}))
	defer server.Close()

	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	av, err := newArtifactVerify(server.URL, []PublicKey{rootPubKey})
	require.NoError(t, err)

	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err = av.Verify(ctx, "1.0.0", artifactPath)
	assert.Error(t, err)
}

func TestArtifactVerify_WithRevocation(t *testing.T) {
	tempDir := t.TempDir()

	// Generate root key
	rootKey, _, _, err := GenerateRootKey(10 * 365 * 24 * time.Hour)
	require.NoError(t, err)

	// Generate two artifact keys
	artifactKey1, _, artifactPubPEM1, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	artifactPubKey1, err := ParseArtifactPubKey(artifactPubPEM1)
	require.NoError(t, err)

	_, _, artifactPubPEM2, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	artifactPubKey2, err := ParseArtifactPubKey(artifactPubPEM2)
	require.NoError(t, err)

	// Create revocation list with first key revoked
	emptyRevocation, _, err := CreateRevocationList(*rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	parsedRevocation, err := ParseRevocationList(emptyRevocation)
	require.NoError(t, err)

	revocationData, revocationSig, err := ExtendRevocationList(*rootKey, *parsedRevocation, artifactPubKey1.Metadata.ID, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Bundle both keys
	artifactKeysBundle, artifactKeysSig, err := BundleArtifactKeys(rootKey, []PublicKey{artifactPubKey1, artifactPubKey2})
	require.NoError(t, err)

	// Create artifact signed by revoked key
	artifactPath := filepath.Join(tempDir, "test.bin")
	artifactData := []byte("test data")
	err = os.WriteFile(artifactPath, artifactData, 0644)
	require.NoError(t, err)

	artifactSigData, err := SignData(*artifactKey1, artifactData)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact-signatures/keys/" + revocationFileName:
			_, _ = w.Write(revocationData)
		case "/artifact-signatures/keys/" + revocationSignFileName:
			_, _ = w.Write(revocationSig)
		case "/artifact-signatures/keys/" + artifactPubKeysFileName:
			_, _ = w.Write(artifactKeysBundle)
		case "/artifact-signatures/keys/" + artifactPubKeysSigFileName:
			_, _ = w.Write(artifactKeysSig)
		case "/artifact-signatures/tag/v1.0.0/test.bin.sig":
			_, _ = w.Write(artifactSigData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	av, err := newArtifactVerify(server.URL+"/artifact-signatures", []PublicKey{rootPubKey})
	require.NoError(t, err)

	ctx := context.Background()
	err = av.Verify(ctx, "1.0.0", artifactPath)
	// Should fail because the signing key is revoked
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no signing Key found")
}

func TestArtifactVerify_ValidWithSecondKey(t *testing.T) {
	tempDir := t.TempDir()

	// Generate root key
	rootKey, _, _, err := GenerateRootKey(10 * 365 * 24 * time.Hour)
	require.NoError(t, err)

	// Generate two artifact keys
	_, _, artifactPubPEM1, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	artifactPubKey1, err := ParseArtifactPubKey(artifactPubPEM1)
	require.NoError(t, err)

	artifactKey2, _, artifactPubPEM2, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	artifactPubKey2, err := ParseArtifactPubKey(artifactPubPEM2)
	require.NoError(t, err)

	// Create revocation list with first key revoked
	emptyRevocation, _, err := CreateRevocationList(*rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	parsedRevocation, err := ParseRevocationList(emptyRevocation)
	require.NoError(t, err)

	revocationData, revocationSig, err := ExtendRevocationList(*rootKey, *parsedRevocation, artifactPubKey1.Metadata.ID, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Bundle both keys
	artifactKeysBundle, artifactKeysSig, err := BundleArtifactKeys(rootKey, []PublicKey{artifactPubKey1, artifactPubKey2})
	require.NoError(t, err)

	// Create artifact signed by second key (not revoked)
	artifactPath := filepath.Join(tempDir, "test.bin")
	artifactData := []byte("test data")
	err = os.WriteFile(artifactPath, artifactData, 0644)
	require.NoError(t, err)

	artifactSigData, err := SignData(*artifactKey2, artifactData)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact-signatures/keys/" + revocationFileName:
			_, _ = w.Write(revocationData)
		case "/artifact-signatures/keys/" + revocationSignFileName:
			_, _ = w.Write(revocationSig)
		case "/artifact-signatures/keys/" + artifactPubKeysFileName:
			_, _ = w.Write(artifactKeysBundle)
		case "/artifact-signatures/keys/" + artifactPubKeysSigFileName:
			_, _ = w.Write(artifactKeysSig)
		case "/artifact-signatures/tag/v1.0.0/test.bin.sig":
			_, _ = w.Write(artifactSigData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	av, err := newArtifactVerify(server.URL+"/artifact-signatures", []PublicKey{rootPubKey})
	require.NoError(t, err)

	ctx := context.Background()
	err = av.Verify(ctx, "1.0.0", artifactPath)
	// Should succeed because second key is not revoked
	assert.NoError(t, err)
}

func TestArtifactVerify_TamperedArtifact(t *testing.T) {
	tempDir := t.TempDir()

	// Generate root key and artifact key
	rootKey, _, _, err := GenerateRootKey(10 * 365 * 24 * time.Hour)
	require.NoError(t, err)

	artifactKey, _, artifactPubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	artifactPubKey, err := ParseArtifactPubKey(artifactPubPEM)
	require.NoError(t, err)

	// Create revocation list
	revocationData, revocationSig, err := CreateRevocationList(*rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Bundle keys
	artifactKeysBundle, artifactKeysSig, err := BundleArtifactKeys(rootKey, []PublicKey{artifactPubKey})
	require.NoError(t, err)

	// Sign original data
	originalData := []byte("original data")
	artifactSigData, err := SignData(*artifactKey, originalData)
	require.NoError(t, err)

	// Write tampered data to file
	artifactPath := filepath.Join(tempDir, "test.bin")
	tamperedData := []byte("tampered data")
	err = os.WriteFile(artifactPath, tamperedData, 0644)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifact-signatures/keys/" + revocationFileName:
			_, _ = w.Write(revocationData)
		case "/artifact-signatures/keys/" + revocationSignFileName:
			_, _ = w.Write(revocationSig)
		case "/artifact-signatures/keys/" + artifactPubKeysFileName:
			_, _ = w.Write(artifactKeysBundle)
		case "/artifact-signatures/keys/" + artifactPubKeysSigFileName:
			_, _ = w.Write(artifactKeysSig)
		case "/artifact-signatures/tag/v1.0.0/test.bin.sig":
			_, _ = w.Write(artifactSigData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rootPubKey := PublicKey{
		Key:      rootKey.Key.Public().(ed25519.PublicKey),
		Metadata: rootKey.Metadata,
	}

	av, err := newArtifactVerify(server.URL+"/artifact-signatures", []PublicKey{rootPubKey})
	require.NoError(t, err)

	ctx := context.Background()
	err = av.Verify(ctx, "1.0.0", artifactPath)
	// Should fail because artifact was tampered
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to validate artifact")
}

// Test URL validation

func TestArtifactVerify_URLParsing(t *testing.T) {
	tests := []struct {
		name        string
		keysBaseURL string
		expectError bool
	}{
		{
			name:        "Valid HTTP URL",
			keysBaseURL: "http://example.com/artifact-signatures",
			expectError: false,
		},
		{
			name:        "Valid HTTPS URL",
			keysBaseURL: "https://example.com/artifact-signatures",
			expectError: false,
		},
		{
			name:        "URL with port",
			keysBaseURL: "http://localhost:8080/artifact-signatures",
			expectError: false,
		},
		{
			name:        "Invalid URL",
			keysBaseURL: "://invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newArtifactVerify(tt.keysBaseURL, nil)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
