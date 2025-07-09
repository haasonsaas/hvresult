package gitops_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/threatkey-oss/hvresult/internal/gitops"
	"github.com/threatkey-oss/hvresult/internal/testcluster"
)

func TestDownloadAuthUserpass(t *testing.T) {
	ctx := context.Background()
	vc := testcluster.NewTestCluster(t)

	tempDir, err := os.MkdirTemp("", "hvresult-download-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	authDir := filepath.Join(tempDir, "auth")

	// Enable Userpass auth method
	err = vc.Sys().EnableAuthWithOptions("userpass", &vault.EnableAuthOptions{Type: "userpass"})
	if err != nil {
		t.Fatalf("failed to enable Userpass auth method: %v", err)
	}

	// Create a Userpass user
	const userpassUserName = "test-user"
	userpassUserPath := "auth/userpass/users/" + userpassUserName
	userpassUserData := map[string]interface{}{
		"password": "test-password",
		"policies": []string{"default"},
	}
	_, err = vc.Logical().Write(userpassUserPath, userpassUserData)
	if err != nil {
		t.Fatalf("failed to create Userpass user: %v", err)
	}

	// Download auth configurations
	err = gitops.DownloadAuth(ctx, vc, authDir)
	if err != nil {
		t.Fatalf("DownloadAuth failed: %v", err)
	}

	// Verify downloaded Userpass user
	downloadedUserPath := filepath.Join(authDir, "userpass", "users", userpassUserName)
	_, err = os.Stat(downloadedUserPath)
	if os.IsNotExist(err) {
		t.Errorf("downloaded Userpass user file not found at %s", downloadedUserPath)
	}

	content, err := os.ReadFile(downloadedUserPath)
	if err != nil {
		t.Fatalf("failed to read downloaded Userpass user file: %v", err)
	}

	var downloadedData map[string]interface{}
	err = json.Unmarshal(content, &downloadedData)
	if err != nil {
		t.Fatalf("failed to unmarshal downloaded Userpass user data: %v", err)
	}

	// Compare relevant fields
	if downloadedData["policies"] == nil {
		t.Errorf("downloaded Userpass user missing policies")
	}
	if policies, ok := downloadedData["policies"].([]interface{}); !ok || len(policies) == 0 || policies[0] != "default" {
		t.Errorf("downloaded Userpass user policies not correct: %v", policies)
	}
}
