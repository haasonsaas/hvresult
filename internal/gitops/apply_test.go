package gitops_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/threatkey-oss/hvresult/internal/gitops"
	"github.com/threatkey-oss/hvresult/internal/testcluster"
)

func TestApplyChanges(t *testing.T) {
	ctx := context.Background()
	vc := testcluster.NewTestCluster(t)

	tempDir, err := os.MkdirTemp("", "hvresult-apply-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	authDir := filepath.Join(tempDir, "auth")
	policyDir := filepath.Join(tempDir, "sys", "policies", "acl")

	// Create some dummy policy and auth role files
	// Policy 1
	policy1Content := `path "secret/data/foo" { capabilities = ["read"] }`
	policy1Path := filepath.Join(policyDir, "test-policy-1")
	_ = os.MkdirAll(filepath.Dir(policy1Path), 0o755)
	_ = os.WriteFile(policy1Path, []byte(policy1Content), 0o644)

	// Policy 2
	policy2Content := `path "secret/data/bar" { capabilities = ["list"] }`
	policy2Path := filepath.Join(policyDir, "test-policy-2")
	_ = os.MkdirAll(filepath.Dir(policy2Path), 0o755)
	_ = os.WriteFile(policy2Path, []byte(policy2Content), 0o644)

	// Auth Role (example: approle)
	approleRoleContent := `{"token_policies": ["test-policy-1"]}`
	approleRolePath := filepath.Join(authDir, "approle", "role", "test-approle-role")
	_ = os.MkdirAll(filepath.Dir(approleRolePath), 0o755)
	_ = os.WriteFile(approleRolePath, []byte(approleRoleContent), 0o644)

	// Enable approle auth method in Vault
	_ = vc.Sys().EnableAuthWithOptions("approle", &vault.EnableAuthOptions{Type: "approle"})

	// Test initial apply
	err = gitops.ApplyChanges(ctx, vc, authDir, policyDir)
	if err != nil {
		t.Fatalf("initial ApplyChanges failed: %v", err)
	}

	// Verify policies are created
	policy1, err := vc.Sys().GetPolicyWithContext(ctx, "test-policy-1")
	if err != nil || policy1 != policy1Content {
		t.Errorf("policy test-policy-1 not applied correctly: %v, %s", err, policy1)
	}
	policy2, err := vc.Sys().GetPolicyWithContext(ctx, "test-policy-2")
	if err != nil || policy2 != policy2Content {
		t.Errorf("policy test-policy-2 not applied correctly: %v, %s", err, policy2)
	}

	// Verify approle role is created
	approleRole, err := vc.Logical().ReadWithContext(ctx, "auth/approle/role/test-approle-role")
	if err != nil {
		t.Errorf("error reading approle role: %v", err)
	}
	if approleRole == nil || approleRole.Data == nil {
		t.Errorf("approle role is nil or data is nil")
	}
	if policies, ok := approleRole.Data["token_policies"].([]interface{}); !ok || len(policies) == 0 || policies[0] != "test-policy-1" {
		t.Errorf("approle role token_policies not correct: %v", policies)
	}

	// Test update: modify policy 1, add policy 3, delete policy 2
	policy1UpdatedContent := `path "secret/data/foo" { capabilities = ["read", "update"] }`
	_ = os.WriteFile(policy1Path, []byte(policy1UpdatedContent), 0o644)

	policy3Content := `path "secret/data/baz" { capabilities = ["create"] }`
	policy3Path := filepath.Join(policyDir, "test-policy-3")
	_ = os.MkdirAll(filepath.Dir(policy3Path), 0o755)
	_ = os.WriteFile(policy3Path, []byte(policy3Content), 0o644)

	_ = os.Remove(policy2Path)

	// Test update to auth role
	approleRoleUpdatedContent := `{"token_policies": ["test-policy-3"]}`
	_ = os.WriteFile(approleRolePath, []byte(approleRoleUpdatedContent), 0o644)

	err = gitops.ApplyChanges(ctx, vc, authDir, policyDir)
	if err != nil {
		t.Fatalf("update ApplyChanges failed: %v", err)
	}

	// Verify policy 1 is updated
	policy1, err = vc.Sys().GetPolicyWithContext(ctx, "test-policy-1")
	if err != nil || policy1 != policy1UpdatedContent {
		t.Errorf("policy test-policy-1 not updated correctly: %v, %s", err, policy1)
	}

	// Verify policy 2 is deleted
	policiesAfterUpdate, err := vc.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		t.Fatalf("failed to list policies after update: %v", err)
	}
	foundPolicy2 := false
	for _, p := range policiesAfterUpdate {
		if p == "test-policy-2" {
			foundPolicy2 = true
			break
		}
	}
	if foundPolicy2 {
		t.Errorf("policy test-policy-2 not deleted correctly")
	}

	// Verify policy 3 is created
	policy3, err := vc.Sys().GetPolicyWithContext(ctx, "test-policy-3")
	if err != nil || policy3 != policy3Content {
		t.Errorf("policy test-policy-3 not created correctly: %v, %s", err, policy3)
	}

	// Verify approle role is updated
	approleRole, err = vc.Logical().ReadWithContext(ctx, "auth/approle/role/test-approle-role")
	if err != nil {
		t.Errorf("error reading approle role: %v", err)
	}
	if approleRole == nil || approleRole.Data == nil {
		t.Errorf("approle role is nil or data is nil")
	}
	if policies, ok := approleRole.Data["token_policies"].([]interface{}); !ok || len(policies) == 0 || policies[0] != "test-policy-3" {
		t.Errorf("approle role token_policies not correct: %v", policies)
	}

	// Test idempotency: run apply again with no changes
	err = gitops.ApplyChanges(ctx, vc, authDir, policyDir)
	if err != nil {
		t.Fatalf("idempotency test failed: %v", err)
	}

	// Verify state is still correct after idempotency run
	policy1, err = vc.Sys().GetPolicyWithContext(ctx, "test-policy-1")
	if err != nil || policy1 != policy1UpdatedContent {
		t.Errorf("idempotency: policy test-policy-1 not correct: %v, %s", err, policy1)
	}
	policiesAfterIdempotency, err := vc.Sys().ListPoliciesWithContext(ctx)
		if err != nil {
			t.Fatalf("idempotency: failed to list policies: %v", err)
		}
		foundPolicy2Idempotency := false
		for _, p := range policiesAfterIdempotency {
			if p == "test-policy-2" {
				foundPolicy2Idempotency = true
				break
			}
		}
		if foundPolicy2Idempotency {
			t.Errorf("idempotency: policy test-policy-2 not deleted")
		}
	policy3, err = vc.Sys().GetPolicyWithContext(ctx, "test-policy-3")
	if err != nil || policy3 != policy3Content {
		t.Errorf("idempotency: policy test-policy-3 not correct: %v, %s", err, policy3)
	}
	approleRole, err = vc.Logical().ReadWithContext(ctx, "auth/approle/role/test-approle-role")
	if err != nil {
		t.Errorf("idempotency: error reading approle role: %v", err)
	}
	if approleRole == nil || approleRole.Data == nil {
		t.Errorf("idempotency: approle role is nil or data is nil")
	}
	if policies, ok := approleRole.Data["token_policies"].([]interface{}); !ok || len(policies) == 0 || policies[0] != "test-policy-3" {
		t.Errorf("idempotency: approle role token_policies not correct: %v", policies)
	}
}

func TestPolicyDeletion(t *testing.T) {
	ctx := context.Background()
	vc := testcluster.NewTestCluster(t)

	policyName := "test-delete-policy"
	policyContent := `path "secret/data/delete" { capabilities = ["read"] }`

	// Create the policy
	err := vc.Sys().PutPolicyWithContext(ctx, policyName, policyContent)
	if err != nil {
		t.Fatalf("failed to create policy for deletion test: %v", err)
	}

	// Verify it exists
	_, err = vc.Sys().GetPolicyWithContext(ctx, policyName)
	if err != nil {
		t.Fatalf("policy %s not found after creation: %v", policyName, err)
	}

	// Delete the policy
	err = vc.Sys().DeletePolicyWithContext(ctx, policyName)
	if err != nil {
		t.Fatalf("failed to delete policy %s: %v", policyName, err)
	}

	// Verify it's deleted (expect it not to be in the list)
	policies, err := vc.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		t.Fatalf("failed to list policies after deletion: %v", err)
	}
	for _, p := range policies {
		if p == policyName {
			t.Errorf("policy %s found in list after deletion", policyName)
		}
	}
}