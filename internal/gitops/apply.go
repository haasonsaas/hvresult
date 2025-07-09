package gitops

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// ApplyChanges applies local Vault policy and auth role configurations to Vault.
func ApplyChanges(ctx context.Context, vc *vault.Client, authDirectory, policyDirectory string) error {
	log.Info().Msg("Applying changes to Vault...")

	if err := applyPolicyChanges(ctx, vc, policyDirectory); err != nil {
		return fmt.Errorf("error applying policy changes: %w", err)
	}

	if err := applyAuthChanges(ctx, vc, authDirectory); err != nil {
		return fmt.Errorf("error applying auth changes: %w", err)
	}

	return nil
}

func applyPolicyChanges(ctx context.Context, vc *vault.Client, policyDirectory string) error {
	log.Info().Str("directory", policyDirectory).Msg("Applying policy changes...")

	// Get existing policies from Vault
	existingPolicies, err := vc.Sys().ListPoliciesWithContext(ctx)
	if err != nil {
		return fmt.Errorf("error listing existing policies from Vault: %w", err)
	}

	// Read local policy files
	localPolicies := make(map[string]string)
	err = filepath.WalkDir(policyDirectory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		policyName := d.Name()
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("error reading local policy file %s: %w", path, err)
		}
		localPolicies[policyName] = string(content)
		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking policy directory: %w", err)
	}

	var eg errgroup.Group
	eg.SetLimit(5)

	// Apply/Update policies
	for name, content := range localPolicies {
		name := name
		content := content
		eg.Go(func() error {
			log.Debug().Str("policy", name).Msg("Writing policy to Vault")
			if err := vc.Sys().PutPolicyWithContext(ctx, name, content); err != nil {
				return fmt.Errorf("error writing policy %s to Vault: %w", name, err)
			}
			return nil
		})
	}

	// Delete policies not present locally
	for _, existingPolicy := range existingPolicies {
		existingPolicy := existingPolicy
		// Skip deleting root and default policies
		if existingPolicy == "root" || existingPolicy == "default" {
			log.Debug().Str("policy", existingPolicy).Msg("Skipping deletion of protected policy")
			continue
		}
		if _, exists := localPolicies[existingPolicy]; !exists {
				eg.Go(func() error {
					log.Debug().Str("policy", existingPolicy).Msg("Deleting policy from Vault")
					if err := vc.Sys().DeletePolicyWithContext(ctx, existingPolicy); err != nil {
						return fmt.Errorf("error deleting policy %s from Vault: %w", existingPolicy, err)
					}
					return nil
				})
		}
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	log.Info().Msg("Policy changes applied successfully.")
	return nil
}

func applyAuthChanges(ctx context.Context, vc *vault.Client, authDirectory string) error {
	log.Info().Str("directory", authDirectory).Msg("Applying auth role changes...")

	// Get existing auth mounts from Vault
	mounts, err := vc.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("error listing auth mounts from Vault: %w", err)
	}

	// Iterate over each auth mount
	for mountName, mount := range mounts {
		mountName := strings.TrimSuffix(mountName, "/")
		mount := mount

		log.Debug().Str("mount", mountName).Msg("Processing auth mount")

		// Determine the path to roles/users/groups for this mount type
		var rolePathPrefix string
		switch mount.Type {
		case "aws", "gcp":
			rolePathPrefix = "roles"
		case "azure", "kubernetes", "oidc", "oci", "saml", "approle":
			rolePathPrefix = "role"
		case "kerberos":
			rolePathPrefix = "groups"
		case "ldap", "okta":
			rolePathPrefix = "groups"
		case "radius":
			rolePathPrefix = "users"
		case "token":
			rolePathPrefix = "roles"
		default:
			log.Warn().Str("mount_type", mount.Type).Msg("Unsupported auth mount type, skipping")
			continue
		}

		localMountDir := filepath.Join(authDirectory, mountName, rolePathPrefix)
		log.Debug().Str("local_mount_dir", localMountDir).Msg("Reading local auth roles for mount")

		localRoles := make(map[string]map[string]interface{})
		err = filepath.WalkDir(localMountDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			roleName := d.Name()
			content, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("error reading local auth role file %s: %w", path, err)
			}
			var roleData map[string]interface{}
			if err := json.Unmarshal(content, &roleData); err != nil {
				return fmt.Errorf("error unmarshalling local auth role file %s: %w", path, err)
			}
			localRoles[roleName] = roleData
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("error walking local auth mount directory %s: %w", localMountDir, err)
		}

		// Get existing roles for this mount from Vault
		listPath := fmt.Sprintf("auth/%s/%s", mountName, rolePathPrefix)
		secret, err := vc.Logical().ListWithContext(ctx, listPath)
		if err != nil {
			return fmt.Errorf("error listing existing roles for mount %s from Vault: %w", mountName, err)
		}

		existingRoles := make(map[string]bool)
		if secret != nil && secret.Data != nil {
			if keys, ok := secret.Data["keys"].([]interface{}); ok {
				for _, key := range keys {
					if s, ok := key.(string); ok {
						existingRoles[s] = true
					}
				}
			}
		}

		var egMount errgroup.Group
		egMount.SetLimit(5)

		// Apply/Update roles
		for name, data := range localRoles {
			name := name
			data := data
			egMount.Go(func() error {
				writePath := fmt.Sprintf("auth/%s/%s/%s", mountName, rolePathPrefix, name)
				log.Debug().Str("role", name).Str("path", writePath).Msg("Writing auth role to Vault")
				if _, err := vc.Logical().WriteWithContext(ctx, writePath, data); err != nil {
					return fmt.Errorf("error writing auth role %s to Vault: %w", name, err)
				}
				return nil
			})
		}

		// Delete roles not present locally
		for existingRole := range existingRoles {
			existingRole := existingRole
			if _, exists := localRoles[existingRole]; !exists {
				egMount.Go(func() error {
					deletePath := fmt.Sprintf("auth/%s/%s/%s", mountName, rolePathPrefix, existingRole)
					log.Debug().Str("role", existingRole).Str("path", deletePath).Msg("Deleting auth role from Vault")
					if _, err := vc.Logical().DeleteWithContext(ctx, deletePath); err != nil {
						return fmt.Errorf("error deleting auth role %s from Vault: %w", existingRole, err)
					}
					return nil
				})
			}
		}

		if err := egMount.Wait(); err != nil {
			return err
		}
	}

	log.Info().Msg("Auth role changes applied successfully.")
	return nil
}
