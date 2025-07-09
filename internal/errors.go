package internal

import (
	"fmt"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// VaultAPIError provides more user-friendly messages for common Vault API errors.
func VaultAPIError(err error) error {
	if err == nil {
		return nil
	}

	// Check for Vault API errors
	if apiErr, ok := err.(*vault.ResponseError); ok {
		if len(apiErr.Errors) > 0 {
			// Join multiple Vault API errors
			return fmt.Errorf("Vault API error: %s", strings.Join(apiErr.Errors, "; "))
		}
	}

	// Check for common network/connection errors
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		return fmt.Errorf("Vault connection error: %s. Ensure VAULT_ADDR is correct and Vault is running.", err.Error())
	}

	// Generic fallback
	return fmt.Errorf("Vault operation failed: %w", err)
}
