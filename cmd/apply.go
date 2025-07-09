/*
Copyright © 2024 ThreatKey, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package cmd

import (
	"context"
	"path/filepath"

	vault "github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/threatkey-oss/hvresult/internal"
	"github.com/threatkey-oss/hvresult/internal/gitops"
)

// applyCmd represents the apply command
var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply Vault policy and auth roles from a local directory to Vault",
	Long: `This command reads Vault policy and auth role configurations from a local
directory and applies them to the Vault server. It can be used to synchronize
the state of your Vault server with a GitOps repository.`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			ctx          = context.Background()
			_f           = cmd.Flags()
			directory, _ = _f.GetString("directory")
		)

		vc, err := vault.NewClient(vault.DefaultConfig())
		if err != nil {
			log.Fatal().Err(internal.VaultAPIError(err)).Msg("error creating Vault client")
		}

		if err := gitops.ApplyChanges(ctx, vc, filepath.Join(directory, "auth"), filepath.Join(directory, "sys", "policies", "acl")); err != nil {
			log.Fatal().Err(internal.VaultAPIError(err)).Msg("error applying changes to Vault")
		}
		log.Info().Msg("Successfully applied changes to Vault.")
	},
}

func init() {
	gitopsCmd.AddCommand(applyCmd)
}
