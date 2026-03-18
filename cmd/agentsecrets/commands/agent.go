package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var agentService *agents.Service

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agent identities and tokens",
	Long:  "Manage agent identities and tokens for the current workspace.\n\nAgents are named identities that can be bound to credential calls.\nEvery call through the proxy is logged with the calling agent's identity.\nIssued tokens provide cryptographically verified identity.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := authService.EnsureAuth(cmd, args); err != nil {
			return err
		}
		// Init agent service if not already
		if agentService == nil {
			agentService = agents.NewService(apiClient)
		}
		return nil
	},
}

var agentRegisterCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register a new agent and issue its first token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		projectID, _ := cmd.Flags().GetString("project")
		label, _ := cmd.Flags().GetString("label")
		expires, _ := cmd.Flags().GetString("expires")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		resp, err := agentService.Register(agents.RegisterRequest{
			Name:        name,
			WorkspaceID: workspaceID,
			ProjectID:   projectID,
			Label:       label,
			ExpiresIn:   expires,
		})
		if err != nil {
			return fmt.Errorf("agent registration failed: %w", err)
		}

		scope := "workspace"
		if projectID != "" {
			scope = projectID
		}

		fmt.Println("\n" + ui.SuccessStyle.Render("Agent registered"))
		fmt.Printf("  Name     %s\n", resp.Agent.Name)
		fmt.Printf("  Scope    %s\n", scope)
		fmt.Printf("  Token    %s\n", resp.Token)
		if resp.ExpiresAt != nil {
			fmt.Printf("  Expires  %s\n", resp.ExpiresAt.Format("2006-01-02"))
		}

		fmt.Println("\n" + ui.WarningStyle.Render("Store this token securely. It will not be shown again."))
		fmt.Printf("To use it: export AS_AGENT_TOKEN=%s\n\n", resp.Token)
		return nil
	},
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectID, _ := cmd.Flags().GetString("project")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		list, err := agentService.List(workspaceID, projectID)
		if err != nil {
			return fmt.Errorf("failed to list agents: %w", err)
		}

		if len(list) == 0 {
			fmt.Println(ui.DimStyle.Render("No agents found."))
			return nil
		}

		// Header
		fmt.Printf("%-20s %-15s %-8s %-25s %s\n", "AGENT", "SCOPE", "TOKENS", "LAST USED", "REGISTERED")
		for _, a := range list {
			scope := "workspace"
			if a.ProjectID != nil {
				scope = *a.ProjectID
			}
			lastUsed := "never"
			if a.LastUsed != nil {
				lastUsed = a.LastUsed.Format("2006-01-02 15:04 UTC")
			}
			registered := a.CreatedAt.Format("2006-01-02")
			fmt.Printf("%-20s %-15s %-8d %-25s %s\n", a.Name, scope, a.TokenCount, lastUsed, registered)
		}
		return nil
	},
}

var agentTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage agent tokens",
}

var agentTokenIssueCmd = &cobra.Command{
	Use:   "issue <name>",
	Short: "Issue a new token for an existing agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		label, _ := cmd.Flags().GetString("label")
		expires, _ := cmd.Flags().GetString("expires")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		agent, err := agentService.GetByName(workspaceID, name)
		if err != nil {
			return err
		}

		resp, err := agentService.TokenIssue(workspaceID, agent.ID, agents.IssueTokenRequest{
			Label:     label,
			ExpiresIn: expires,
		})
		if err != nil {
			return fmt.Errorf("token issuance failed: %w", err)
		}

		fmt.Println("\n" + ui.SuccessStyle.Render("Token issued"))
		fmt.Printf("  Agent    %s\n", name)
		fmt.Printf("  Token    %s\n", resp.Token)
		if resp.Label != "" {
			fmt.Printf("  Label    %s\n", resp.Label)
		}
		if resp.ExpiresAt != nil {
			fmt.Printf("  Expires  %s\n", resp.ExpiresAt.Format("2006-01-02"))
		}
		fmt.Println("\n" + ui.WarningStyle.Render("Store this token securely. It will not be shown again."))
		return nil
	},
}

var agentTokenListCmd = &cobra.Command{
	Use:   "list <name>",
	Short: "List tokens for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		agent, err := agentService.GetByName(workspaceID, name)
		if err != nil {
			return err
		}

		tokens, err := agentService.TokenList(workspaceID, agent.ID)
		if err != nil {
			return fmt.Errorf("failed to list tokens: %w", err)
		}

		if len(tokens) == 0 {
			fmt.Println(ui.DimStyle.Render("No tokens found for agent."))
			return nil
		}

		fmt.Printf("%-20s %-15s %-15s %-25s %s\n", "TOKEN ID", "LABEL", "EXPIRES", "LAST USED", "STATUS")
		for _, t := range tokens {
			label := t.Label
			if label == "" {
				label = "(none)"
			}
			expires := "(none)"
			if t.ExpiresAt != nil {
				expires = t.ExpiresAt.Format("2006-01-02")
			}
			lastUsed := "never"
			if t.LastUsed != nil {
				lastUsed = t.LastUsed.Format("2006-01-02 15:04 UTC")
			}
			fmt.Printf("%-20s %-15s %-15s %-25s %s\n", t.ID, label, expires, lastUsed, t.Status)
		}
		return nil
	},
}

var agentTokenRevokeCmd = &cobra.Command{
	Use:   "revoke [token_id]",
	Short: "Revoke one or all tokens for an agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName, _ := cmd.Flags().GetString("agent")
		all, _ := cmd.Flags().GetBool("all")
		confirm, _ := cmd.Flags().GetBool("confirm")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		if !all && len(args) == 0 {
			return fmt.Errorf("must specify <token_id> or use --all with --agent <name>")
		}

		if all {
			if agentName == "" {
				return fmt.Errorf("--agent must be provided when using --all")
			}
			if !confirm {
				fmt.Printf("Revoke all active tokens for %s? [y/N] ", agentName)
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					fmt.Println("Aborted.")
					os.Exit(0)
				}
			}
			
			agent, err := agentService.GetByName(workspaceID, agentName)
			if err != nil {
				return err
			}

			err = agentService.TokenRevokeAll(workspaceID, agent.ID)
			if err != nil {
				return fmt.Errorf("failed to revoke tokens: %w", err)
			}
			fmt.Println("\nTokens revoked.")
			fmt.Println("Propagation to active proxy instances: up to 60 seconds.")
			return nil
		}

		// Revoke single token
		tokenID := args[0]
		if agentName == "" {
			return fmt.Errorf("please provide the --agent <name> for the token")
		}
		
		if !confirm {
			fmt.Printf("Revoke token %s for agent %s? [y/N] ", tokenID, agentName)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Aborted.")
				os.Exit(0)
			}
		}

		agent, err := agentService.GetByName(workspaceID, agentName)
		if err != nil {
			return err
		}

		err = agentService.TokenRevoke(workspaceID, agent.ID, tokenID)
		if err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
		fmt.Println("\nToken revoked.")
		fmt.Println("Propagation to active proxy instances: up to 60 seconds.")
		return nil
	},
}

var agentDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an agent registration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		confirm, _ := cmd.Flags().GetBool("confirm")

		workspaceID := config.GetSelectedWorkspaceID()
		if workspaceID == "" {
			return fmt.Errorf("no workspace selected — run 'agentsecrets workspace switch' first")
		}

		if !confirm {
			fmt.Printf("Delete agent %q and revoke all active tokens? [y/N] ", name)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Aborted.")
				os.Exit(0)
			}
		}

		agent, err := agentService.GetByName(workspaceID, name)
		if err != nil {
			return err
		}

		err = agentService.Delete(workspaceID, agent.ID)
		if err != nil {
			return fmt.Errorf("failed to delete agent: %w", err)
		}
		fmt.Println("\nAgent deleted.")
		return nil
	},
}

func init() {
	// Root subcommands
	agentCmd.AddCommand(agentRegisterCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentTokenCmd)
	agentCmd.AddCommand(agentDeleteCmd)

	// Token subcommands
	agentTokenCmd.AddCommand(agentTokenIssueCmd)
	agentTokenCmd.AddCommand(agentTokenListCmd)
	agentTokenCmd.AddCommand(agentTokenRevokeCmd)

	// Flags for register
	agentRegisterCmd.Flags().StringP("project", "p", "", "scope to a specific project")
	agentRegisterCmd.Flags().StringP("label", "l", "", "human label for the first token")
	agentRegisterCmd.Flags().StringP("expires", "e", "", "token expiry (e.g. 30d, 90d)")
	agentRegisterCmd.Flags().Bool("output-json", false, "output as JSON instead of formatted text") // Add this if needed later

	// Flags for list
	agentListCmd.Flags().StringP("project", "p", "", "filter to a specific project")
	agentListCmd.Flags().Bool("output-json", false, "output as JSON")

	// Flags for token issue
	agentTokenIssueCmd.Flags().StringP("label", "l", "", "label for this token")
	agentTokenIssueCmd.Flags().StringP("expires", "e", "", "token expiry (e.g. 30d, 90d)")
	agentTokenIssueCmd.Flags().Bool("output-json", false, "output as JSON")

	// Flags for token list
	agentTokenListCmd.Flags().Bool("output-json", false, "output as JSON")

	// Flags for token revoke
	agentTokenRevokeCmd.Flags().StringP("agent", "a", "", "used with --all or specific token to identify the agent")
	agentTokenRevokeCmd.Flags().Bool("all", false, "revoke all active tokens for the agent")
	agentTokenRevokeCmd.Flags().Bool("confirm", false, "skip confirmation prompt")

	// Flags for delete
	agentDeleteCmd.Flags().Bool("confirm", false, "skip confirmation prompt")
}
