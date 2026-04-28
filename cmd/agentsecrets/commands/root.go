package commands

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keychainauth"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
	"fmt"
)

// Version is set at build time via ldflags
var Version = "dev"

var (
	authService      *auth.Service
	workspaceService *workspaces.Service
	apiClient        *api.Client
)

// rootCmd is the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "agentsecrets",
	Short: "Secure secrets management for the AI era",
	Long: lipgloss.JoinVertical(lipgloss.Left,
		"",
		ui.BrandStyle.Render("AgentSecrets"),
		ui.DimStyle.Render("   Zero-knowledge secrets manager for AI-assisted development"),
		"",
		ui.LabelStyle.Render("   Manage secrets across projects, teams, and environments."),
		ui.LabelStyle.Render("   AI assistants can use this tool without seeing secret values."),
		"",
		ui.DimStyle.Render("   Get started:"),
		"   "+ui.BrandStyle.Render("agentsecrets init")+"        "+ui.LabelStyle.Render("Create a new account"),
		"   "+ui.BrandStyle.Render("agentsecrets login")+"       "+ui.LabelStyle.Render("Login to existing account"),
		"   "+ui.BrandStyle.Render("agentsecrets status")+"      "+ui.LabelStyle.Render("Show current session info"),
		"",
	),
	Version: Version,
}

func Execute() error {
	// Ensure keychain-auth socket is closed on exit
	defer keychainauth.Close()

	// Run update check. It's efficient (24h interval) and has a short timeout.
	if res, _ := config.CheckForUpdates(Version); res != nil && res.NewVersionAvailable {
		ui.Banner(fmt.Sprintf("Update Available: %s → %s", res.CurrentVersion, res.LatestVersion))
		ui.Info("Run 'brew upgrade agentsecrets', 'npm install -g @the-17/agentsecrets',")
		ui.Info("or 'pip install agentsecrets-cli' to update.")
		ui.Divider()
		fmt.Println()
	}

	return rootCmd.Execute()
}

func init() {
	// Create the API client with a token provider function.
	apiClient = api.NewClient(func() string {
		return config.GetAccessToken()
	})

	// Create the shared services
	authService = auth.NewService(apiClient)
	workspaceService = workspaces.NewService(apiClient)
	InitProjectService(apiClient)
	InitSecretsService(apiClient)

	// Register all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(statusCmd)
	
	// Add auth middleware to commands that require it
	workspaceCmd.PersistentPreRunE = authService.EnsureAuth
	projectCmd.PersistentPreRunE = authService.EnsureAuth
	environmentCmd.PersistentPreRunE = authService.EnsureAuth

	// Commands that read secrets need both auth AND keychain-auth session.
	// The keychainAuthMiddleware chains EnsureAuth → keychainauth.Init().
	secretsCmd.PersistentPreRunE = keychainAuthMiddleware
	callCmd.PersistentPreRunE = keychainAuthMiddleware

	rootCmd.AddCommand(workspaceCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(logCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(callCmd)
	rootCmd.AddCommand(environmentCmd)
	rootCmd.AddCommand(NewEnvCmd())
	rootCmd.AddCommand(NewExecCmd())
}

// keychainAuthMiddleware is a PersistentPreRunE that ensures both:
// 1. The user is authenticated (EnsureAuth)
// 2. A keychain-auth session is established (keychainauth.Init)
//
// If keychain-auth is not installed or not running, it performs automatic
// setup with a spinner and explanatory message so the user understands
// what is happening and why.
func keychainAuthMiddleware(cmd *cobra.Command, args []string) error {
	// Step 1: Ensure the user is logged in
	if err := authService.EnsureAuth(cmd, args); err != nil {
		return err
	}

	// Step 2: Skip if session already established (e.g. parent command already ran this)
	if keychainauth.IsInitialized() {
		return nil
	}

	// Step 3: If keychain-auth isn't available, run auto-setup
	if !keychainauth.IsAvailable() {
		fmt.Println()
		ui.Info("Setting up keychain-auth — this secures your secrets with process-level verification.")
		ui.Info("This is a one-time setup that runs automatically.")
		fmt.Println()

		if err := ui.Spinner("Installing and configuring keychain-auth...", func() error {
			return keychainauth.AutoSetup()
		}); err != nil {
			ui.Error("keychain-auth setup failed: " + err.Error())
			fmt.Println()
			ui.Info("You can set it up manually:")
			ui.Info("  brew install The-17/tap/keychain-auth")
			ui.Info("  keychain-auth start")
			fmt.Println()
			return fmt.Errorf("keychain-auth is required for secret operations")
		}

		ui.Success("keychain-auth configured successfully.")
		fmt.Println()
	}

	// Step 4: Establish the session
	if err := keychainauth.Init(); err != nil {
		return fmt.Errorf("%s", keychainauth.UserMessage(err))
	}

	return nil
}
