package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func init() {
	rootCmd.AddCommand(validateCmd)
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "validate configuration file",
	Run:   runValidate,
}

func runValidate(cmd *cobra.Command, args []string) {
	initConfig()
	var vc config.ViperConfig
	viper.Unmarshal(&vc)
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	verbose, _ := cmd.Flags().GetBool("verbose")

	for _, rule := range cfg.Rules {
		if len(rule.Validate.TruePositive) == 0 {
			continue
		}
		singleRuleConfig := config.Config{}
		singleRuleConfig.Rules = append(singleRuleConfig.Rules, rule)
		for _, tp := range rule.Validate.TruePositive {
			findings := detect.DetectFindings(
				singleRuleConfig, []byte(tp), "validate", "")
			if verbose {
				for _, f := range findings {
					printFinding(f)
				}
			}
			if len(findings) != 1 {
				log.Warn().Msgf("%s expected true positive for \"%s\", but found %d true positives", rule.RuleID, tp, len(findings))
			} else {
				log.Info().Msgf("%-10v ok", rule.RuleID)
			}
		}
	}
}
func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}
