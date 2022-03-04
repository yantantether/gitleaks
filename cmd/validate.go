package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"runtime"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var Blue = "\033[34m"
var Purple = "\033[35m"
var Cyan = "\033[36m"
var Gray = "\033[37m"
var White = "\033[97m"

func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().String("rule-id", "", "rule-id to validate")
	if runtime.GOOS == "windows" {
		Reset = ""
		Red = ""
		Green = ""
		Yellow = ""
		Blue = ""
		Purple = ""
		Cyan = ""
		Gray = ""
		White = ""
	}
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
	ruleID, _ := cmd.Flags().GetString("rule-id")

	const padding = 3
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, '.', tabwriter.TabIndent)

	for _, rule := range cfg.Rules {
		if ruleID != "" && ruleID != rule.RuleID {
			continue
		}
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
				fmt.Fprintf(w, "%s true positive %s\t%sfailed%s\n", rule.RuleID, tp, Red, Reset)
			} else {
				fmt.Fprintf(w, "%s true positive %s\t%sok%s\n", rule.RuleID, tp, Green, Reset)
			}
		}
		for _, fp := range rule.Validate.FalsePositive {
			findings := detect.DetectFindings(
				singleRuleConfig, []byte(fp), "validate", "")
			if verbose {
				for _, f := range findings {
					printFinding(f)
				}
			}
			if len(findings) != 0 {
				fmt.Fprintf(w, "%s false positive %s\t%sfailed%s\n", rule.RuleID, fp, Red, Reset)
			} else {
				fmt.Fprintf(w, "%s false positive %s\t%sok%s\n", rule.RuleID, fp, Green, Reset)
			}
		}
	}
	w.Flush()
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}
