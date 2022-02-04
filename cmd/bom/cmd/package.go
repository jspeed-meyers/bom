/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"regexp"
	// "strings"

	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"sigs.k8s.io/bom/pkg/spdx"
)

type packageOptions struct {
	Format string //
}

var packageOpts = &packageOptions{}

var packageCmd = &cobra.Command{
	Short: "bom document package → Get package dependency information from an SBOM",
	Long: `bom document package → Get package dependency information from an SBOM",

TBD

`,
	Use:               "package",
	SilenceUsage:      true,
	SilenceErrors:     true,
	PersistentPreRunE: initLogging,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("At least one spdx sbom should be specified")
		}
		return runPackage(packageOpts, args)
	},
}

func init() {
	packageCmd.PersistentFlags().StringVar(
		&packageOpts.Format,
		"format",
		"table",
		"Output format for package dependency data. Can be either table or json",
	)
}

func runPackage(opts *packageOptions, args []string) error {
	doc, err := spdx.OpenDoc(args[0])
	if err != nil {
		return errors.Wrap(err, "opening doc")
	}

	if opts.Format == "table" {
		fmt.Println(spdx.Banner())
		if len(args) > 1 {
			return elementPackageTable(opts, doc, args[1])
		}

		return documentPackageTable(opts, doc)
	}
	return errors.New("Unknown format")
}

func elementPackageTable(_ *packageOptions, doc *spdx.Document, elementID string) error {
	var p *spdx.Package
	for _, pt := range doc.Packages {
		if pt.SPDXID() == elementID {
			p = pt
			break
		}
	}
	if p == nil {
		return errors.Errorf("Unable to find package %s", elementID)
	}
	data := [][]string{}
	deps, err := p.Dependencies()
	if err != nil {
		return errors.Wrap(err, "getting package dependencies")
	}
	for _, d := range deps {
		if p, ok := d.(*spdx.Package); ok {
			// TODO: THIS IS WHERE TO ADD IN GETTING PACKAGE VERSION INFO
			// l := spdx.NOASSERTION
			// if p.LicenseConcluded != spdx.NOASSERTION {
			// 	l = p.LicenseConcluded
			// }

			// if p.LicenseDeclared != "" && p.LicenseDeclared != spdx.NOASSERTION {
			// 	l = p.LicenseDeclared
			// }
			re := regexp.MustCompile(`(@v)(\d+.\d+.\d+)`)
			l := string(re.Find([]byte(p.Name)))
			data = append(data, []string{p.Name, l})
		}
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Package", "Version"})
	table.SetBorder(true)
	table.AppendBulk(data)
	table.Render()

	return nil
}

func documentPackageTable(_ *packageOptions, doc *spdx.Document) error {
	// sbomData, err := doc.PackageData()
	// if err != nil {
	// 	return errors.Wrap(err, "getting package information")
	// }

	// data := [][]string{}

	// for _, packageData := range sbomData.Packages {
	// 	data = append(data, []string{
	// 		packageData.Name,
	// 		packageData.ID,
	// 		strings.Join(packageData.LicenseConcluded, " + "),
	// 		// fmt.Sprintf("%d", packageData.NumDependencies),
	// 		// fmt.Sprintf("%d", packageData.NumLicenses),
	// 	},
	// 	)
	// }

	// table := tablewriter.NewWriter(os.Stdout)
	// table.SetHeader([]string{"Package", "SPDX ID", "Version"})
	// table.SetBorder(true)
	// table.AppendBulk(data)
	// table.Render()
	return nil
}
