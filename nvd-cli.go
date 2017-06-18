package main

import (
	"log"

	"github.com/okuuva/nvd-search-cli/nvd-search"

	"github.com/docopt/docopt-go"
	"github.com/mitchellh/go-homedir"
)

func main() {
	usage := `Usage: nvd-search [-c CVE | -k KEY] [-v VENDOR] [-p PRODUCT] [-n NVD]

Options:
 -h --help                      show this
 -c CVE --cve CVE               CVE-ID of the vulnerability [default: ]
 -k KEY --key KEY               keyword search [default: ]
 -v VENDOR --vendor VENDOR      CPE vendor name [default: ]
 -p PRODUCT --product PRODUCT   CPE product name [default: ]
 -n NVD --nvd NVD               Location of the local NVD [default: ~/.config/nvd-cli/db]
`
	args, _ := docopt.Parse(usage, nil, true, "nvd-cli 0.1", false)
	path, err := homedir.Expand(args["--nvd"].(string))
	if err != nil {
		log.Fatal(err)
	}
	nvd_search.Search(args["--cve"].(string), args["--key"].(string), args["--vendor"].(string), args["--product"].(string), path)
}
