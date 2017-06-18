package main

import (
	"fmt"

	"github.com/docopt/docopt-go"
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
	args, _ := docopt.Parse(usage, nil, true, "nvd-search 0.1", false)
	fmt.Println(args)
}
