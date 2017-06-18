package nvd_search

import (
	"log"
	"fmt"
	"time"
	"path"

	"github.com/levigross/grequests"
)

const (
	NVDFeedBaseUrl = "https://static.nvd.nist.gov/feeds/"
	NVDJsonFeedUrl = "json/cve/%.1[1]f/nvdcve-%.1[1]f-"
	NVDFeedVersion = 1.0
)

var NVDUrl string = fmt.Sprintf("%v%v", NVDFeedBaseUrl, fmt.Sprintf(NVDJsonFeedUrl, NVDFeedVersion))

func checkFatal(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func checkError(e error) bool {
	if e != nil {
		log.Println(e)
		return false
	}
	return true
}

func downloadFile(uri, filename string) bool {
	log.Println("Downloading license file from", uri)
	response, err := grequests.Get(uri, nil)
	if !checkError(err) {
		log.Println("Couldn't download file, maybe it's not valid URL?")
		return false
	}
	err = response.DownloadToFile(filename)
	checkFatal(err)
	log.Println("Saved content from", uri, "to", filename)
	return true
}

func generateFileList() []string {
	fileList := []string{"modified"}
	for year := 2002; year <= time.Now().Year(); year++ {
		fileList = append(fileList, fmt.Sprintf("%v", year))
	}
	return fileList
}

func getMeta(variety string) {
	url := fmt.Sprintf("%v%v.meta", NVDUrl, variety)
	response, err := grequests.Get(url, nil)
	checkFatal(err)
	fmt.Println(response.String())
}

func getJsonGz(variety, filepath string) {
	filename := fmt.Sprintf("%v.json.gz", variety)
	url := fmt.Sprintf("%v%v", NVDUrl, filename)
	if !downloadFile(url, path.Join(filepath, filename)) {
		log.Fatal("oops")
	}
}
