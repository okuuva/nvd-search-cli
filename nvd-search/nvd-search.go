package nvd_search

import (
	"io"
	"os"
	"log"
	"fmt"
	"time"
	"path"
	"crypto/sha256"

	"github.com/levigross/grequests"
)

const (
	NVDFeedBaseUrl = "https://static.nvd.nist.gov/feeds/"
	NVDJsonFeedUrl = "json/cve/%.1[1]f/nvdcve-%.1[1]f-"
	NVDFeedVersion = 1.0
)

var NVDUrl string = fmt.Sprintf("%v%v", NVDFeedBaseUrl, fmt.Sprintf(NVDJsonFeedUrl, NVDFeedVersion))

type meta map[string]interface{}
}

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
	log.Println("Downloading file from", uri)
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

func getMeta(c chan<- meta, variety string) {
	metaName := fmt.Sprintf("%v.meta", variety)
	url := fmt.Sprintf("%v%v", NVDUrl, metaName)
	log.Println("Fetching meta file from", url)
	response, err := grequests.Get(url, nil)
	checkFatal(err)
	if response.StatusCode != 200 {
		log.Fatal(fmt.Sprintf("NVD returned %v from %v", response.StatusCode, url))
	}
	content := strings.Split(response.String(), "\r\n")
	meta := make(meta)
	for _, line := range content {
		if len(line) == 0 {
			continue
		}
		parsedLine := strings.SplitN(line, ":", 2)
		meta[parsedLine[0]] = parsedLine[1]
	}
	log.Println("Parsed meta file", metaName, "succesfully")
	c <- meta
}

func getMetas(fileList []string) []meta {
	c := make(chan meta)
	defer close(c)
	for _, file := range fileList {
		go getMeta(c, file)
	}
	var metas = make([]meta, 0)
	for meta := range c {
		metas = append(metas, meta)
		if len(metas) == len(fileList) {
			break
		}
	}
	return metas
}

func getJsonGz(variety, filepath string) {
	filename := fmt.Sprintf("%v.json.gz", variety)
	url := fmt.Sprintf("%v%v", NVDUrl, filename)
	if !downloadFile(url, path.Join(filepath, filename)) {
		log.Fatal("oops")
	}
}

func calculateSHA(r io.Reader) []byte {
	hasher := sha256.New()
	_, err := io.Copy(hasher, r)
	checkFatal(err)
	return hasher.Sum(nil)
}

func loadNVD(dbPath string) {
	os.MkdirAll(dbPath, 0755)
	file, err := os.Open(path.Join(dbPath, "db.json"))
	if !checkError(err) {
		log.Print("Concatenated database does not exist, creating from scratch")
		Update(dbPath, true)
		os.Exit(2)
	}
	log.Printf("%x", calculateSHA(file))
	Update(dbPath, false)
}

func Update(dbPath string, all bool) {
	os.MkdirAll(dbPath, 0755)
	fileList := []string{"modified"}
	if all {
		fileList = generateFileList()
	}
	fmt.Println(fileList)
	}
}

func Search(cve, key, vendor, product, dbPath string) {
	if cve != "" && key != "" {
		log.Fatal("CVE and keyword search are mutually exclusive, please give only either or.")
	} else if !(cve == "" || key == "" || vendor == "" || product == "") {
		log.Fatal("Give at least one search parameter")
	}
	loadNVD(dbPath)
}
