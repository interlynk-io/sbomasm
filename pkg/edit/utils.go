package edit

import (
	"errors"
	"os"
	"time"

	"github.com/interlynk-io/sbomasm/pkg/detect"
)

var errNoConfiguration = errors.New("no configuration provided")
var errNotSupported = errors.New("not supported")
var errInvalidInput = errors.New("invalid input data")

func detectSbom(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	spec, format, err := detect.Detect(f)
	if err != nil {
		return "", "", err
	}
	return string(spec), string(format), nil
}

func utcNowTime() string {
	location, _ := time.LoadLocation("UTC")
	locationTime := time.Now().In(location)
	return locationTime.Format(time.RFC3339)
}
