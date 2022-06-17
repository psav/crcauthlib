package deps

import "net/http"

var (
	HTTP HTTPClient
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
}

func init() {
	HTTP = &http.Client{}
}
