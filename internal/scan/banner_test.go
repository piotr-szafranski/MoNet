package scan

import (
	"testing"

	"github.com/asi-agh/asi/internal/httpprobe"
)

// Regresja: nagłówek Server bez wersji („nginx/”) albo pusty produkt nie mogą wywracać skanu.
func TestAddBannerTechNoPanic(t *testing.T) {
	cases := []string{"nginx/", "Apache/ ", "/", " ", "x/   "}
	for _, sv := range cases {
		o := &Observation{Data: ObsData{HTTP: &httpprobe.Result{Status: 200, Headers: map[string][]string{"server": {sv}}}}}
		o.addBannerTech()
	}
	o := &Observation{Product: " httpd"}
	o.addBannerTech()
	o = &Observation{Product: "nginx", Version: "1.2"}
	o.addBannerTech()
	if len(o.Techs) != 1 || o.Techs[0].Name != "nginx" {
		t.Fatalf("oczekiwano technologii nginx, jest %+v", o.Techs)
	}
}
