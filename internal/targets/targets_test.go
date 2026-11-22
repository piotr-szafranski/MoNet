package targets

import (
	"context"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	ok := map[string]Kind{"10.0.0.1": KindIP, "10.0.0.0/24": KindCIDR, "10.0.0.1-50": KindRange, "10.0.0.1-10.0.1.5": KindRange, "Portal.Example.PL": KindDomain}
	for v, k := range ok {
		if _, got, err := Classify(v); err != nil || got != k {
			t.Errorf("%s: %v %v", v, got, err)
		}
	}
	for _, bad := range []string{"10.0.0.0/4", "nie-ma-takiego", "300.1.1.1", ""} {
		if _, _, err := Classify(bad); err == nil {
			t.Errorf("powinno odrzucić %q", bad)
		}
	}
}

func TestExpand(t *testing.T) {
	ex, err := Expand(context.Background(), []string{"10.0.0.0/24", "10.0.0.5", "10.0.1.1-3"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.IPs) != 254+3 { // /24 bez adresu sieci i broadcastu, duplikat 10.0.0.5 usunięty
		t.Fatalf("adresów: %d", len(ex.IPs))
	}
	if CountEstimate([]string{"10.0.0.0/18"}) != 16382 {
		t.Fatal("estymacja /18")
	}
}

func TestCSVAndJSON(t *testing.T) {
	in, err := ParseCSV(strings.NewReader("value;tags;note\n10.0.0.0/24;dmz|www;serwery\n10.0.0.9;;\n"))
	if err != nil || len(in) != 2 || len(in[0].Tags) != 2 || in[0].Note != "serwery" {
		t.Fatalf("csv: %+v %v", in, err)
	}
	j, err := ParseJSON(strings.NewReader(`{"targets":["10.1.1.1",{"value":"10.2.0.0/16","tags":["a"]}]}`))
	if err != nil || len(j) != 2 || j[1].Tags[0] != "a" {
		t.Fatalf("json: %+v %v", j, err)
	}
}

func TestClassifyRejectsBadNumeric(t *testing.T) {
	for _, v := range []string{"10.66.8.300", "10.66.8.0/33", "10.0.0.50-10.0.0.1", "1.2.3"} {
		if _, _, err := Classify(v); err == nil {
			t.Errorf("%q powinno być odrzucone", v)
		}
	}
}
