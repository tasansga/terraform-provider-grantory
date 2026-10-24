package controller

import "testing"

func TestParsePayloadString(t *testing.T) {
	mapped, err := parsePayloadString(`{"k":"v"}`)
	if err != nil {
		t.Fatalf("parsePayloadString: %v", err)
	}
	if mapped["k"] != "v" {
		t.Fatalf("expected k=v, got %v", mapped["k"])
	}

	mapped, err = parsePayloadString(``)
	if err != nil {
		t.Fatalf("parsePayloadString empty: %v", err)
	}
	if mapped != nil {
		t.Fatalf("expected empty string to return nil")
	}

	mapped, err = parsePayloadString(`   `)
	if err != nil {
		t.Fatalf("parsePayloadString whitespace: %v", err)
	}
	if mapped != nil {
		t.Fatalf("expected whitespace to return nil")
	}
}

func TestParsePayloadStringInvalid(t *testing.T) {
	_, err := parsePayloadString(`{`)
	if err == nil {
		t.Fatalf("expected error for invalid json")
	}

	_, err = parsePayloadString(`["x"]`)
	if err == nil {
		t.Fatalf("expected error for non-object json")
	}
}
