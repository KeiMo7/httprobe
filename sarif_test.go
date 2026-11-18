package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func loadSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	schemaPath := filepath.Join("testdata", "sarif-schema-2.1.0.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read SARIF schema: %v", err)
	}
	if err := compiler.AddResource(sarifSchema, bytes.NewReader(schemaData)); err != nil {
		t.Fatalf("load SARIF schema: %v", err)
	}
	schema, err := compiler.Compile(sarifSchema)
	if err != nil {
		t.Fatalf("compile SARIF schema: %v", err)
	}
	return schema
}

func mustReadFile(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func validateSARIFDocument(t *testing.T, path string) any {
	t.Helper()
	document := mustReadFile(t, path)
	if err := loadSARIFSchema(t).Validate(document); err != nil {
		validationError, ok := err.(*jsonschema.ValidationError)
		if !ok {
			t.Fatalf("SARIF schema validation failed: %v", err)
		}
		t.Fatalf("SARIF schema validation failed:\n%v", validationError.DetailedOutput())
	}
	return document
}

func TestSARIFMultipleResultsOnePerHit(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "results.sarif")
	writer, err := newSARIFOutput(outputPath, t.TempDir(), "domains.txt", 2)
	if err != nil {
		t.Fatalf("newSARIFOutput: %v", err)
	}

	first := newFinding(probeTarget{domain: "example.com", line: 1, column: 1, length: 11}, "https")
	second := newFinding(probeTarget{domain: "example.com", line: 1, column: 1, length: 11}, "http")
	third := newFinding(probeTarget{domain: "example.com:8080", line: 2, column: 1, length: 16}, "http")
	fourth := newFinding(probeTarget{domain: "example.com", line: 4, column: 3, length: 11}, "https")

	for _, hit := range []finding{first, second, third, fourth} {
		if err := writer.WriteResult(hit); err != nil {
			t.Fatalf("WriteResult: %v", err)
		}
	}
	if err := writer.Close(nil); err != nil {
		t.Fatalf("Close: %v", err)
	}

	document := validateSARIFDocument(t, outputPath)
	run := document.(map[string]any)["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 4 {
		t.Fatalf("expected 4 independent results, got %d", len(results))
	}

	expectedLevels := map[string]string{
		ruleHTTPSListening: "note",
		ruleHTTPListening:  "warning",
		ruleNonStdPort:     "error",
	}
	expectedLines := []float64{1, 1, 2, 4}
	seenRules := map[string]bool{}
	for index, rawResult := range results {
		result := rawResult.(map[string]any)
		ruleID := result["ruleId"].(string)
		seenRules[ruleID] = true
		if result["level"].(string) != expectedLevels[ruleID] {
			t.Fatalf("result %d: unexpected level %q for rule %q", index, result["level"], ruleID)
		}
		message := result["message"].(map[string]any)["text"].(string)
		if !strings.Contains(message, result["properties"].(map[string]any)["protocol"].(string)) {
			t.Fatalf("result %d: message does not identify the protocol: %q", index, message)
		}
		location := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
		region := location["region"].(map[string]any)
		if region["startLine"].(float64) != expectedLines[index] {
			t.Fatalf("result %d: unexpected start line %v, want %v", index, region["startLine"], expectedLines[index])
		}
	}

	if !seenRules[ruleHTTPSListening] || !seenRules[ruleHTTPListening] || !seenRules[ruleNonStdPort] {
		t.Fatalf("expected all three rules to be represented, got %v", seenRules)
	}

	invocation := run["invocations"].([]any)[0].(map[string]any)
	if invocation["executionSuccessful"] != true {
		t.Fatalf("expected successful invocation, got %v", invocation)
	}

	rawBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if bytes.Count(rawBytes, []byte("\n")) < 4 {
		t.Fatalf("expected results to be streamed across multiple lines")
	}
}

func TestSARIFZeroHitsIsValid(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "empty.sarif")
	writer, err := newSARIFOutput(outputPath, t.TempDir(), "domains.txt", sarifFlushEvery)
	if err != nil {
		t.Fatalf("newSARIFOutput: %v", err)
	}
	if err := writer.Close(nil); err != nil {
		t.Fatalf("Close: %v", err)
	}

	document := validateSARIFDocument(t, outputPath)
	run := document.(map[string]any)["runs"].([]any)[0].(map[string]any)
	if results, ok := run["results"].([]any); !ok || len(results) != 0 {
		t.Fatalf("expected an empty results array, got %v", run["results"])
	}
}

func TestSARIFFailureMarksInvocationAndKeepsValidFile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "failed.sarif")
	writer, err := newSARIFOutput(outputPath, t.TempDir(), "domains.txt", sarifFlushEvery)
	if err != nil {
		t.Fatalf("newSARIFOutput: %v", err)
	}
	hit := newFinding(probeTarget{domain: "example.com", line: 1, column: 1, length: 11}, "http")
	if err := writer.WriteResult(hit); err != nil {
		t.Fatalf("WriteResult: %v", err)
	}
	if err := writer.Fail(assertionError("probe transport failed")); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	document := validateSARIFDocument(t, outputPath)
	invocation := document.(map[string]any)["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if invocation["executionSuccessful"] != false {
		t.Fatalf("expected executionSuccessful=false, got %v", invocation)
	}
	notifications := invocation["toolExecutionNotifications"].([]any)
	if len(notifications) != 1 || notifications[0].(map[string]any)["level"] != "error" {
		t.Fatalf("expected one error notification, got %v", notifications)
	}
}

func TestSARIFAbortLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "missing.sarif")
	writer, err := newSARIFOutput(outputPath, dir, "domains.txt", sarifFlushEvery)
	if err != nil {
		t.Fatalf("newSARIFOutput: %v", err)
	}
	writer.abort()

	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("expected no published file after abort, got err=%v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".httprobe-sarif-") {
			t.Fatalf("temporary file was not removed: %s", entry.Name())
		}
	}
}

func TestSeverityMappingIsExplicit(t *testing.T) {
	expected := map[severity]string{
		severityHigh:   "error",
		severityMedium: "warning",
		severityNote:   "note",
	}
	for level, sarifLevel := range expected {
		if severityToLevel[level] != sarifLevel {
			t.Fatalf("severity %q maps to %q, want %q", level, severityToLevel[level], sarifLevel)
		}
	}
}

func TestRelativeArtifactURIStripsRootsAndEscapesPaths(t *testing.T) {
	repoRoot := filepath.Join(string(filepath.Separator), "home", "feedback", "uid52")
	cases := []struct {
		name string
		path string
		want string
	}{
		{"absolute inside repo", filepath.Join(repoRoot, "recon", "domains.txt"), "recon/domains.txt"},
		{"already relative", filepath.Join("recon", "domains.txt"), "recon/domains.txt"},
		{"non utf8 bytes", filepath.Join(repoRoot, "recon", "domains-\xff.txt"), "recon/domains-%uFFFD.txt"},
		{"space in path", filepath.Join(repoRoot, "recon", "my domains.txt"), "recon/my%20domains.txt"},
		{"long path", filepath.Join(repoRoot, strings.Repeat("segment/", 40)+"domains.txt"), strings.Repeat("segment/", 40) + "domains.txt"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := relativeArtifactURI(testCase.path, repoRoot)
			if got != testCase.want {
				t.Fatalf("relativeArtifactURI(%q) = %q, want %q", testCase.path, got, testCase.want)
			}
			if strings.HasPrefix(got, "/") || strings.Contains(got, "/home/") || strings.Contains(got, ":") {
				t.Fatalf("artifact URI leaks an absolute or drive-qualified path: %q", got)
			}
		})
	}
}

func TestRuleIDsAreStable(t *testing.T) {
	stableIDs := []string{ruleHTTPSListening, ruleHTTPListening, ruleNonStdPort}
	for _, id := range stableIDs {
		if strings.ContainsAny(id, "/\\ ") {
			t.Fatalf("rule ID must stay stable and readable: %q", id)
		}
	}

	first := newFinding(probeTarget{domain: "a.example.com:8443", line: 9, column: 2, length: 20}, "https")
	second := newFinding(probeTarget{domain: "b.example.com:8443", line: 27, column: 5, length: 22}, "https")
	if first.ruleID != second.ruleID {
		t.Fatalf("same rule produced different IDs across files/lines: %q vs %q", first.ruleID, second.ruleID)
	}
}

func TestStreamingWriterFlushesInChunks(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "streamed.sarif")
	writer, err := newSARIFOutput(outputPath, t.TempDir(), "domains.txt", 100)
	if err != nil {
		t.Fatalf("newSARIFOutput: %v", err)
	}

	target := probeTarget{domain: "example.com", line: 1, column: 1, length: 11}
	for index := 0; index < 1050; index++ {
		target.line = index + 1
		if err := writer.WriteResult(newFinding(target, "http")); err != nil {
			t.Fatalf("WriteResult %d: %v", index, err)
		}
	}
	if err := writer.Close(nil); err != nil {
		t.Fatalf("Close: %v", err)
	}

	document := validateSARIFDocument(t, outputPath)
	results := document.(map[string]any)["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 1050 {
		t.Fatalf("expected 1050 streamed results, got %d", len(results))
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }
