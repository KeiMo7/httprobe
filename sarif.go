package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const sarifVersion = "2.1.0"
const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"
const sarifFlushEvery = 1000

const (
	ruleHTTPSListening = "HTTPS-001"
	ruleHTTPListening  = "HTTP-001"
	ruleNonStdPort     = "PORT-001"
)

var severityToLevel = map[severity]string{
	severityHigh:   "error",
	severityMedium: "warning",
	severityNote:   "note",
}

var sarifRules = []map[string]interface{}{
	{
		"id":               ruleHTTPSListening,
		"name":             "HttpsServiceListening",
		"shortDescription": map[string]string{"text": "HTTPS service is listening"},
		"fullDescription":  map[string]string{"text": "An HTTPS service responded on the probed host and port."},
		"defaultConfiguration": map[string]interface{}{
			"level": severityToLevel[severityNote],
		},
	},
	{
		"id":               ruleHTTPListening,
		"name":             "HttpServiceListening",
		"shortDescription": map[string]string{"text": "HTTP service is listening"},
		"fullDescription":  map[string]string{"text": "An HTTP service responded on the probed host and port."},
		"defaultConfiguration": map[string]interface{}{
			"level": severityToLevel[severityMedium],
		},
	},
	{
		"id":               ruleNonStdPort,
		"name":             "ServiceListeningOnNonStandardPort",
		"shortDescription": map[string]string{"text": "Service is listening on a non-standard port"},
		"fullDescription":  map[string]string{"text": "A web service responded on a port other than the protocol default, which may expose an unintended interface."},
		"defaultConfiguration": map[string]interface{}{
			"level": severityToLevel[severityHigh],
		},
	},
}

type sarifOutput struct {
	finalPath string
	tempPath  string
	repoRoot  string
	inputFile string
	file      *os.File
	encoder   *json.Encoder
	written   int
	flushAt   int
	closed    bool
}

func newFinding(target probeTarget, scheme string) finding {
	port := defaultPort(scheme)
	if idx := strings.LastIndex(target.domain, ":"); idx > 0 {
		port = target.domain[idx+1:]
	}

	ruleID := ruleHTTPListening
	level := severityMedium
	if scheme == "https" {
		ruleID = ruleHTTPSListening
		level = severityNote
	}
	if port != defaultPort(scheme) {
		ruleID = ruleNonStdPort
		level = severityHigh
	}

	return finding{
		target: target,
		scheme: scheme,
		port:   port,
		ruleID: ruleID,
		level:  level,
	}
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func newSARIFOutput(path, repoRoot, inputFile string, flushAt int) (*sarifOutput, error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".httprobe-sarif-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temporary SARIF file: %w", err)
	}

	if flushAt <= 0 {
		flushAt = sarifFlushEvery
	}

	output := &sarifOutput{
		finalPath: path,
		tempPath:  temp.Name(),
		repoRoot:  repoRoot,
		inputFile: inputFile,
		file:      temp,
		encoder:   json.NewEncoder(temp),
		flushAt:   flushAt,
	}

	if err := output.writePreamble(); err != nil {
		output.abort()
		return nil, err
	}
	return output, nil
}

func (s *sarifOutput) writePreamble() error {
	header := `{
  "version": "` + sarifVersion + `",
  "$schema": "` + sarifSchema + `",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "httprobe",
          "informationUri": "https://github.com/tomnomnom/httprobe",
          "rules": `
	if _, err := s.file.WriteString(header); err != nil {
		return fmt.Errorf("write SARIF preamble: %w", err)
	}
	if err := s.encoder.Encode(sarifRules); err != nil {
		return fmt.Errorf("write SARIF rules: %w", err)
	}
	if _, err := s.file.WriteString("      }\n    },\n    \"results\": ["); err != nil {
		return fmt.Errorf("write SARIF preamble: %w", err)
	}
	return nil
}

func (s *sarifOutput) WriteResult(hit finding) error {
	if s.closed {
		return fmt.Errorf("SARIF output is already closed")
	}

	result := map[string]interface{}{
		"ruleId":  hit.ruleID,
		"level":   severityToLevel[hit.level],
		"message": map[string]string{"text": resultMessage(hit)},
		"locations": []map[string]interface{}{
			{
				"physicalLocation": map[string]interface{}{
					"artifactLocation": map[string]string{
						"uri":       s.artifactURI(),
						"uriBaseId": "%SRCROOT%",
					},
					"region": map[string]int{
						"startLine":   hit.target.line,
						"startColumn": hit.target.column,
						"endColumn":   hit.target.column + hit.target.length,
					},
				},
			},
		},
		"properties": map[string]string{
			"protocol": hit.scheme,
			"port":     hit.port,
		},
	}

	prefix := ""
	if s.written > 0 {
		prefix = ","
	}
	if _, err := fmt.Fprintf(s.file, "%s\n      ", prefix); err != nil {
		return fmt.Errorf("write SARIF result: %w", err)
	}
	if err := s.encoder.Encode(result); err != nil {
		return fmt.Errorf("write SARIF result: %w", err)
	}

	s.written++
	if s.written%s.flushAt == 0 {
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("flush SARIF results: %w", err)
		}
	}

	return nil
}

func resultMessage(hit finding) string {
	return fmt.Sprintf("%s service is listening on %s://%s", strings.ToUpper(hit.scheme), hit.scheme, hit.target.domain)
}

func (s *sarifOutput) Fail(err error) error {
	if s.closed {
		return nil
	}
	return s.close(true, err)
}

func (s *sarifOutput) Close(err error) error {
	if s.closed {
		return nil
	}
	return s.close(err != nil, err)
}

func (s *sarifOutput) close(failed bool, cause error) error {
	s.closed = true

	invocation := map[string]interface{}{
		"executionSuccessful": !failed,
	}
	if failed && cause != nil {
		invocation["toolExecutionNotifications"] = []map[string]interface{}{
			{
				"level":   "error",
				"message": map[string]string{"text": cause.Error()},
			},
		}
	}

	if _, err := fmt.Fprintf(s.file, "\n    ],\n    \"invocations\": ["); err != nil {
		s.abort()
		return fmt.Errorf("write SARIF invocation: %w", err)
	}
	if err := s.encoder.Encode(invocation); err != nil {
		s.abort()
		return fmt.Errorf("write SARIF invocation: %w", err)
	}
	if _, err := s.file.WriteString("    ]\n  }\n]\n}\n"); err != nil {
		s.abort()
		return fmt.Errorf("finalize SARIF output: %w", err)
	}

	if err := s.file.Sync(); err != nil {
		s.abort()
		return fmt.Errorf("flush SARIF output: %w", err)
	}
	if err := s.file.Close(); err != nil {
		s.abort()
		return fmt.Errorf("close SARIF output: %w", err)
	}

	if err := validateSARIFFile(s.tempPath); err != nil {
		s.abort()
		return err
	}

	if err := os.Rename(s.tempPath, s.finalPath); err != nil {
		s.abort()
		return fmt.Errorf("publish SARIF output: %w", err)
	}
	return nil
}

func (s *sarifOutput) abort() {
	if s.file != nil {
		s.file.Close()
	}
	os.Remove(s.tempPath)
}

func (s *sarifOutput) artifactURI() string {
	if s.inputFile == "" {
		return "stdin"
	}
	return relativeArtifactURI(s.inputFile, s.repoRoot)
}

func relativeArtifactURI(path, repoRoot string) string {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(repoRoot)

	relative := cleanPath
	if rooted, err := filepath.Rel(cleanRoot, cleanPath); err == nil {
		relative = rooted
	}
	relative = filepath.ToSlash(relative)
	relative = strings.TrimPrefix(relative, "/")

	// Drop Windows drive letters and any UNC-style prefixes so that only
	// repository-relative path segments remain.
	if len(relative) >= 2 && relative[1] == ':' {
		relative = relative[2:]
		relative = strings.TrimPrefix(relative, "/")
	}
	return escapeArtifactURI(relative)
}

func escapeArtifactURI(uri string) string {
	var builder strings.Builder
	if !utf8.ValidString(uri) {
		uri = strings.ToValidUTF8(uri, "\ufffd")
	}
	for _, r := range uri {
		switch {
		case r == '/' || r == '-' || r == '_' || r == '.':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r == ' ':
			builder.WriteString("%20")
		default:
			for _, unit := range utf16.Encode([]rune{r}) {
				builder.WriteString("%u")
				builder.WriteString(strings.ToUpper(strconv.FormatUint(uint64(unit), 16)))
			}
		}
	}
	return builder.String()
}

func utf16Length(text string) int {
	return len(utf16.Encode([]rune(text)))
}

func repositoryRoot() string {
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return "."
}

func validateSARIFFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read SARIF output for validation: %w", err)
	}
	if !json.Valid(data) {
		return fmt.Errorf("SARIF self-check failed: document is not valid JSON (root value)")
	}

	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("SARIF self-check failed at root: %w", err)
	}
	if document["version"] != sarifVersion {
		return fmt.Errorf("SARIF self-check failed at /version: expected %q", sarifVersion)
	}
	runs, ok := document["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		return fmt.Errorf("SARIF self-check failed at /runs: expected exactly one run")
	}
	run := runs[0].(map[string]interface{})
	results, ok := run["results"].([]interface{})
	if !ok {
		return fmt.Errorf("SARIF self-check failed at /runs/0/results: expected an array")
	}
	for index, rawResult := range results {
		result, ok := rawResult.(map[string]interface{})
		if !ok {
			return fmt.Errorf("SARIF self-check failed at /runs/0/results/%d: expected an object", index)
		}
		if _, ok := result["ruleId"].(string); !ok {
			return fmt.Errorf("SARIF self-check failed at /runs/0/results/%d/ruleId: expected a string", index)
		}
		if _, ok := result["level"].(string); !ok {
			return fmt.Errorf("SARIF self-check failed at /runs/0/results/%d/level: expected a string", index)
		}
		if _, ok := result["message"].(map[string]interface{}); !ok {
			return fmt.Errorf("SARIF self-check failed at /runs/0/results/%d/message: expected an object", index)
		}
	}
	return nil
}
