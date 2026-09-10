package httputil

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func DecodeJSON(w http.ResponseWriter, r *http.Request, limit int64, destination any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON value")
	}
	return nil
}
