// Deliberately vulnerable test code for Phoenix repository coverage (SAST column). Do not deploy.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

func main() {
	// SQL injection
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", r.URL.Query().Get("name")))
		defer rows.Close()
	})
	// Command injection
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		out, _ := exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Output()
		w.Write(out)
	})
	// Path traversal
	http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		data, _ := os.ReadFile(filepath.Join("/srv", r.URL.Query().Get("name")))
		w.Write(data)
	})
	// Reflected XSS
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<h1>Hello "+r.URL.Query().Get("name")+"</h1>")
	})
	// Open redirect
	http.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
	})
	// Weak hash of a password
	http.HandleFunc("/hash", func(w http.ResponseWriter, r *http.Request) {
		password := r.URL.Query().Get("password")
		fmt.Fprintf(w, "%x", md5.Sum([]byte(password)))
	})
	// Disabled TLS certificate check
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	_ = client
	http.ListenAndServe(":8080", nil)
}
