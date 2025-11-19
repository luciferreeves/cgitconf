package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
)

// Load from environment with defaults
var secret = getenv("WEBHOOK_SECRET", "DOYOUREALLYTHINKIEXPOSESECRETS?")
var mirrorBin = getenv("MIRROR_BIN", "/usr/local/bin/mirror")
var mirrorSyncBin = getenv("MIRROR_SYNC_BIN", "/usr/local/bin/mirror-sync")
var repoRoot = getenv("REPO_ROOT", "/root/shifoogit/repos")

func getenv(k, def string) string {
    if v := os.Getenv(k); v != "" {
        return v
    }
    return def
}

type Repo struct {
    Name     string `json:"name"`
    FullName string `json:"full_name"`
    CloneURL string `json:"clone_url"`
    Private  bool   `json:"private"`
}

type RepoEvent struct {
    Action     string `json:"action"`
    Repository Repo   `json:"repository"`
}

type InstallationRepoEvent struct {
    Action              string `json:"action"`
    RepositoriesAdded   []Repo `json:"repositories_added"`
    RepositoriesRemoved []Repo `json:"repositories_removed"`
}

func verifySignature(payload []byte, sig string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    expected := hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(sig))
}

func run(cmd string, args ...string) {
    log.Printf("Running: %s %v", cmd, args)
    c := exec.Command(cmd, args...)
    c.Stdout = os.Stdout
    c.Stderr = os.Stderr
    err := c.Run()
    if err != nil {
        log.Printf("ERROR running %s: %v", cmd, err)
    }
}

func handler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)

    // Signature check
    sigHeader := r.Header.Get("X-Hub-Signature-256")
    var sig string
    fmt.Sscanf(sigHeader, "sha256=%s", &sig)
    if !verifySignature(body, sig) {
        log.Println("Invalid signature")
        return
    }

    event := r.Header.Get("X-GitHub-Event")
    log.Println("Received event:", event)

    switch event {

    // ---------------------------------------------------
    // REPOSITORY EVENTS
    // ---------------------------------------------------
    case "repository":
        var ev RepoEvent
        json.Unmarshal(body, &ev)

        name := ev.Repository.Name
        url := ev.Repository.CloneURL
        path := repoRoot + "/" + name

        log.Printf("repository action=%s repo=%s private=%v",
            ev.Action, name, ev.Repository.Private)

        switch ev.Action {

        case "created", "publicized":
            run(mirrorBin, url)

        case "deleted", "privatized":
            run("rm", "-rf", path)

        case "renamed":
            var old struct {
                Repository struct {
                    PreviousName string `json:"previous_name"`
                } `json:"repository"`
            }
            json.Unmarshal(body, &old)

            oldPath := repoRoot + "/" + old.Repository.PreviousName
            newPath := repoRoot + "/" + name
            run("mv", oldPath, newPath)
        }

    // ---------------------------------------------------
    // installation_repositories — we IGNORE for mirroring
    // ---------------------------------------------------
    case "installation_repositories":
        var ev InstallationRepoEvent
        json.Unmarshal(body, &ev)

        log.Printf("installation_repositories action=%s added=%d removed=%d — ignored",
            ev.Action, len(ev.RepositoriesAdded), len(ev.RepositoriesRemoved))

    // ---------------------------------------------------
    // SYNC TRIGGERS
    // ---------------------------------------------------
    case "push", "create", "delete", "release":
        log.Printf("triggering mirror-sync for event: %s", event)
        run(mirrorSyncBin)

    default:
        log.Println("Ignoring event:", event)
    }

    fmt.Fprintln(w, "OK")
}

func main() {
    http.HandleFunc("/", handler)
    log.Println("Listening on :53981")
    log.Fatal(http.ListenAndServe(":53981", nil))
}
