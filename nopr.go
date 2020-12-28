// TODO: allow users to configure behavior:
// - whether to close the PR or add a status (closing hides statuses)
// - whether to comment on the PR before closing
// - custom text to use when closing
// TODO: use appengine-value to store client secret
// TODO: use gorilla sessions instead of Google auth
// TODO: xsrf everywhere

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/appengine/user"

	"github.com/google/go-github/github"
)

const (
	// TODO: get these for your own app in github
	clientID        = ""
	clientSecret    = ""
	redirectURLPath = "/oauthcallback"
)

var scopes = strings.Join([]string{
	"user:email",      // permission to get basic information about the user
	"public_repo",     // permission to close PRs
	"admin:repo_hook", // permission to add/delete webhooks
	// TODO: ask for this when we're not just closing the PR
	// "repo:status",     // permission to add statuses to commits
}, ",")

func main() {
	appengine.Main()
}

func init() {
	http.HandleFunc("/start", startHandler)
	http.HandleFunc(redirectURLPath, oauthHandler)
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/enable/", enableHandler)
	http.HandleFunc("/disable/", disableHandler)
	http.HandleFunc("/revoke", revokeHandler)
	http.HandleFunc("/hook", webhookHandler)
}

func startHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	u := user.Current(ctx)
	if u == nil || u.Email != "tsdgeos@gmail.com" {
		log.Infof(ctx, "not logged in, redirecting...")
		loginURL, _ := user.LoginURL(ctx, r.URL.Path)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	log.Infof(ctx, "starting oauth...")
	redirectURL := fmt.Sprintf("https://%s.appspot.com", appengine.AppID(ctx)) + redirectURLPath
	url := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=%s",
		clientID, redirectURL, scopes)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func renderError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusInternalServerError)
	errorTmpl.Execute(w, msg)
}

func oauthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	code := r.FormValue("code")
	if code == "" {
		log.Errorf(ctx, "no code, going to start")
		http.Redirect(w, r, "/start", http.StatusSeeOther)
		return
	}

	u := user.Current(ctx)
	if u == nil || u.Email != "tsdgeos@gmail.com" {
		log.Infof(ctx, "not logged in, redirecting...")
		loginURL, _ := user.LoginURL(ctx, r.URL.Path)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	tok, err := getAccessToken(ctx, code)
	if err != nil {
		log.Errorf(ctx, "getting access token: %v", err)
		renderError(w, "Error getting access token")
		return
	}

	ghu, _, err := newClient(ctx, tok).Users.Get(ctx, "")
	if err != nil {
		log.Errorf(ctx, "getting user: %v", err)
		renderError(w, "Error getting user")
		return
	}

	if err := PutUser(ctx, User{
		GoogleUserID: u.ID,
		GitHubUserID: *ghu.ID,
		GitHubToken:  tok,
	}); err != nil {
		log.Errorf(ctx, "put user: %v", err)
		renderError(w, "Error writing user entry")
		return
	}
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}

func getAccessToken(ctx context.Context, code string) (string, error) {
	client := urlfetch.Client(ctx)
	url := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s",
		clientID, clientSecret, code)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Errorf(ctx, "posting request: %v", err)
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf(ctx, "exchanging code: %v", err)
		return "", err
	}
	defer resp.Body.Close()
	var b struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		log.Errorf(ctx, "decoding json: %v", err)
		return "", err
	}
	return b.AccessToken, nil
}

func newClient(ctx context.Context, tok string) *github.Client {
	return github.NewClient(&http.Client{Transport: transport{ctx, tok}})
}

type transport struct {
	ctx context.Context
	tok string
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "token "+t.tok)
	return urlfetch.Client(t.ctx).Do(req)
}

type User struct {
	GoogleUserID string
	GitHubUserID int64
	GitHubToken  string
}

func PutUser(ctx context.Context, u User) error {
	k := datastore.NewKey(ctx, "User", u.GoogleUserID, 0, nil)
	_, err := datastore.Put(ctx, k, &u)
	return err
}

func GetUser(ctx context.Context, id string) *User {
	k := datastore.NewKey(ctx, "User", id, 0, nil)
	var u User
	if err := datastore.Get(ctx, k, &u); err == datastore.ErrNoSuchEntity {
		return nil
	} else if err != nil {
		log.Errorf(ctx, "getting user: %v", err)
		return nil
	}
	return &u
}

func DeleteUser(ctx context.Context, userID string) error {
	return datastore.Delete(ctx, datastore.NewKey(ctx, "User", userID, 0, nil))
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	uu := user.Current(ctx)
	if uu == nil || uu.Email != "tsdgeos@gmail.com" {
		log.Infof(ctx, "not logged in, redirecting...")
		loginURL, _ := user.LoginURL(ctx, r.URL.Path)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	u := GetUser(ctx, uu.ID)
	if u == nil {
		log.Infof(ctx, "unknown user, going to /start")
		http.Redirect(w, r, "/start", http.StatusSeeOther)
		return
	}

	allRepos := []*github.Repository{}
	opt := &github.RepositoryListOptions{
		Type: "admin",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	for {
		repos, resp, err := newClient(ctx, u.GitHubToken).Repositories.List(ctx, "", opt)
		if err != nil {
			errResponse, ok := err.(*github.ErrorResponse)
			if ok && errResponse.Response.StatusCode == 401 {
				// The token has expired, delete the user to request a re-login
				if err := DeleteUser(ctx, uu.ID); err != nil {
					log.Errorf(ctx, "deleting user with expired github token: %v", err)
					renderError(w, "Error deleting user with expired GitHub token")
					return
				}

				http.Redirect(w, r, "/", http.StatusSeeOther)
			}

			log.Errorf(ctx, "listing repos: %v", err)
			renderError(w, "Error listing repos")
			return
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.ListOptions.Page = resp.NextPage
	}

	type data struct {
		Repo     *github.Repository
		Disabled bool
	}
	d := []data{}

	keys := []*datastore.Key{}
	for _, r := range allRepos {
		keys = append(keys, datastore.NewKey(ctx, "Repo", *r.FullName, 0, nil))
	}
	repoEntities := make([]Repo, len(keys))
	if err := datastore.GetMulti(ctx, keys, repoEntities); err != nil {
		if me, ok := err.(appengine.MultiError); ok {
			for i, e := range me {
				var disabled = e == nil
				d = append(d, data{Repo: allRepos[i], Disabled: disabled})
			}
		} else {
			log.Errorf(ctx, "getmulti: %v", err)
			renderError(w, "Error retrieving repos")
			return
		}
	} else {
		// all repos are disabled
		for _, r := range allRepos {
			d = append(d, data{Repo: r, Disabled: true})
		}
	}

	if err := userTmpl.Execute(w, d); err != nil {
		log.Errorf(ctx, "executing template: %v", err)
	}
}

type Repo struct {
	FullName  string // e.g., MyUser/foo-bar
	UserID    string // User key to use to close PRs
	WebhookID int64  // Used to delete the hook
}

func (r Repo) Split() (string, string) {
	parts := strings.Split(r.FullName, "/")
	if len(parts) < 2 {
		panic("invalid full name: " + r.FullName)
	}
	return parts[0], parts[1]
}

func PutRepo(ctx context.Context, r Repo) error {
	k := datastore.NewKey(ctx, "Repo", r.FullName, 0, nil)
	_, err := datastore.Put(ctx, k, &r)
	return err
}

func GetRepo(ctx context.Context, fn string) *Repo {
	k := datastore.NewKey(ctx, "Repo", fn, 0, nil)
	var r Repo
	if err := datastore.Get(ctx, k, &r); err == datastore.ErrNoSuchEntity {
		return nil
	} else if err != nil {
		log.Errorf(ctx, "getting repo: %v", err)
		return nil
	}
	return &r
}

func DeleteRepo(ctx context.Context, fn string) error {
	return datastore.Delete(ctx, datastore.NewKey(ctx, "Repo", fn, 0, nil))
}

func disableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	ctx := appengine.NewContext(r)
	uu := user.Current(ctx)
	if uu == nil || uu.Email != "tsdgeos@gmail.com" {
		log.Infof(ctx, "not logged in, redirecting...")
		loginURL, _ := user.LoginURL(ctx, r.URL.Path)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	u := GetUser(ctx, uu.ID)
	if u == nil {
		log.Infof(ctx, "unknown user, going to /start")
		http.Redirect(w, r, "/start", http.StatusSeeOther)
		return
	}
	// TODO: check that the user is an admin on the repo

	fullName := r.URL.Path[len("/disable/"):]

	ghUser, ghRepo := Repo{FullName: fullName}.Split()
	hook, _, err := newClient(ctx, u.GitHubToken).Repositories.CreateHook(ctx, ghUser, ghRepo, &github.Hook{
		Name:   github.String("web"),
		Events: []string{"pull_request"},
		Config: map[string]interface{}{
			"content_type": "json",
			"url":          fmt.Sprintf("https://%s.appspot.com/hook", appengine.AppID(ctx)),
		},
	})
	if err != nil {
		log.Errorf(ctx, "creating hook: %v", err)
		renderError(w, "Error creating webhook")
		return
	}

	if err := PutRepo(ctx, Repo{
		FullName:  fullName,
		UserID:    u.GoogleUserID,
		WebhookID: *hook.ID,
	}); err != nil {
		log.Errorf(ctx, "put repo: %v", err)
		renderError(w, "Error writing repo entry")
		return
	}
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}

func enableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	ctx := appengine.NewContext(r)
	uu := user.Current(ctx)
	if uu == nil || uu.Email != "tsdgeos@gmail.com" {
		log.Infof(ctx, "not logged in, redirecting...")
		loginURL, _ := user.LoginURL(ctx, r.URL.Path)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	u := GetUser(ctx, uu.ID)
	if u == nil {
		log.Infof(ctx, "unknown user, going to /start")
		http.Redirect(w, r, "/start", http.StatusSeeOther)
		return
	}
	// TODO: check that the user is an admin on the repo

	fullName := r.URL.Path[len("/enable/"):]

	repo := GetRepo(ctx, fullName)
	if repo == nil {
		http.Error(w, "repo not found", http.StatusNotFound)
		return
	}

	ghUser, ghRepo := repo.Split()
	if _, err := newClient(ctx, u.GitHubToken).Repositories.DeleteHook(ctx, ghUser, ghRepo, repo.WebhookID); err != nil {
		log.Errorf(ctx, "delete hook: %v", err)
		renderError(w, "Error deleting webhook")
		return
	}
	if err := DeleteRepo(ctx, repo.FullName); err != nil {
		log.Errorf(ctx, "delete repo: %v", err)
		renderError(w, "Error deleting repo entry")
		return
	}
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	if r.Method != "POST" {
		return
	}
	if r.Header.Get("X-Github-Event") != "pull_request" {
		return
	}
	defer r.Body.Close()
	var hook github.PullRequestEvent
	if err := json.NewDecoder(r.Body).Decode(&hook); err != nil {
		log.Errorf(ctx, "decoding json: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if *hook.Action != "opened" && *hook.Action != "reopened" {
		return
	}
	log.Infof(ctx, "got webhook for pull request %d opened for %q (%s)", *hook.Number, *hook.Repo.FullName, *hook.PullRequest.Head.SHA)

	repo := GetRepo(ctx, *hook.Repo.FullName)
	if repo == nil {
		log.Errorf(ctx, "unknown repo")
		// TODO: delete webhook?
		return
	}

	user := GetUser(ctx, repo.UserID)
	if user == nil {
		log.Errorf(ctx, "unknown user %q", repo.UserID)
		// TODO: user who configured the hook has left?
		return
	}

	ghUser, ghRepo := repo.Split()
	client := newClient(ctx, user.GitHubToken)

	// TODO: Commit statuses are hidden when the PR is closed, and stick around
	// once they're reopened. Either the PR should stay open with a failed status,
	// and the status should be removed when PRs are re-enabled (ugh), or we can
	// just skip the status and comment and close.
	/*
		if _, _, err := client.Repositories.CreateStatus(ghUser, ghRepo, *hook.PullRequest.Head.SHA, &github.RepoStatus{
			State:       github.String("error"),
			TargetURL:   github.String("https://nopullrequests.appspot.com"),
			Description: github.String("This repository has chosen not to enable pull requests."), // TODO: configurable
			Context:     github.String("no pull requests"),
		}); err != nil {
			ctx.Errorf("failed to create status on %q: %v", *hook.PullRequest.Head.SHA, err)
		}
	*/

	if _, _, err := client.Issues.CreateComment(ctx, ghUser, ghRepo, *hook.Number, &github.IssueComment{
		Body: github.String(`
Thanks for your contribution :smiley:

This repository is a mirror of a KDE repository. This means that developers are not looking at pull requests created in GitHub, so I'm closing this pull request (actually a bot is doing it).
Please see https://community.kde.org/Infrastructure/Github_Mirror for details on how to contribute to this and other KDE projects.`),
	}); err != nil {
		log.Errorf(ctx, "failed to create comment: %v", err)
	}

	if _, _, err := client.PullRequests.Edit(ctx, ghUser, ghRepo, *hook.Number, &github.PullRequest{
		State: github.String("closed"),
	}); err != nil {
		log.Errorf(ctx, "failed to close pull request: %v", err)
	}
}

func revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	ctx := appengine.NewContext(r)
	uu := user.Current(ctx)
	if uu == nil || uu.Email != "tsdgeos@gmail.com" {
		log.Infof(ctx, "not logged in, redirecting...")
		loginURL, _ := user.LoginURL(ctx, r.URL.Path)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	u := GetUser(ctx, uu.ID)
	if u == nil {
		log.Infof(ctx, "unknown user, going to /start")
		http.Redirect(w, r, "/start", http.StatusSeeOther)
		return
	}

	client := newClient(ctx, u.GitHubToken)

	q := datastore.NewQuery("Repo").Filter("UserID =", uu.ID)
	for t := q.Run(ctx); ; {
		var r Repo
		if _, err := t.Next(&r); err == datastore.Done {
			break
		} else if err != nil {
			log.Errorf(ctx, "query: %v", err)
			renderError(w, "Error listing repos")
			return
		}
		ghUser, ghRepo := r.Split()
		if _, err := client.Repositories.DeleteHook(ctx, ghUser, ghRepo, r.WebhookID); err != nil {
			log.Errorf(ctx, "delete hook: %v", err)
			renderError(w, "Error deleting hook")
			return
		}
		if err := DeleteRepo(ctx, r.FullName); err != nil {
			log.Errorf(ctx, "delete repo: %v", err)
			renderError(w, "Error deleting repo entry")
			return
		}
	}

	url := fmt.Sprintf("https://api.github.com/applications/%s/tokens/%s", clientID, u.GitHubToken)
	log.Debugf(ctx, url)
	req, _ := http.NewRequest("DELETE", url, nil)
	req.SetBasicAuth(clientID, clientSecret)
	if resp, err := urlfetch.Client(ctx).Do(req); err != nil || resp.StatusCode != http.StatusNoContent {
		log.Errorf(ctx, "revoking token (%d): %v", resp.StatusCode, err)
		renderError(w, "Error revoking access")
		return
	}

	if err := DeleteUser(ctx, uu.ID); err != nil {
		log.Errorf(ctx, "delete user: %v", err)
		renderError(w, "Error deleting user entry")
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
