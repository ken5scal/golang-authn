package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

const myKey = "this is kind of key"
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var db = map[string]user{}                 // key is email, value is user
var oauthConnections = map[string]string{} //key is uid frm oauth provider, value should be userIDs in your own system
var session = map[string]string{}          // key is sessionid, value is email
var pkce_code_verifier string
var oauthStateExp = map[string]time.Time{} // key is uuid from oauth login state, value is exp time

// https://developer.amazon.com/
var amazonOAuthConfig = &oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.32871ba0533c485dae7f0a95db3ed766",
	ClientSecret: "some-secret",
	Endpoint:     amazon.Endpoint,
	Scopes:       []string{"profile"},
	RedirectURL:  "http://localhost:8080/oauth/amazon/receive",
}

type amazonResponse struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}

type user struct {
	password []byte
	First    string
}

type UserClaims struct {
	jwt.StandardClaims
	SessionID string
	//sid       string
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == "" {
		return fmt.Errorf("Invalid session ID")
	}

	return nil
}

func createSession(email string, w http.ResponseWriter) error {
	sUUID := uuid.NewV4().String()
	token, err := createToken(sUUID)
	if err != nil {
		return fmt.Errorf("couldn't creat token in createSession %w", err)
	}

	session[sUUID] = email // store in redis
	http.SetCookie(w, &http.Cookie{
		Name:  "sessionID",
		Value: token,
		Path:  "/",
	})

	return nil
}

func createToken(sid string) (string, error) {
	fmt.Println("created sid: " + sid)
	cc := &UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
		SessionID: sid,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	return token.SignedString([]byte(myKey))

	//construct HMAC Sig as Token
	//mac := hmac.New(sha256.New, []byte(myKey))
	//mac.Write([]byte(sid))
	//signedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	//return signedMac + "|" + sid
}

func parseToken(ss string) (string, error) {
	token, err := jwt.ParseWithClaims(ss, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims failed due to different alg used")
		}

		return []byte(myKey), nil
	})

	if err != nil {
		return "", fmt.Errorf("Couldn't ParseWithClaims: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parseToken")
	}

	return token.Claims.(*UserClaims).SessionID, nil

	//construct HMAC Sig as Token
	//xs := strings.SplitN(ss, "|", 2)
	//if len(xs) != 2 {
	//	return "", fmt.Errorf("stop hacking me wrong number of items in string parsetoken")
	//}
	//xb, err := base64.StdEncoding.DecodeString(xs[0])
	//if err != nil {
	//	return "", fmt.Errorf("cou;dn't parseToken decode string %w", err)
	//}
	//mac := hmac.New(sha256.New, []byte(myKey))
	//mac.Write([]byte(xs[1]))
	//
	//if !hmac.Equal(xb, mac.Sum(nil)) {
	//	return "", fmt.Errorf("couldn't parseTOken not equal signed sid and sid")
	//}
	//
	//return xs[1], nil
}

type person struct {
	First string
}

// session samples: https://github.com/GoesToEleven/SummerBootCamp/tree/master/05_golang/02/03/11_sessions
func main() {
	simpleTest()

	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/oauth/amazon/login", startAmazonOAuth)
	http.HandleFunc("/oauth/amazon/receive", completeAmazonOAuth)
	http.HandleFunc("/oauth/amazon/register", registerAmazon)
	http.HandleFunc("/partial-register", partialRegister)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sessionID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	var e string
	var f string
	if sessionID != "" {
		e = session[sessionID]
	}

	if _, ok := db[e]; ok {
		f = db[e].First
	}

	msg := r.FormValue("msg")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Document</title>
</head>
<body>
<h1>If you have a session, here is  the Name: %s</h1>
	<h1>If you have a session, here is  the email: %s</h1>
	<h1>If there was any error, here it is: %s</h1>
	<h1>Register</h1>
    <form action="/register" method="POST">
	<label for="first">First</label>
	<input type="text" name="first" placeholder="First" id="first">
        <input type="email" name="e">
        <input type="password" name="p">
        <input type="submit">
    </form>
	<h1>Log In</h1>
    <form action="/login" method="POST">
        <input type="email" name="e">
        <input type="password" name="p">
        <input type="submit">
    </form>
	<h1>Log In w/ Amazon</h1>
	<form action="/oauth/amazon/login" method="POST">
		<input type="submit" value="Login With Amazon">
    </form>
	<h1>Log Out</h1>
	<form action="/logout" method="POST">
        <input type="submit" value="logout">
	</form>
</body>
</html>`, f, e, msg)
}

func startAmazonOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	state := uuid.NewV4().String()
	oauthStateExp[state] = time.Now().Add(time.Minute)

	ra := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 43)
	for i := range b {
		b[i] = letterBytes[ra.Intn(len(letterBytes))]
	}
	pkce_code_verifier = string(b)

	h := sha256.New()
	h.Write(b)
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))

	opt1 := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	opt2 := oauth2.SetAuthURLParam("code_challenge_method", "S256")
	redirectURL := amazonOAuthConfig.AuthCodeURL(state, opt1, opt2)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeAmazonOAuth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	if state == "" || code == "" {
		msg := url.QueryEscape("state or code was empty in Amazon Login")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if t, ok := oauthStateExp[state]; !ok || time.Now().After(t) {
		msg := url.QueryEscape("state is either empty or expired")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	opt1 := oauth2.SetAuthURLParam("code_verifier", pkce_code_verifier)

	t, err := amazonOAuthConfig.Exchange(r.Context(), code, opt1)
	if err != nil {
		msg := url.QueryEscape("couldn't do oauth exchange" + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	ts := amazonOAuthConfig.TokenSource(r.Context(), t)
	c := oauth2.NewClient(r.Context(), ts)

	resp, err := c.Get("https://api.amazon.com/user/profile")
	if err != nil {
		msg := url.QueryEscape("couldnt get an amazon user" + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := url.QueryEscape("status code not good: " + string(resp.StatusCode))
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	var aws amazonResponse
	if err := json.NewDecoder(resp.Body).Decode(&aws); err != nil {
		http.Error(w, "AWS Invalid response", http.StatusInternalServerError)
		return
	}

	email, ok := oauthConnections[aws.UserID]

	if !ok { // then register user
		uv := url.Values{}
		uv.Add("sst", aws.UserID)
		uv.Add("name", aws.Name)
		uv.Add("email", aws.Email)
		http.Redirect(w, r, "/partial-register?"+uv.Encode(), http.StatusSeeOther)
	}

	if err := createSession(email, w); err != nil { // if user is already registered
		log.Println("couldn't create session in amaon", err)
		msg := url.QueryEscape("our server din't get enough lunch whatever ")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in" + email)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func partialRegister(w http.ResponseWriter, r *http.Request) {
	oauthID := r.FormValue("sst")
	name := r.FormValue("name")
	email := r.FormValue("email")

	if oauthID == "" {
		log.Println("couldn't get set in partial register")
		msg := url.QueryEscape("failed")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Document</title>
</head>
<body>
	<form action="/oauth/amazon/register" method="POST">
		<label for="firstName">FIRST NAME</label>
		<input type="text" name="first" id="firstName" value="%s">
        <label for="Email">Email</label>
		<input type="text" name="email" id="Email" value="%s">
		<input type="hidden" name="oauthID" id="oauthID" value="%s">
		<input type="submit" value="Register With Amazon">
    </form>
</body>
</html>`, name, email, oauthID)
}

func registerAmazon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	first := r.FormValue("first")
	email := r.FormValue("email")
	amazonUID := r.FormValue("oauthID")
	if first == "" || email == "" || amazonUID == "" {
		errorMsg := url.QueryEscape("your first, email, or OAUTHID need to not be empty")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	db[email] = user{First: first} // register user in DB
	oauthConnections[amazonUID] = email

	if err := createSession(email, w); err != nil { // after registration (db transaction), create a session
		errorMsg := url.QueryEscape("couldn't createSerssion")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		errorMsg := url.QueryEscape("your email need to not be empty")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		errorMsg := url.QueryEscape("your password need to not be empty")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	f := r.FormValue("first")
	if f == "" {
		errorMsg := url.QueryEscape("your first name need to not be empty")
		http.Redirect(w, r, "/?msg="+errorMsg, http.StatusSeeOther)
		return
	}

	bsp, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		errorMsg := "internal server error"
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	db[e] = user{
		First:    f,
		password: bsp,
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your email need to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your password need to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[e]; !ok {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if err := bcrypt.CompareHashAndPassword(db[e].password, []byte(p)); err != nil {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if err := createSession(e, w); err != nil {
		log.Println("couldn't createSession in login", err)
		msg := url.QueryEscape("our server didn't get enough lunch and is not working 200% right now. Try bak later")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + e)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sessionID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	delete(session, sessionID)
	c.MaxAge = -1
	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func simpleTest() {
	verifier := "5CFCAiZC0g0OA-jmBmmjTBZiyPCQsnq_2q5k9fD-aAY"
	msg := "Fw7s3XHRVb2m1nT7s646UrYiYLMJ54as0ZIU_injyqw"
	h2 := sha256.New()
	h2.Write([]byte(verifier))
	e := base64.URLEncoding.EncodeToString(h2.Sum(nil))
	fmt.Println(e)

	// ---------------------------
	// Base 64
	// ---------------------------
	encoded := base64.URLEncoding.EncodeToString([]byte(msg))
	fmt.Println("base64 url encoding: ", encoded)
	decoded, _ := base64.URLEncoding.DecodeString(encoded)
	fmt.Println("base64 url decoding: ", string(decoded))
	fmt.Println(base64.StdEncoding.EncodeToString([]byte("user:pass")))

	// ---------------------------
	// encrypt / decrypt
	// ---------------------------
	pwd := "pwd"
	bs, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
	if err != nil {
		log.Fatalln("could'nt bcrypt password", err)
	}
	bs = bs[:16]
	r, err := enDecode(bs, msg)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("encrypt with AES: ", string(r))
	r, err = enDecode(bs, string(r))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("decrypt with AES: ", string(r))

	wtr := &bytes.Buffer{}
	encWriter, err := encryptWrite(wtr, bs)
	if _, err := io.WriteString(encWriter, msg); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("using encrypt with io writer: ", wtr.String())

	// ---------------------------
	// Sha256
	// ---------------------------
	f, err := os.Open("README.md")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatalln("could'nt io.copy", err)
	}

	fmt.Printf("here's the type Before Sum: %T\n", h)
	xb := h.Sum(nil)
	fmt.Printf("here's the type AFTER Sum: %T\n", xb)
	fmt.Printf("here's the value AFTER Sum: %x\n", xb)

	pass := "abcdef"
	fmt.Println(pass)
	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	if err := comparePassword(pass, hashedPass); err != nil {
		log.Fatalln("not logged in")
	}

	log.Println("logged in")
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte(myKey))
	if _, err := h.Write(msg); err != nil {
		return nil, fmt.Errorf("Error in signMessage while hasing msg : %w", err)
	}
	return h.Sum(nil), nil
}

func checkSig(msg, sig []byte) (bool, error) {
	s, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSig while getting signature of message: %w", err)
	}
	return hmac.Equal(s, sig), nil
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

func comparePassword(pwd string, hashedPass []byte) error {
	if err := bcrypt.CompareHashAndPassword(hashedPass, []byte(pwd)); err != nil {
		return fmt.Errorf("Invalidd pwd: %w", err)
	}
	return nil
}

func foo(w http.ResponseWriter, r *http.Request) {
	p1 := person{
		First: "ken5scal",
	}

	p2 := person{
		First: "ken5scal",
	}

	xp1 := []person{p1, p2}

	if err := json.NewEncoder(w).Encode(xp1); err != nil {
		log.Println("encoded bad data", err)
	}
}

func bar(w http.ResponseWriter, r *http.Request) {
	var xp1 []person
	if err := json.NewDecoder(r.Body).Decode(&xp1); err != nil {
		log.Println("decoded bad data", err)
	}

	log.Println("Person:", xp1)
}

func enDecode(kye []byte, input string) ([]byte, error) {
	b, err := aes.NewCipher(kye)
	if err != nil {
		return nil, fmt.Errorf("could'nt newCiper %w", err)
	}
	buf := &bytes.Buffer{}
	iv := make([]byte, aes.BlockSize)
	//_, err = io.ReadFull(rand.Reader, iv)

	s := cipher.NewCTR(b, iv)
	sw := cipher.StreamWriter{
		S: s,
		W: buf,
	}
	if _, err := sw.Write([]byte(input)); err != nil {
		return nil, fmt.Errorf("couldn't write to streamwriter: %w", err)
	}

	return buf.Bytes(), nil
}

func encryptWrite(w io.WriterTo, key []byte) (io.Writer, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't newCipher %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	s := cipher.NewCTR(b, iv)
	buff := &bytes.Buffer{}
	return cipher.StreamWriter{S: s, W: buff}, nil
}
