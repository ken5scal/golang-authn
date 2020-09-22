package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session ID")
	}

	return nil
}

func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Error in createTOken when signing token: %w", err)
	}
	return signedToken, nil
}

var currentKid = ""

type key struct {
	key     []byte
	created time.Time
}

var keys = map[string]key{} // usually it's in db

func generateNewKey() error {
	newKey := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return fmt.Errorf("Error in generateNewKey while genrating simpleKey: %w", err)
	}

	uid := uuid.NewV4()
	keys[uid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}

	currentKid = uid.String()
	return nil
}

func parseToken(signedToken string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithm")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid kid")
		}

		k, ok := keys[kid] // Get from db
		if !ok {
			return nil, fmt.Errorf("Invalid simpleKey ID")
		}

		return k.key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error in parseToken while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}

	return t.Claims.(*UserClaims), nil
}

type person struct {
	First string
}

// session samples: https://github.com/GoesToEleven/SummerBootCamp/tree/master/05_golang/02/03/11_sessions
func main() {

	msg := "hello world"
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

	for i := 1; i <= 64; i++ {
		simpleKey = append(simpleKey, byte(i))
	}

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

	http.HandleFunc("/", hoge)
	http.HandleFunc("/submit", fuga)
	http.ListenAndServe(":8080", nil)
	//http.HandleFunc("/encode", foo)
	//http.HandleFunc("/decode", bar)
	//http.ListenAndServe(":8080", nil)
}

var simpleKey = []byte{}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha256.New, keys[currentKid].key)
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

func hoge(writer http.ResponseWriter, request *http.Request) {
	c, err := request.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	isEqual := false
	xs := strings.SplitN(c.Value, "|", 2)
	if len(xs) == 2 {
		cCode := xs[0]
		cEmail := xs[1]

		code := getCode(cEmail)
		isEqual = hmac.Equal([]byte(cCode), []byte(code))
	}

	message := "Not logged in"
	if isEqual {
		message = "logged in"
	}

	html := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8"
	<title>HMAC Example</title>
</head>
  <body>
	<p>Cookie value: ` + c.Value + `</p>
	<p>` + message + `</p>
    <form action="/submit" method="post">
      <input type="email" name="email">
      <input type="submit">
    </form>
  </body>
</html>`
	io.WriteString(writer, html)
}

func fuga(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("--------------------- fuga function -------------")
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	fmt.Printf("email: " + email)
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c := http.Cookie{
		Name:  "session",
		Value: getCode(email) + "|" + email,
	}
	fmt.Printf("cookie: " + c.Value)
	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getCode(email string) string {
	h := hmac.New(sha256.New, []byte("this is kind of key"))
	h.Write([]byte(email))
	return fmt.Sprintf("%x", h.Sum(nil))
}
