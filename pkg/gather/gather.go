package gather

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	xj "github.com/basgys/goxml2json"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jahkeup/prometheus-moto-exporter/pkg/hnap"
)

const hSOAPAction = "SOAPAction"
const hHNAPAuth = "HNAP_AUTH"

type Gatherer struct {
	username string
	password string

	endpoint *url.URL

	mu         *sync.RWMutex
	privateKey []byte
	client     *http.Client
}

func New(endpoint *url.URL, username, password string) (*Gatherer, error) {
	return &Gatherer{
		username: username,
		password: password,
		endpoint: endpoint,

		mu: &sync.RWMutex{},

		client: &http.Client{
			Jar: func() http.CookieJar { j, _ := cookiejar.New(nil); return j }(),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: time.Second * 45,
		},
	}, nil
}

func (g *Gatherer) Login() error {
	const (
		loginAction = "Login"
		loginURI    = "http://purenetworks.com/HNAP1/Login"
	)

	log := logrus.WithField("action", "login")

	// 1. Request challenge, uid, and public key from endpoint. We have to use a
	// valid username to be given a login challenge.

	challenge := map[string]interface{}{
		// Wrap the message in the HNAP action name.
		"Login": map[string]string{
			"Action":   "request",
			"Username": g.username,
		},
	}
	data, err := json.Marshal(challenge)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, g.endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Add(hSOAPAction, loginURI)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	log.Debug("requesting challenge")
	resp, err := g.client.Do(req)
	if err != nil {
		logrus.WithError(err).Error("unable to request challenge")
		return err
	}
	log.Debug("accepting challenge")

	type LoginResponse struct {
		XMLName   xml.Name `xml:"LoginResponse"`
		Challenge string   `xml:"Challenge"`
		PublicKey string   `xml:"PublicKey"`
		Cookie    string   `xml:"Cookie"`
	}

	type Body struct {
		XMLName       xml.Name
		LoginResponse LoginResponse `xml:"LoginResponse"`
	}
	type MyRespEnvelope struct {
		XMLName xml.Name
		Body    Body
	}

	var soapResp MyRespEnvelope
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	err = xml.Unmarshal(b, &soapResp)
	if err != nil {
		return err
	}
	hnapResponse := soapResp.Body
	log.WithFields(logrus.Fields{
		"challenge": hnapResponse.LoginResponse.Challenge,
		"uid":       hnapResponse.LoginResponse.Cookie,
	}).Trace("computing response")

	// 2. Compute challenge response by making its "private key". We'll use it
	// to submit a login challenge response to complete the login-flow.

	privateKey, err := digest(hnapResponse.LoginResponse.Challenge, []byte(hnapResponse.LoginResponse.PublicKey+g.password))
	if err != nil {
		return err
	}

	passKey, err := digest(hnapResponse.LoginResponse.Challenge, privateKey)
	if err != nil {
		return err
	}

	uidCookie := &http.Cookie{
		Name:  "uid",
		Value: string(hnapResponse.LoginResponse.Cookie),
	}
	pkCookie := &http.Cookie{
		Name:  "PrivateKey",
		Value: string(privateKey),
	}

	// 3. Submit response to challenge to complete the login.
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>login</Action><Username>Admin</Username><LoginPassword>%s</LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>`, string(passKey))

	req, err = g.requestWithKey(loginAction, loginURI, bytes.NewReader([]byte(body)), privateKey)
	if err != nil {
		return err
	}

	req.AddCookie(uidCookie)
	req.AddCookie(pkCookie)

	log.Debug("submitting response")
	resp, err = g.client.Do(req)
	if err != nil {
		log.WithError(err).Error("unable to login")
		return err
	}
	resp.Body.Close()

	log.WithFields(logrus.Fields{
		"action":      loginURI,
		"action.call": "login",
		"status":      resp.StatusCode,
	}).Debug("response sent")

	if resp.StatusCode != http.StatusOK {
		return errors.New("challenge response rejected")
	}

	// Update client to use our new session

	log.Trace("updating gatherer HTTP client")
	// Acquire lock to modify the underlying client data.
	g.mu.Lock()
	{
		// Record the Private Key that's for this login.
		g.privateKey = privateKey
		g.client.Jar.SetCookies(g.endpoint, []*http.Cookie{uidCookie, pkCookie})
	}
	g.mu.Unlock()
	log.Trace("gatherer configured with new login session")

	return nil
}

func (g *Gatherer) getInterfaceStatistics() ([]byte, error) {
	const actionName = "GetMultipleHNAPs"
	const actionURI = "http://purenetworks.com/HNAP1/" + actionName

	log := logrus.WithField("action", actionURI)

	data := "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetMultipleHNAPs xmlns=\"http://purenetworks.com/HNAP1/\"><GetInterfaceStatistics xmlns=\"http://purenetworks.com/HNAP1/\"><Interface>WAN</Interface></GetInterfaceStatistics><GetInterfaceStatistics xmlns=\"http://purenetworks.com/HNAP1/\"><Interface>LAN</Interface></GetInterfaceStatistics><GetInterfaceStatistics xmlns=\"http://purenetworks.com/HNAP1/\"><Interface>WLAN2.4G</Interface></GetInterfaceStatistics><GetInterfaceStatistics xmlns=\"http://purenetworks.com/HNAP1/\"><Interface>WLAN5G</Interface></GetInterfaceStatistics></GetMultipleHNAPs></soap:Body></soap:Envelope>"

	g.mu.RLock()
	unlock := unlockGuarded(g.mu.RLocker())
	defer unlock()

	req, err := g.request(actionName, actionURI, bytes.NewReader([]byte(data)))
	if err != nil {
		log.Error("unable to prepare request")
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		log.WithError(err).Error("unable to complete request")
		return nil, err
	}
	unlock()

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	xmlBody := strings.NewReader(string(b))
	jsonBody, err := xj.Convert(xmlBody)
	return jsonBody.Bytes(), err
}

func (g *Gatherer) GetLoginStatus() (int, error) {
	const actionName = "GetCurrentInternetStatus"
	const actionURI = "http://purenetworks.com/HNAP1/" + actionName

	log := logrus.WithField("action", actionURI)

	data := "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetCurrentInternetStatus xmlns=\"http://purenetworks.com/HNAP1/\"><InternetStatus>true</InternetStatus></GetCurrentInternetStatus></soap:Body></soap:Envelope>"

	g.mu.RLock()
	unlock := unlockGuarded(g.mu.RLocker())
	defer unlock()

	req, err := g.request(actionName, actionURI, bytes.NewReader([]byte(data)))
	if err != nil {
		log.Error("unable to prepare request")
		return -1, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		log.WithError(err).Error("unable to complete request")
		return -1, err
	}
	unlock()

	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func (g *Gatherer) getClientInfo() ([]byte, error) {
	const actionName = "GetClientInfo"
	const actionURI = "http://purenetworks.com/HNAP1/" + actionName

	log := logrus.WithField("action", actionURI)

	data := "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetClientInfo xmlns=\"http://purenetworks.com/HNAP1/\"/></soap:Body></soap:Envelope>"

	g.mu.RLock()
	unlock := unlockGuarded(g.mu.RLocker())
	defer unlock()

	req, err := g.request(actionName, actionURI, bytes.NewReader([]byte(data)))
	if err != nil {
		log.Error("unable to prepare request")
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		log.WithError(err).Error("unable to complete request")
		return nil, err
	}
	unlock()

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	xmlBody := strings.NewReader(string(b))
	jsonBody, err := xj.Convert(xmlBody)
	return jsonBody.Bytes(), err
}
func (g *Gatherer) getInternetConnection() ([]byte, error) {
	const actionName = "GetCurrentInternetStatus"
	const actionURI = "http://purenetworks.com/HNAP1/" + actionName

	log := logrus.WithField("action", actionURI)

	data := "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetCurrentInternetStatus xmlns=\"http://purenetworks.com/HNAP1/\"><InternetStatus>true</InternetStatus></GetCurrentInternetStatus></soap:Body></soap:Envelope>"

	g.mu.RLock()
	unlock := unlockGuarded(g.mu.RLocker())
	defer unlock()

	req, err := g.request(actionName, actionURI, bytes.NewReader([]byte(data)))
	if err != nil {
		log.Error("unable to prepare request")
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		log.WithError(err).Error("unable to complete request")
		return nil, err
	}
	unlock()

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	xmlBody := strings.NewReader(string(b))
	jsonBody, err := xj.Convert(xmlBody)
	return jsonBody.Bytes(), err
}
func (g *Gatherer) getDeviceSettings() ([]byte, error) {
	const actionName = "GetDeviceSettings"
	const actionURI = "http://purenetworks.com/HNAP1/" + actionName

	log := logrus.WithField("action", actionURI)

	data := "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetDeviceSettings xmlns=\"http://purenetworks.com/HNAP1/\" /></soap:Body></soap:Envelope>"

	g.mu.RLock()
	unlock := unlockGuarded(g.mu.RLocker())
	defer unlock()

	req, err := g.request(actionName, actionURI, bytes.NewReader([]byte(data)))
	if err != nil {
		log.Error("unable to prepare request")
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		log.WithError(err).Error("unable to complete request")
		return nil, err
	}
	unlock()

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	xmlBody := strings.NewReader(string(b))
	jsonBody, err := xj.Convert(xmlBody)
	return jsonBody.Bytes(), err
}

func (g *Gatherer) Gather() (*Collection, error) {
	connectionInfo, err := g.getInterfaceStatistics()
	if err != nil {
		return nil, err
	}

	internetConnectionStatus, err := g.getInternetConnection()
	if err != nil {
		return nil, err
	}
	var response hnap.GetMultipleHNAPsResponse
	response.HNAP = make(map[string]json.RawMessage)
	response.HNAP["ConnectionInfo"] = connectionInfo
	var InternetConnectionResponse hnap.InternetConnectionResponse
	err = json.Unmarshal(internetConnectionStatus, &InternetConnectionResponse)
	if err != nil {
		return nil, err
	}
	online := InternetConnectionResponse.Envelope.Body.GetCurrentInternetStatusResponse.GetCurrentInternetStatusResult == "OK_CONNECTED"
	// device information
	info, err := g.getDeviceSettings()
	if err != nil {
		return nil, err
	}

	var software hnap.DeviceInformation
	err = json.Unmarshal(info, &software)
	if err != nil {
		return nil, err
	}

	// Client Information
	clientAction, err := g.getClientInfo()
	if err != nil {
		return nil, err
	}
	var clients hnap.Clients
	err = json.Unmarshal(clientAction, &clients)
	if err != nil {
		return nil, err
	}

	for k, v := range response.HNAP {
		// Raw JSON string
		logrus.WithField("name", k).Tracef("%s", v)
	}

	var (
		connection hnap.ConnectionResponse
	)

	parses := map[string]interface{}{
		"ConnectionInfo": &connection,
	}

	for name, binding := range parses {
		jsonData, err := response.GetJSON(name)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch data: %w", err)
		}

		err = json.Unmarshal(jsonData, binding)
		if err != nil {
			return nil, fmt.Errorf("cannot parse data: %w", err)
		}
	}

	return &Collection{
		//Upstream: upstream.Channels,
		//Downstream: downstream.Channels,
		Connection:      connection.Envelope.Body.GetMultipleHNAPsResponse.GetInterfaceStatisticsResponse,
		Online:          online,
		Clients:         clients,
		SoftwareVersion: software.Envelope.Body.GetDeviceSettingsResponse.FirmwareVersion,
		SpecVersion:     software.Envelope.Body.GetDeviceSettingsResponse.ModelName,
		HardwareVersion: software.Envelope.Body.GetDeviceSettingsResponse.HardwareVersion,
		SerialNumber:    software.Envelope.Body.GetDeviceSettingsResponse.Dcs,

		CustomerVersion: software.Envelope.Body.GetDeviceSettingsResponse.BundleName,
		//BootFile:        startup.ConfigurationFileName,
	}, nil
}

func (g *Gatherer) request(actionName, actionURI string, data io.Reader) (*http.Request, error) {
	return g.requestWithKey(actionName, actionURI, data, g.privateKey)
}

func (g *Gatherer) requestWithKey(actionName, actionURI string, data io.Reader, key []byte) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, g.endpoint.String(), data)
	if err != nil {
		return nil, err
	}

	hnapAuth, ts, err := digestAuth(actionURI, key)
	if err != nil {
		return nil, err
	}

	req.Header.Add(hSOAPAction, fmt.Sprintf(`%s`, actionURI))
	req.Header.Add(hHNAPAuth, fmt.Sprintf("%s %d", string(hnapAuth), ts))

	req.Header.Add("Content-Type", "text/xml")
	req.Header.Add("Accept", "text/xml")

	return req, nil
}

// Single use Unlock()er.
func unlockGuarded(lock sync.Locker) func() {
	var singleUse sync.Once
	return func() { singleUse.Do(lock.Unlock) }
}

// digestAuth prepares an authentication digest for calling a given SOAPAction.
func digestAuth(actionURI string, key []byte) ([]byte, int64, error) {
	ts := time.Now().Unix()
	data, err := digest(fmt.Sprintf(`%d"%s"`, ts, actionURI), key)
	return data, ts, err
}

// digest prepares an authentication digest for use with HNAP.
func digest(msg string, key []byte) ([]byte, error) {
	mac := hmac.New(md5.New, key)
	_, err := fmt.Fprint(mac, msg)
	if err != nil {
		return nil, err
	}
	digestData := mac.Sum(nil)

	digestHex := make([]byte, hex.EncodedLen(len(digestData)))
	hex.Encode(digestHex, digestData)
	return bytes.ToUpper(digestHex), nil
}
