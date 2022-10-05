package hnap

type DeviceInformation struct {
	Envelope struct {
		Soap string `json:"-soap"`
		Xsd  string `json:"-xsd"`
		Xsi  string `json:"-xsi"`
		Body struct {
			GetDeviceSettingsResponse struct {
				Xmlns                   string `json:"-xmlns"`
				BackOff                 string `json:"BackOff"`
				BundleName              string `json:"BundleName"`
				Captcha                 string `json:"CAPTCHA"`
				Dcs                     string `json:"DCS"`
				DeviceMACAddress        string `json:"DeviceMACAddress"`
				DeviceName              string `json:"DeviceName"`
				FirmwareRegion          string `json:"FirmwareRegion"`
				FirmwareVariant         string `json:"FirmwareVariant"`
				FirmwareVersion         string `json:"FirmwareVersion"`
				GetDeviceSettingsResult string `json:"GetDeviceSettingsResult"`
				HardwareVersion         string `json:"HardwareVersion"`
				HTTPRedirect            string `json:"HttpRedirect"`
				LatestFirmwareVersion   string `json:"LatestFirmwareVersion"`
				ModelDescription        string `json:"ModelDescription"`
				ModelName               string `json:"ModelName"`
				PresentationURL         string `json:"PresentationURL"`
				RequireLevel            string `json:"RequireLevel"`
				SOAPActions             struct {
					String []string `json:"string"`
				} `json:"SOAPActions"`
				Ssl                     string `json:"SSL"`
				SharePortStatus         string `json:"SharePortStatus"`
				SubDeviceURLs           string `json:"SubDeviceURLs"`
				SupportMyDLinkAbilities string `json:"SupportMyDLinkAbilities"`
				SupportMyDLinkStatus    string `json:"SupportMyDLinkStatus"`
				TZLocation              string `json:"TZLocation"`
				Tasks                   string `json:"Tasks"`
				Type                    string `json:"Type"`
				VendorName              string `json:"VendorName"`
			} `json:"GetDeviceSettingsResponse"`
		} `json:"Body"`
	} `json:"Envelope"`
}
