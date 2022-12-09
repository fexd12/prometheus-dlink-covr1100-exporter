package hnap

type GetCurrentInternetStatusResponse struct {
	Xmlns                          string `json:"-xmlns"`
	GetCurrentInternetStatusResult string `json:"GetCurrentInternetStatusResult"`
}

type InternetConnectionResponse struct {
	Envelope struct {
		Soap string `json:"-soap"`
		Xsd  string `json:"-xsd"`
		Xsi  string `json:"-xsi"`
		Body struct {
			GetCurrentInternetStatusResponse GetCurrentInternetStatusResponse `json:"GetCurrentInternetStatusResponse"`
		} `json:"Body"`
	} `json:"Envelope"`
}

type GetInternetConnUpTimeResponse struct {
	Xmlns                       string `json:"-xmlns"`
	GetInternetConnUpTimeResult string `json:"GetInternetConnUpTimeResult"`
	UpTime string `json:"UpTime"`
}

type InternetConnUpTimeResponse struct {
	Envelope struct {
		Soap string `json:"-soap"`
		Xsd  string `json:"-xsd"`
		Xsi  string `json:"-xsi"`
		Body struct {
			GetInternetConnUpTimeResponse GetInternetConnUpTimeResponse `json:"GetInternetConnUpTimeResponse"`
		} `json:"Body"`
	} `json:"Envelope"`
}
