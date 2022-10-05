package hnap

type ClientInfo struct {
	DeviceName         string `json:"DeviceName"`
	ExtenderMacAddress string `json:"ExtenderMacAddress"`
	IPv4Address        string `json:"IPv4Address"`
	IPv6Address        string `json:"IPv6Address"`
	MacAddress         string `json:"MacAddress"`
	NickName           string `json:"NickName"`
	ReserveIP          string `json:"ReserveIP"`
	SignalStrength     string `json:"SignalStrength"`
	State              string `json:"State"`
	Type               string `json:"Type"`
}

type Clients struct {
	Envelope struct {
		Soap string `json:"-soap"`
		Xsd  string `json:"-xsd"`
		Xsi  string `json:"-xsi"`
		Body struct {
			GetClientInfoResponse struct {
				Xmlns           string `json:"-xmlns"`
				ClientInfoLists struct {
					ClientInfo []ClientInfo `json:"ClientInfo"`
				} `json:"ClientInfoLists"`
				GetClientInfoResult string `json:"GetClientInfoResult"`
			} `json:"GetClientInfoResponse"`
		} `json:"Body"`
	} `json:"Envelope"`
}
