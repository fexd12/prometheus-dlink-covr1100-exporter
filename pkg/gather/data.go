package gather

import "github.com/jahkeup/prometheus-moto-exporter/pkg/hnap"

type Collection struct {
	Upstream   []hnap.UpstreamInfo
	Downstream []hnap.DownstreamInfo
	Connection []hnap.GetInterfaceStatisticsResponse
	Online     bool
	Clients    hnap.Clients

	SerialNumber    string
	SoftwareVersion string
	HardwareVersion string
	SpecVersion     string

	BootFile        string
	CustomerVersion string
}
