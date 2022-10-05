package hnap

import (
	"strconv"

	"github.com/pkg/errors"
)

type ConnectionInfo struct {
	ID                int64
	LockStatus        string
	Modulation        string
	Channel           int64
	SymbolRate        int64
	Frequency         float64
	DecibelMillivolts float64
}
type StatisticInfo struct {
	RXDropped string `json:"RXDropped"`
	Session   string `json:"Session"`
	Errors    string `json:"Errors"`
	Sent      string `json:"Sent"`
	Received  string `json:"Received"`
	TXPackets string `json:"TXPackets"`
	RXPackets string `json:"RXPackets"`
	TXDropped string `json:"TXDropped"`
}

type InterfaceStatistics struct {
	StatisticInfo StatisticInfo `json:"StatisticInfo"`
}

type GetInterfaceStatisticsResponse struct {
	HistoryAbilityInterval       string              `json:"HistoryAbilityInterval"`
	GetInterfaceStatisticsResult string              `json:"GetInterfaceStatisticsResult"`
	MACAddress                   string              `json:"MACAddress"`
	Interface                    string              `json:"Interface"`
	InterfaceStatistics          InterfaceStatistics `json:"InterfaceStatistics"`
	HistoryAbility               string              `json:"HistoryAbility"`
	HistoryAbilityRecords        string              `json:"HistoryAbilityRecords"`
}

func (info *ConnectionInfo) Parse(row []string) error {
	const dataSize = 8 // 1 unused field, not sure what it is!

	const (
		idField = iota
		lockStatusField
		modulationField
		channelIDField
		symbolRateField
		frequencyField
		dbmvField
	)

	if len(row) != dataSize {
		return errors.Errorf("invalid data size: expected %d but found %d", dataSize, len(row))
	}

	var err error

	info.ID, err = strconv.ParseInt(row[idField], 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse ID")
	}

	info.LockStatus = row[lockStatusField]
	info.Modulation = row[modulationField]

	info.Channel, err = strconv.ParseInt(row[channelIDField], 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse channel ID")
	}

	info.SymbolRate, err = strconv.ParseInt(row[symbolRateField], 10, 64)
	if err != nil {
		return errors.Wrap(err, "parse symbol rate")
	}
	// ksym -> sym
	info.SymbolRate *= 1000

	info.Frequency, err = strconv.ParseFloat(row[frequencyField], 64)
	if err != nil {
		return errors.Wrap(err, "parse frequency")
	}
	info.Frequency *= 1000 * 1000 // Mhz -> hz

	info.DecibelMillivolts, err = strconv.ParseFloat(row[dbmvField], 64)
	if err != nil {
		return errors.Wrap(err, "parse dBmV")
	}

	return nil
}

type ConnectionResponse struct {
	Envelope struct {
		Xsi  string `json:"-xsi"`
		Xsd  string `json:"-xsd"`
		Soap string `json:"-soap"`
		Body struct {
			GetMultipleHNAPsResponse struct {
				Xmlns                          string                           `json:"-xmlns"`
				GetMultipleHNAPsResult         string                           `json:"GetMultipleHNAPsResult"`
				GetInterfaceStatisticsResponse []GetInterfaceStatisticsResponse `json:"GetInterfaceStatisticsResponse"`
			} `json:"GetMultipleHNAPsResponse"`
		} `json:"Body"`
	} `json:"Envelope"`
}
