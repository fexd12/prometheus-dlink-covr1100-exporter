package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/jahkeup/prometheus-moto-exporter/pkg/gather"
	"github.com/jahkeup/prometheus-moto-exporter/pkg/hnap"
)

const (
	labelChannel         = "channel"
	labelChannelID       = "channel_id"
	labelModulation      = "modulation"
	labelSerial          = "serial"
	labelSoftwareVersion = "software_version"
	labelHardwareVersion = "hardware_version"
	labelCustomerVersion = "customer_version"
	labelSpecVersion     = "spec_version"
	labelBootFile        = "boot_file"
	labelFrequency       = "device"
	labelInterfaceId     = "interface_id"
	namespace            = "node"
)

type serverRegistry interface {
	prometheus.Gatherer
	prometheus.Registerer
}

type Server struct {
	gatherer   *gather.Gatherer
	clients    *clientMetrics
	upstream   *upstreamMetrics
	downstream *downstreamMetrics
	device     *deviceMetrics
	connection *connectionMetrics
	meta       *metaMetrics

	registry serverRegistry
}

func NewServer(gatherer *gather.Gatherer) (*Server, error) {
	s := &Server{
		gatherer:   gatherer,
		clients:    NewClientMetric(),
		upstream:   NewUpstreamMetrics(),
		connection: NewConnectionMetrics(),
		downstream: NewDownstreamMetrics(),
		device:     NewDeviceMetrics(),
		meta:       NewMetaMetrics(),
	}

	// Add the metrics to the default registerer, user can change this later if
	// they're using another.

	// NOTE: this will cause the default registry to contain the metric even if
	// the user does change it. The usage here doesn't bump into any issue with
	// this.
	reg, ok := prometheus.DefaultRegisterer.(serverRegistry)
	if !ok {
		return nil, errors.New("unable to use default registry")
	}
	err := s.RegisterMetrics(reg)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// RegisterMetrics adds the Servers managed metrics to the provided registry and
// updates itself to track this registry.
func (s *Server) RegisterMetrics(reg serverRegistry) error {
	s.registry = reg

	groups := []interface {
		RegisterMetrics(prometheus.Registerer) error
	}{
		s.upstream,
		s.downstream,
		s.connection,
		s.device,
		s.clients,
		s.meta,
	}

	for _, group := range groups {
		err := group.RegisterMetrics(reg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) Collect() error {
	// TODO: track requests separately
	spanTimer := prometheus.NewTimer(s.meta.CollectionTime)
	defer func() {
		spanTimer.ObserveDuration()
		logrus.WithFields(logrus.Fields{
			"context": "collect",
		}).Info("finished collecting")
	}()

	err := s.gatherer.Login()
	if err != nil {
		return err
	}

	collect, err := &gather.Collection{}, nil

	collect, err = s.gatherer.Gather()

	if err != nil {
		return err
	}

	for _, info := range collect.Downstream {
		s.downstream.RecordOne(&info)
	}

	for _, info := range collect.Upstream {
		s.upstream.RecordOne(&info)
	}

	for _, info := range collect.Connection {
		s.connection.RecordOne(&info)
	}
	iFace := map[string]float64{}
	for _, info := range collect.Clients {
		if _, ok := iFace[info.Type]; !ok {
			iFace[info.Type] = 0
		}
		iFace[info.Type]++
		s.clients.RecordOne(&info)
	}
	for k, v := range iFace {
		s.clients.RecordType(k, v)
	}
	s.device.RecordOne(collect)

	return nil
}

func (s *Server) Run(ctx context.Context, addr string) error {
	log := logrus.WithField("context", "server")

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{
		ErrorLog:      log.WithField("handler", "prometheus"),
		ErrorHandling: promhttp.ContinueOnError,
	}))

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Infof("starting server on %s", addr)

	var serverErr error
	go func() {
		serverErr := srv.ListenAndServe()
		if serverErr != nil && serverErr != http.ErrServerClosed {
			log.WithError(serverErr).Error("server returned an error")
		}
	}()

	collectCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	group, groupCtx := errgroup.WithContext(collectCtx)
	group.Go(func() error {
		log := log.WithField("context", "collect")
		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()

		collect := func() {
			// TODO: add retry handling
			log.Info("collecting")
			err := s.Collect()
			if err != nil {
				log.WithError(err).Error("collection error")
				return
			}
			log.Info("completed successfully")
		}

		collect()

		for {
			select {
			case <-ticker.C:
				collect()
			case <-collectCtx.Done():
				return nil
			}
		}
	})

	go func() {
		<-groupCtx.Done()
	}()

	<-ctx.Done()
	<-groupCtx.Done()

	const shutdownTimeout = time.Second * 5
	log.Info("shutting down server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.WithError(err).Error("unable to shutdown server")
		return err
	}

	log.Info("server shutdown")

	if serverErr != nil && serverErr != http.ErrServerClosed {
		return serverErr
	}

	return serverErr
}

// metaMetrics are internal metrics having to do with the server and collection
// process, ie: not the collected data.
type metaMetrics struct {
	CollectionTime prometheus.Histogram
}

// NewMetaMetrics prepares a set of metrics for tracking internal server and
// collection process metrics.
func NewMetaMetrics() *metaMetrics {
	return &metaMetrics{
		CollectionTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "collection",
			Name:      "seconds",
			Buckets:   []float64{1, 5, 10, 15, 30, 45, 60},
			Help:      "time taken to perform collection from device in seconds",
		}),
	}
}

// RegisterMetrics adds metrics to the provided registry.
func (m *metaMetrics) RegisterMetrics(reg prometheus.Registerer) error {
	cs := []prometheus.Collector{
		m.CollectionTime,
	}

	for _, c := range cs {
		err := reg.Register(c)
		if err != nil {
			return err
		}
	}

	return nil
}

// downstreamMetrics are the metrics maintained for Downstream Channels.
type downstreamMetrics struct {
	// 0 or 1
	Locked    *prometheus.GaugeVec
	Frequency *prometheus.GaugeVec
	// TODO: make these counters with Set(), the standard Counter does not allow
	// this.
	Uncorrected *prometheus.GaugeVec
	Corrected   *prometheus.GaugeVec
	Signal      *prometheus.GaugeVec
	Power       *prometheus.GaugeVec
}

func NewDownstreamMetrics() *downstreamMetrics {
	const subsystem = "downstream_channel"

	var labels = []string{
		labelChannel,
		labelChannelID,
		labelModulation,
	}

	return &downstreamMetrics{
		Locked: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "locked",
			Help:      "channel locked status",
		}, labels),
		Frequency: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "frequency",
			Help:      "channel frequency in Hz",
		}, labels),
		Corrected: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "corrected_total",
			Help:      "corrected symbols",
		}, labels),
		Uncorrected: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "uncorrected_total",
			Help:      "uncorrected symbols",
		}, labels),
		Signal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "signal_noise_ratio",
			Help:      "signal to noise ratio measured in dB",
		}, labels),
		Power: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "power_dbmv",
			Help:      "channel power level in dBmV",
		}, labels),
	}
}

func (m *downstreamMetrics) RegisterMetrics(reg prometheus.Registerer) error {
	cs := []prometheus.Collector{
		m.Locked,
		m.Frequency,
		m.Uncorrected,
		m.Corrected,
		m.Signal,
		m.Power,
	}

	for _, c := range cs {
		err := reg.Register(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *downstreamMetrics) RecordOne(info *hnap.DownstreamInfo) {
	// TODO: insert metrics from info
	labels := prometheus.Labels{
		labelChannel:    fmt.Sprintf("%d", info.ID),
		labelChannelID:  fmt.Sprintf("%d", info.ChannelID),
		labelModulation: info.Modulation,
	}

	var locked float64
	if info.LockStatus == "Locked" {
		locked = 1
	}

	m.Locked.With(labels).Set(locked)
	m.Frequency.With(labels).Set(info.Frequency)
	m.Power.With(labels).Set(info.DecibelMillivolts)
	m.Corrected.With(labels).Set(float64(info.Corrected))
	m.Uncorrected.With(labels).Set(float64(info.Uncorrected))
	m.Signal.With(labels).Set(info.Signal)
}

type upstreamMetrics struct {
	// 0 or 1
	Locked     *prometheus.GaugeVec
	Frequency  *prometheus.GaugeVec
	SymbolRate *prometheus.GaugeVec
	Power      *prometheus.GaugeVec
}

type clientMetrics struct {
	SignalStrength *prometheus.GaugeVec
	State          *prometheus.GaugeVec
	iFace          *prometheus.GaugeVec
}

type connectionMetrics struct {
	// 0 or 1
	RXDropped *prometheus.GaugeVec
	Session   *prometheus.GaugeVec
	Errors    *prometheus.GaugeVec
	Sent      *prometheus.GaugeVec
	Received  *prometheus.GaugeVec
	TXPackets *prometheus.GaugeVec
	RXPackets *prometheus.GaugeVec
	TXDropped *prometheus.GaugeVec
}

// upstreamMetrics are the metrics maintained for Downstream Channels.
func NewConnectionMetrics() *connectionMetrics {
	//const subsystem = "network"

	labels := []string{
		labelFrequency,
		labelInterfaceId,
	}
	return &connectionMetrics{
		TXPackets: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_transmit_packets",
			Name:      "total",
			Help:      "TXPackets status",
		}, labels),
		RXPackets: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_receive_packets",
			Name:      "total",
			Help:      "RXPackets status",
		}, labels),
		Sent: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_transmit_bytes",
			Name:      "total",
			Help:      "sent bytes",
		}, labels),
		Received: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_receive_bytes",
			Name:      "total",
			Help:      "received bytes",
		}, labels),
		TXDropped: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_transmit_drop",
			Name:      "total",
			Help:      "sent bytes",
		}, labels),
		RXDropped: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_receive_drop",
			Name:      "total",
			Help:      "received bytes",
		}, labels),
	}
}

func (m *connectionMetrics) RegisterMetrics(reg prometheus.Registerer) error {
	cs := []prometheus.Collector{
		m.Received,
		m.Sent,
		m.RXPackets,
		m.TXPackets,
	}

	for _, c := range cs {
		err := reg.Register(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *connectionMetrics) RecordOne(info *hnap.GetInterfaceStatisticsResponse) {
	labels := prometheus.Labels{
		labelFrequency:   fmt.Sprintf("%s", info.Interface),
		labelInterfaceId: fmt.Sprintf("%s", info.MACAddress),
	}
	received, _ := strconv.Atoi(info.InterfaceStatistics.StatisticInfo.Received)
	m.Received.With(labels).Set(float64(received))
	sent, _ := strconv.Atoi(info.InterfaceStatistics.StatisticInfo.Sent)
	m.Sent.With(labels).Set(float64(sent))
	trasmit, _ := strconv.Atoi(info.InterfaceStatistics.StatisticInfo.TXPackets)
	m.TXPackets.With(labels).Set(float64(trasmit))
	rxreceived, _ := strconv.Atoi(info.InterfaceStatistics.StatisticInfo.RXPackets)
	m.RXPackets.With(labels).Set(float64(rxreceived))
	rxdrop, _ := strconv.Atoi(info.InterfaceStatistics.StatisticInfo.RXDropped)
	m.RXDropped.With(labels).Set(float64(rxdrop))
	txdrop, _ := strconv.Atoi(info.InterfaceStatistics.StatisticInfo.TXDropped)
	m.TXDropped.With(labels).Set(float64(txdrop))
}

// NewClientMetric are the metrics maintained for clients.
func NewClientMetric() *clientMetrics {
	//const subsystem = "network"
	labels := []string{
		"DeviceName",
		"MacAddress",
		"NickName",
		"ReserveIP",
		"Type",
	}
	return &clientMetrics{
		SignalStrength: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_client",
			Name:      "signal",
			Help:      "Network Clients signal",
		}, labels),
		State: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_client",
			Name:      "state",
			Help:      "Network Clients status",
		}, labels),
		iFace: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "network_client",
			Name:      "interface",
			Help:      "Network Clients on interface",
		}, []string{"Type"}),
	}
}

func (m *clientMetrics) RegisterMetrics(reg prometheus.Registerer) error {
	cs := []prometheus.Collector{
		m.State,
		m.SignalStrength,
		m.iFace,
	}

	for _, c := range cs {
		err := reg.Register(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *clientMetrics) RecordOne(info *hnap.ClientInfo) {
	labels := prometheus.Labels{
		"DeviceName": info.DeviceName,
		"MacAddress": info.MacAddress,
		"NickName":   info.NickName,
		"ReserveIP":  info.ReserveIP,
		"Type":       info.Type,
	}
	state := 0
	if info.State == "UNBLOCKED" {
		state = 1
	}
	m.State.With(labels).Set(float64(state))
	strength, _ := strconv.Atoi(info.SignalStrength)
	m.SignalStrength.With(labels).Set(float64(strength))
}

func (m *clientMetrics) RecordType(iFace string, count float64) {
	m.iFace.With(prometheus.Labels{"Type": iFace}).Set(count)
}

// upstreamMetrics are the metrics maintained for Downstream Channels.
func NewUpstreamMetrics() *upstreamMetrics {
	const subsystem = "upstream_channel"

	labels := []string{
		labelChannel,
		labelChannelID,
		labelModulation,
	}

	return &upstreamMetrics{
		Locked: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "locked",
			Help:      "channel locked status",
		}, labels),
		Frequency: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "frequency",
			Help:      "channel freqency in Hz",
		}, labels),
		SymbolRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "symbol_rate",
			Help:      "instantaneous symbols per second rate",
		}, labels),
		Power: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "power_dbmv",
			Help:      "channel power level in dBmV",
		}, labels),
	}
}

func (m *upstreamMetrics) RegisterMetrics(reg prometheus.Registerer) error {
	cs := []prometheus.Collector{
		m.Locked,
		m.Frequency,
		m.SymbolRate,
		m.Power,
	}

	for _, c := range cs {
		err := reg.Register(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *upstreamMetrics) RecordOne(info *hnap.UpstreamInfo) {
	labels := prometheus.Labels{
		labelChannel:    fmt.Sprintf("%d", info.ID),
		labelChannelID:  fmt.Sprintf("%d", info.Channel),
		labelModulation: info.Modulation,
	}

	var locked float64
	if info.LockStatus == "Locked" {
		locked = 1
	}

	m.Locked.With(labels).Set(locked)
	m.Frequency.With(labels).Set(info.Frequency)
	m.SymbolRate.With(labels).Set(float64(info.SymbolRate))
	m.Power.With(labels).Set(info.DecibelMillivolts)
}

type deviceMetrics struct {
	Device    *prometheus.GaugeVec
	Connected *prometheus.GaugeVec
}

// deviceMetrics are the metrics maintained for Downstream Channels.
func NewDeviceMetrics() *deviceMetrics {
	const subsystem = "device"

	return &deviceMetrics{
		Device: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "hardware_info",
			Help:      "channel locked status",
		}, []string{
			labelSerial,
			labelSoftwareVersion,
			labelHardwareVersion,
			labelCustomerVersion,
			labelSpecVersion,
			labelBootFile,
		}),
		Connected: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "connected_status",
			Help:      "channel locked status",
		}, []string{
			labelSerial,
		}),
	}
}

func (m *deviceMetrics) RegisterMetrics(reg prometheus.Registerer) error {
	cs := []prometheus.Collector{
		m.Device,
		m.Connected,
	}

	for _, c := range cs {
		err := reg.Register(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *deviceMetrics) RecordOne(info *gather.Collection) {
	m.Device.With(prometheus.Labels{
		labelSerial:          info.SerialNumber,
		labelSoftwareVersion: info.SoftwareVersion,
		labelHardwareVersion: info.HardwareVersion,
		labelCustomerVersion: info.CustomerVersion,
		labelSpecVersion:     info.SpecVersion,
		labelBootFile:        info.BootFile,
	}).Set(1)

	var connected float64
	if info.Online {
		connected = 1
	}
	m.Connected.With(prometheus.Labels{
		labelSerial: info.SerialNumber,
	}).Set(connected)
}
