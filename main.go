// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/pkg/flagutil"
	log "github.com/golang/glog"
	"golang.org/x/net/context"

	"github.com/coreos/flannel/network"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/coreos/flannel/subnet/etcdv2"
	"github.com/coreos/flannel/subnet/kube"
	"github.com/coreos/flannel/version"

	"time"

	"github.com/joho/godotenv"

	"sync"

	// Backends need to be imported for their init() to get executed and them to register
	"github.com/coreos/flannel/backend"
	_ "github.com/coreos/flannel/backend/alivpc"
	_ "github.com/coreos/flannel/backend/alloc"
	_ "github.com/coreos/flannel/backend/awsvpc"
	_ "github.com/coreos/flannel/backend/extension"
	_ "github.com/coreos/flannel/backend/gce"
	_ "github.com/coreos/flannel/backend/hostgw"
	_ "github.com/coreos/flannel/backend/ipip"
	_ "github.com/coreos/flannel/backend/udp"
	_ "github.com/coreos/flannel/backend/vxlan"
	"github.com/coreos/go-systemd/daemon"
)

type flagSlice []string

func (t *flagSlice) String() string {
	return fmt.Sprintf("%v", *t)
}

func (t *flagSlice) Set(val string) error {
	*t = append(*t, val)
	return nil
}

// 命令航参数结构体
type CmdLineOpts struct {
	etcdEndpoints          string
	etcdPrefix             string
	etcdKeyfile            string
	etcdCertfile           string
	etcdCAFile             string
	etcdUsername           string
	etcdPassword           string
	help                   bool
	version                bool
	kubeSubnetMgr          bool
	kubeApiUrl             string
	kubeConfigFile         string
	iface                  flagSlice // 完整网卡名称
	ifaceRegex             flagSlice // 正则表达式 网卡名称
	ipMasq                 bool
	subnetFile             string
	subnetDir              string
	publicIP               string
	subnetLeaseRenewMargin int
	healthzIP              string
	healthzPort            int
}

var (
	opts           CmdLineOpts
	errInterrupted = errors.New("interrupted")
	errCanceled    = errors.New("canceled")
	flannelFlags   = flag.NewFlagSet("flannel", flag.ExitOnError)
)

/**
 * init函数 先于main函数执行
 */
func init() {
	flannelFlags.StringVar(&opts.etcdEndpoints, "etcd-endpoints", "http://127.0.0.1:4001,http://127.0.0.1:2379", "a comma-delimited list of etcd endpoints")
	flannelFlags.StringVar(&opts.etcdPrefix, "etcd-prefix", "/coreos.com/network", "etcd prefix")
	flannelFlags.StringVar(&opts.etcdKeyfile, "etcd-keyfile", "", "SSL key file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdCertfile, "etcd-certfile", "", "SSL certification file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdCAFile, "etcd-cafile", "", "SSL Certificate Authority file used to secure etcd communication")
	flannelFlags.StringVar(&opts.etcdUsername, "etcd-username", "", "username for BasicAuth to etcd")
	flannelFlags.StringVar(&opts.etcdPassword, "etcd-password", "", "password for BasicAuth to etcd")
	//创建自定义flag 需要自己实现赋值、读取接口 如上面String(), Set()函数
	flannelFlags.Var(&opts.iface, "iface", "interface to use (IP or name) for inter-host communication. Can be specified multiple times to check each option in order. Returns the first match found.")
	flannelFlags.Var(&opts.ifaceRegex, "iface-regex", "regex expression to match the first interface to use (IP or name) for inter-host communication. Can be specified multiple times to check each regex in order. Returns the first match found. Regexes are checked after specific interfaces specified by the iface option have already been checked.")

	flannelFlags.StringVar(&opts.subnetFile, "subnet-file", "/run/flannel/subnet.env", "filename where env variables (subnet, MTU, ... ) will be written to")
	flannelFlags.StringVar(&opts.publicIP, "public-ip", "", "IP accessible by other nodes for inter-host communication")
	flannelFlags.IntVar(&opts.subnetLeaseRenewMargin, "subnet-lease-renew-margin", 60, "subnet lease renewal margin, in minutes, ranging from 1 to 1439")
	flannelFlags.BoolVar(&opts.ipMasq, "ip-masq", false, "setup IP masquerade rule for traffic destined outside of overlay network")
	flannelFlags.BoolVar(&opts.kubeSubnetMgr, "kube-subnet-mgr", false, "contact the Kubernetes API for subnet assignment instead of etcd.")
	flannelFlags.StringVar(&opts.kubeApiUrl, "kube-api-url", "", "Kubernetes API server URL. Does not need to be specified if flannel is running in a pod.")
	flannelFlags.StringVar(&opts.kubeConfigFile, "kubeconfig-file", "", "kubeconfig file location. Does not need to be specified if flannel is running in a pod.")
	flannelFlags.BoolVar(&opts.version, "version", false, "print version and exit")
	flannelFlags.StringVar(&opts.healthzIP, "healthz-ip", "0.0.0.0", "the IP address for healthz server to listen")
	flannelFlags.IntVar(&opts.healthzPort, "healthz-port", 0, "the port for healthz server to listen(0 to disable)")

	// glog will log to tmp files by default. override so all entries
	// can flow into journald (if running under systemd)
	flag.Set("logtostderr", "true")

	// Only copy the non file logging options from glog
	copyFlag("v")
	copyFlag("vmodule")
	copyFlag("log_backtrace_at")

	// Define the usage function
	flannelFlags.Usage = usage //覆盖默认的Usage函数

	// now parse command line args
	flannelFlags.Parse(os.Args[1:])
}

func copyFlag(name string) {
	flannelFlags.Var(flag.Lookup(name).Value, flag.Lookup(name).Name, flag.Lookup(name).Usage)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
	flannelFlags.PrintDefaults()
	os.Exit(0)
}

/**
 * 创建子网管理对象
 * @param 无
 * @return subnet.Manager 子网管理对象
 * @return error 错误信息对象
 */
func newSubnetManager() (subnet.Manager, error) {
	if opts.kubeSubnetMgr { // 如果kubeSubnetMgr是true则表示采用kubenets方式管理网络
		return kube.NewSubnetManager(opts.kubeApiUrl, opts.kubeConfigFile)
	}
	// 采用etcd方式管理网络 etcd相关配置信息
	cfg := &etcdv2.EtcdConfig{
		Endpoints: strings.Split(opts.etcdEndpoints, ","),
		Keyfile:   opts.etcdKeyfile,
		Certfile:  opts.etcdCertfile,
		CAFile:    opts.etcdCAFile,
		Prefix:    opts.etcdPrefix,
		Username:  opts.etcdUsername,
		Password:  opts.etcdPassword,
	}

	// Attempt to renew the lease for the subnet specified in the subnetFile
	// 读取配置文件 获取子网配置信息 在获取网络租约时 会使用到在local_manager.go 函数tryAcquireLease
	// opts.subnetFile 默认路径是/run/flannel/subnet.env
	prevSubnet := ReadSubnetFromSubnetFile(opts.subnetFile)

	return etcdv2.NewLocalManager(cfg, prevSubnet)
}

func main() {
	if opts.version { //输出版本信息
		fmt.Fprintln(os.Stderr, version.Version)
		os.Exit(0)
	}

	flagutil.SetFlagsFromEnv(flannelFlags, "FLANNELD")

	// Validate flags
	// 子网续约时间不能大于1天 单位是分钟
	if opts.subnetLeaseRenewMargin >= 24*60 || opts.subnetLeaseRenewMargin <= 0 {
		log.Error("Invalid subnet-lease-renew-margin option, out of acceptable range")
		os.Exit(1)
	}

	// Work out which interface to use
	var extIface *backend.ExternalInterface
	var err error
	// Check the default interface only if no interfaces are specified
	if len(opts.iface) == 0 && len(opts.ifaceRegex) == 0 { //没有指定网卡 则自己查找
		extIface, err = LookupExtIface("", "")
		if err != nil {
			log.Error("Failed to find any valid interface to use: ", err)
			os.Exit(1)
		}
	} else {
		// Check explicitly specified interfaces
		for _, iface := range opts.iface {
			extIface, err = LookupExtIface(iface, "")
			if err != nil {
				log.Infof("Could not find valid interface matching %s: %s", iface, err)
			}

			if extIface != nil {
				break
			}
		}

		// Check interfaces that match any specified regexes
		if extIface == nil {
			for _, ifaceRegex := range opts.ifaceRegex {
				extIface, err = LookupExtIface("", ifaceRegex)
				if err != nil {
					log.Infof("Could not find valid interface matching %s: %s", ifaceRegex, err)
				}

				if extIface != nil {
					break
				}
			}
		}
		// 没有找到合适的网卡 直接退出
		if extIface == nil {
			// Exit if any of the specified interfaces do not match
			log.Error("Failed to find interface to use that matches the interfaces and/or regexes provided")
			os.Exit(1)
		}
	}

	sm, err := newSubnetManager() //创建子网管理对象
	if err != nil {
		log.Error("Failed to create SubnetManager: ", err)
		os.Exit(1)
	}
	log.Infof("Created subnet manager: %s", sm.Name())

	// Register for SIGINT and SIGTERM
	// 只接受SIGINT、SIGTERM两种信号
	log.Info("Installing signal handlers")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// This is the main context that everything should run in.
	// All spawned goroutines should exit when cancel is called on this context.
	// Go routines spawned from main.go coordinate using a WaitGroup.
	// This provides a mechanism(机制) to allow the shutdownHandler goroutine
	// to block until all the goroutines return . If those goroutines spawn other goroutines then they are responsible for
	// blocking and returning only when cancel() is called.
	// 返回值：
	// ctx 全局上下文  cancel 函数指针
	// Background() 返回一个空白context,不能被cancel
	// WitchCancel(parent) 继承parent后返回一个新的context，该context可以被cancel
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{} //go routines 同步手段

	wg.Add(1) //此处1 表示等待一个go routines
	go func() {
		shutdownHandler(ctx, sigs, cancel)
		wg.Done() //通知Wait()返回
	}()

	if opts.healthzPort > 0 {
		// It's not super easy to shutdown the HTTP server so don't attempt to stop it cleanly
		//关闭HTTP服务并不是很容易，因此不要试图干净的停止它
		go mustRunHealthz()
	}

	// Fetch the network config (i.e. what backend to use etc..).
	// 从etcd中获取配置
	config, err := getConfig(ctx, sm)
	if err == errCanceled {
		wg.Wait()
		os.Exit(0)
	}

	// Create a backend manager then use it to create the backend and register the network with it.
	bm := backend.NewManager(ctx, sm, extIface) //创建manager对象
	be, err := bm.GetBackend(config.BackendType)
	if err != nil {
		log.Errorf("Error fetching backend: %s", err)
		cancel()  // 促使context.done()返回
		wg.Wait() // 等待同步
		os.Exit(1)
	}

	/**
	 * 如果backend指向的是vxlan则RegisterNetwork函数指向vxlan.go文件中RegisterNetwork
	 * 相当于创建网卡。
	 * vxlan模式 flannel.VNI VNI为vlan id
	 * udp模式   flannel.数字 从0开始
	 * 这个是非常重要的函数
	 */
	bn, err := be.RegisterNetwork(ctx, config)
	if err != nil {
		log.Errorf("Error registering network: %s", err)
		cancel()  // 促使context.done()返回
		wg.Wait() // 等待同步
		os.Exit(1)
	}

	// Set up ipMasq if needed
	if opts.ipMasq { // 开启防火墙 ip-masquerade
		go network.SetupAndEnsureIPTables(network.MasqRules(config.Network, bn.Lease()))
	}

	// Always enables forwarding rules. This is needed for Docker versions >1.13
	// (https://docs.docker.com/engine/userguide/networking/default_network/container-communication/#container-communication-between-hosts)
	// In Docker 1.12 and earlier, the default FORWARD chain policy was ACCEPT.
	// In Docker 1.13 and later, Docker sets the default policy of the FORWARD chain to DROP.
	// 设置防火墙策略
	go network.SetupAndEnsureIPTables(network.ForwardRules(config.Network.String())) // iptables.go

	if err := WriteSubnetFile(opts.subnetFile, config.Network, opts.ipMasq, bn); err != nil {
		// Continue, even though it failed.
		log.Warningf("Failed to write subnet file: %s", err)
	} else {
		log.Infof("Wrote subnet file to %s", opts.subnetFile)
	}

	// Start "Running" the backend network. This will block until the context is done so run in another goroutine.
	log.Info("Running backend.")
	wg.Add(1)
	go func() {
		bn.Run(ctx) //如果是vxlan网络 执行的是vxlan_network.go中Run
		wg.Done()
	}()

	daemon.SdNotify(false, "READY=1")

	// Kube subnet mgr doesn't lease the subnet for this node - it just uses the podCidr that's already assigned.
	// kubernets管理的网络不需要使用该节点
	if !opts.kubeSubnetMgr {
		// 通过etcd管理网络 会进入此函数 此函数是一个死循环
		err = MonitorLease(ctx, sm, bn, &wg) //监控该节点 主要用于节点租约过期后 能够快速获取新的租约
		if err == errInterrupted {
			// The lease was "revoked" - shut everything down
			cancel()
		}
	}

	log.Info("Waiting for all goroutines to exit")
	// Block waiting for all the goroutines to finish.
	wg.Wait()
	log.Info("Exiting cleanly...")
	os.Exit(0)
}

/**
 * 处理函数
 * @param ctx 上下文
 * @param sigs 注册的信号
 * @param cancel 回调函数
 */
func shutdownHandler(ctx context.Context, sigs chan os.Signal, cancel context.CancelFunc) {
	// Wait for the context do be Done or for the signal to come in to shutdown.
	// select 会阻塞在这里 只要满足其中一个case就会继续往下执行
	select {
	case <-ctx.Done(): // 表示上下文初始化完成
		log.Info("Stopping shutdownHandler...")
	case <-sigs: //表示发生信号
		// Call cancel on the context to close everything down.
		cancel()
		log.Info("shutdownHandler sent cancel signal...")
	}

	// Unregister to get default OS nuke behaviour in case we don't exit cleanly
	signal.Stop(sigs)
}

/**
 * 获取网络配置 (每一秒获取一次 直到成功)
 * @param ctx 上下文
 * @param sm  子网管理对象
 */
func getConfig(ctx context.Context, sm subnet.Manager) (*subnet.Config, error) {
	// Retry every second until it succeeds
	for {
		//通过etcd获取数据
		config, err := sm.GetNetworkConfig(ctx) // local_manager.go
		if err != nil {
			log.Errorf("Couldn't fetch network config: %s", err)
		} else if config == nil {
			log.Warningf("Couldn't find network config: %s", err)
		} else {
			log.Infof("Found network config - Backend type: %s", config.BackendType)
			return config, nil
		}
		select {
		case <-ctx.Done(): //当调用cancle()或者超时后 这里就返回了
			return nil, errCanceled
		case <-time.After(1 * time.Second):
			fmt.Println("timed out")
		}
	}
}

/**
 * 监控租约
 * @param ctx 上下文
 * @param sm  子网管理对象
 * @param bn  backend管理对象
 * @param wg  waitgroup对象
 */
func MonitorLease(ctx context.Context, sm subnet.Manager, bn backend.Network, wg *sync.WaitGroup) error {
	// Use the subnet manager to start watching leases.
	evts := make(chan subnet.Event)

	wg.Add(1)
	go func() {
		subnet.WatchLease(ctx, sm, bn.Lease().Subnet, evts)
		wg.Done()
	}()
	// 计算超时时间
	renewMargin := time.Duration(opts.subnetLeaseRenewMargin) * time.Minute
	dur := bn.Lease().Expiration.Sub(time.Now()) - renewMargin

	//死循环 始终监控 当该函数退出表示 flanneld将要退出
	for {
		select {
		case <-time.After(dur):
			err := sm.RenewLease(ctx, bn.Lease()) //发生超时需要重新获取租约
			if err != nil {
				log.Error("Error renewing lease (trying again in 1 min): ", err)
				dur = time.Minute
				continue
			}

			log.Info("Lease renewed, new expiration: ", bn.Lease().Expiration)
			dur = bn.Lease().Expiration.Sub(time.Now()) - renewMargin

		case e := <-evts:
			switch e.Type {
			case subnet.EventAdded:
				bn.Lease().Expiration = e.Lease.Expiration
				dur = bn.Lease().Expiration.Sub(time.Now()) - renewMargin
				log.Infof("Waiting for %s to renew lease", dur)

			case subnet.EventRemoved:
				log.Error("Lease has been revoked. Shutting down daemon.")
				return errInterrupted
			}

		case <-ctx.Done():
			log.Infof("Stopped monitoring lease")
			return errCanceled
		}
	}
}

/**
 * 查找外部通信网卡信息
 * @param ifname 网卡名称 完全匹配
 * @param ifregex 正则表达式 方式查找网卡
 * 如果两个参数都没有指定则查找默认路由所在网卡
 */
func LookupExtIface(ifname string, ifregex string) (*backend.ExternalInterface, error) {
	var iface *net.Interface
	var ifaceAddr net.IP
	var err error

	if len(ifname) > 0 {
		if ifaceAddr = net.ParseIP(ifname); ifaceAddr != nil {
			log.Infof("Searching for interface using %s", ifaceAddr)
			iface, err = ip.GetInterfaceByIP(ifaceAddr)
			if err != nil {
				return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
			}
		} else {
			iface, err = net.InterfaceByName(ifname)
			if err != nil {
				return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
			}
		}
	} else if len(ifregex) > 0 {
		// Use the regex if specified and the iface option for matching a specific ip or name is not used
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("error listing all interfaces: %s", err)
		}

		// Check IP
		for _, ifaceToMatch := range ifaces {
			ifaceIP, err := ip.GetIfaceIP4Addr(&ifaceToMatch)
			if err != nil {
				// Skip if there is no IPv4 address
				continue
			}

			matched, err := regexp.MatchString(ifregex, ifaceIP.String())
			if err != nil {
				return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceIP.String())
			}

			if matched {
				ifaceAddr = ifaceIP
				iface = &ifaceToMatch
				break
			}
		}

		// Check Name
		if iface == nil && ifaceAddr == nil {
			for _, ifaceToMatch := range ifaces {
				matched, err := regexp.MatchString(ifregex, ifaceToMatch.Name)
				if err != nil {
					return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceToMatch.Name)
				}

				if matched {
					iface = &ifaceToMatch
					break
				}
			}
		}

		// Check that nothing was matched
		if iface == nil {
			return nil, fmt.Errorf("Could not match pattern %s to any of the available network interfaces", ifregex)
		}
	} else {
		log.Info("Determining IP address of default interface")
		// linux   通过route信息获取gateway所在网卡
		// windows 通过netsh命令行获取信息netsh interface ipv4 show addresses
		if iface, err = ip.GetDefaultGatewayIface(); err != nil {
			return nil, fmt.Errorf("failed to get default interface: %s", err)
		}
	}

	// 进入到这里表示 网卡获取成功
	if ifaceAddr == nil {
		ifaceAddr, err = ip.GetIfaceIP4Addr(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv4 address for interface %s", iface.Name)
		}
	}

	log.Infof("Using interface with name %s and address %s", iface.Name, ifaceAddr)

	if iface.MTU == 0 {
		return nil, fmt.Errorf("failed to determine MTU for %s interface", ifaceAddr)
	}

	var extAddr net.IP

	if len(opts.publicIP) > 0 {
		extAddr = net.ParseIP(opts.publicIP) //根据ip字符串 生成IP对象
		if extAddr == nil {
			return nil, fmt.Errorf("invalid public IP address: %s", opts.publicIP)
		}
		log.Infof("Using %s as external address", extAddr)
	}

	if extAddr == nil {
		log.Infof("Defaulting external address to interface address (%s)", ifaceAddr)
		extAddr = ifaceAddr
	}

	return &backend.ExternalInterface{
		Iface:     iface,
		IfaceAddr: ifaceAddr,
		ExtAddr:   extAddr,
	}, nil
}

/**
 * 报文子网配置文件
 * @param path 配置文件路径
 * @param nw network
 * @param ipMasq 是否开启
 * 说明：
 *    ip-masq 与防火墙中MASQUERADE类似。具体可百度iptables MASQUERADE相关介绍
 */
func WriteSubnetFile(path string, nw ip.IP4Net, ipMasq bool, bn backend.Network) error {
	dir, name := filepath.Split(path)
	os.MkdirAll(dir, 0755)

	tempFile := filepath.Join(dir, "."+name)
	f, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	// Write out the first usable IP by incrementing
	// sn.IP by one
	sn := bn.Lease().Subnet
	sn.IP += 1

	fmt.Fprintf(f, "FLANNEL_NETWORK=%s\n", nw)
	fmt.Fprintf(f, "FLANNEL_SUBNET=%s\n", sn)
	fmt.Fprintf(f, "FLANNEL_MTU=%d\n", bn.MTU())
	_, err = fmt.Fprintf(f, "FLANNEL_IPMASQ=%v\n", ipMasq)
	f.Close()
	if err != nil {
		return err
	}

	// rename(2) the temporary file to the desired location so that it becomes
	// atomically visible with the contents
	return os.Rename(tempFile, path)
	//TODO - is this safe? What if it's not on the same FS?
}

/**
 * 保活检查
 */
func mustRunHealthz() {
	address := net.JoinHostPort(opts.healthzIP, strconv.Itoa(opts.healthzPort))
	log.Infof("Start healthz server on %s", address)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("flanneld is running"))
	})

	if err := http.ListenAndServe(address, nil); err != nil {
		log.Errorf("Start healthz server error. %v", err)
		panic(err)
	}
}

func ReadSubnetFromSubnetFile(path string) ip.IP4Net {
	var prevSubnet ip.IP4Net
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		prevSubnetVals, err := godotenv.Read(path)
		if err != nil {
			log.Errorf("Couldn't fetch previous subnet from subnet file at %s: %s", path, err)
		} else if prevSubnetString, ok := prevSubnetVals["FLANNEL_SUBNET"]; ok {
			err = prevSubnet.UnmarshalJSON([]byte(prevSubnetString))
			if err != nil {
				log.Errorf("Couldn't parse previous subnet from subnet file at %s: %s", path, err)
			}
		}
	}
	return prevSubnet
}
