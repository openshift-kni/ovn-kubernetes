package cni

// cnishim hack to add an IPv4 interface to pods that need IPv4 access
// in nominally single-stack IPv6 AWS clusters (for access to AWS API
// or DNS endpoints)

import (
	"context"
	"io/ioutil"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
)

var ipv4HackPods = map[string]string{
	// namespace: pod name prefix
	"openshift-authentication-operator":   "authentication-operator",
	"openshift-cloud-credential-operator": "cloud-credential-operator",
	"openshift-console":                   "console",
	"openshift-dns":                       "dns-default",
	"openshift-image-registry":            "cluster-image-registry-operator",
	"openshift-ingress-operator":          "ingress-operator",
	"openshift-machine-api":               "machine-api-controllers",
}

func maybeAddIPv4Hack(args *skel.CmdArgs, result *current.Result) error {
	// Only need IPv4 hack on single-stack IPv6
	if len(result.IPs) != 1 || result.IPs[0].Version != "6" {
		return nil
	}

	// Only need IPv4 hack on AWS
	bytes, err := ioutil.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(string(bytes), "ignition.platform.id=aws") {
		return nil
	}

	cniArgs := os.Getenv("CNI_ARGS")
	mapArgs := make(map[string]string)
	for _, arg := range strings.Split(cniArgs, ";") {
		parts := strings.Split(arg, "=")
		if len(parts) != 2 {
			continue
		}
		mapArgs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	namespace := mapArgs["K8S_POD_NAMESPACE"]
	name := mapArgs["K8S_POD_NAME"]
	if namespace == "" || name == "" {
		return nil
	}

	prefix := ipv4HackPods[namespace]
	if prefix == "" || !strings.HasPrefix(name, prefix) {
		return nil
	}

	v4Args := &invoke.Args{
		Command:     "ADD",
		ContainerID: args.ContainerID,
		NetNS:       args.Netns,
		IfName:      "eth4",
		Path:        "/var/lib/cni/bin",
	}
	v4Config := []byte(`{"cniVersion": "0.3.0", "name": "ipv4-hack", "type": "bridge", "bridge": "ipv4-hack", "isDefaultGateway": true, "ipMasq": true, "ipam": { "type": "host-local", "subnet": "10.192.0.0/24" } }`)
	os.Setenv("CNI_IFNAME", "eth4")
	return invoke.ExecPluginWithoutResult(context.TODO(), "/var/lib/cni/bin/bridge", v4Config, v4Args, nil)
}
