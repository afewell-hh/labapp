// Public, credential-free producer of two independently generated sides (#394).
//
// expected.yaml: public YAML -> actual apiutil.NewLoader/LoadAdd -> actual
//   apiutil.PrintInclude, as the pinned installer build prints it.
// observed.json: that printed YAML reloaded by a fresh loader -> typed objects
//   -> DeepCopy -> actual typed Default() -> ordinary encoding/json. It is never
//   passed through PrintKubeObject again.
//
// Pinned: fabricator v0.43.1 (pkg/util/apiutil), fabric v0.96.2 (api/wiring/v1beta1).
// No hhfab.Build, downloader, registry, envtest, cluster, network or credentials.
// Not a live admission, OCI byte or canonical11 proof.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	wiringapi "go.githedgehog.com/fabric/api/wiring/v1beta1"
	"go.githedgehog.com/fabricator/pkg/util/apiutil"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Deliberately "raw" public input: stale derived labels, the kubectl
// last-applied annotation, unsorted groups/namespaces, SPEED_ prefixes, a
// redundancy group missing from groups, omitted namespaces and unrelated
// label/annotation metadata that must survive on both sides.
const input = `
apiVersion: wiring.githedgehog.com/v1beta1
kind: Switch
metadata:
  name: leaf-01
  labels:
    fabric.githedgehog.com/stale: "true"
    example.com/keep: "yes"
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"public":"synthetic"}'
    example.com/note: keep-me
spec:
  role: server-leaf
  profile: vs
  description: public fixture leaf
  asn: 65101
  ip: 172.30.0.8/21
  protocolIP: 172.30.8.0/32
  vtepIP: 172.30.12.0/32
  groups: [zeta, alpha]
  vlanNamespaces: [vlan-b, vlan-a]
  redundancy:
    group: pair-1
    type: mclag
  portGroupSpeeds:
    "1": SPEED_10G
  portSpeeds:
    E1/2: SPEED_25G
---
apiVersion: wiring.githedgehog.com/v1beta1
kind: Server
metadata:
  name: server-01
  namespace: default
  labels:
    fabric.githedgehog.com/stale: "true"
    example.com/keep: "yes"
spec:
  description: public fixture server
---
apiVersion: wiring.githedgehog.com/v1beta1
kind: Connection
metadata:
  name: server-01--unbundled--leaf-01
  labels:
    fabric.githedgehog.com/stale: "true"
  annotations:
    example.com/note: keep-me
spec:
  unbundled:
    link:
      server:
        port: server-01/enp2s1
      switch:
        port: leaf-01/E1/1
`

type defaulter interface{ Default() }

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pinned-api fixture: "+format+"\n", args...)
	os.Exit(1)
}

func observe(obj kclient.Object, gvk schema.GroupVersionKind, defaulted map[string]bool) json.RawMessage {
	d, ok := obj.(defaulter)
	if ok {
		d.Default()
	}
	defaulted[gvk.Kind] = ok
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	raw, err := json.Marshal(obj)
	if err != nil {
		fail("encode %s: %v", gvk.Kind, err)
	}
	return raw
}

func main() {
	out := flag.String("out", "", "existing empty output directory")
	flag.Parse()
	if *out == "" {
		fail("-out is required")
	}
	ctx := context.Background()

	first := apiutil.NewLoader()
	if err := first.LoadAdd(ctx, apiutil.FabricGatewayGVKs, []byte(input)); err != nil {
		fail("load input: %v", err)
	}
	var printed bytes.Buffer
	if err := apiutil.PrintInclude(ctx, first.GetClient(), &printed); err != nil {
		fail("print include: %v", err)
	}

	second := apiutil.NewLoader()
	if err := second.LoadAdd(ctx, apiutil.FabricGatewayGVKs, printed.Bytes()); err != nil {
		fail("reload printed YAML: %v", err)
	}
	gv := wiringapi.GroupVersion
	defaulted := map[string]bool{}
	var items []json.RawMessage

	switches := &wiringapi.SwitchList{}
	servers := &wiringapi.ServerList{}
	connections := &wiringapi.ConnectionList{}
	if err := second.List(ctx, switches); err != nil {
		fail("list switches: %v", err)
	}
	if err := second.List(ctx, servers); err != nil {
		fail("list servers: %v", err)
	}
	if err := second.List(ctx, connections); err != nil {
		fail("list connections: %v", err)
	}
	for i := range switches.Items {
		items = append(items, observe(switches.Items[i].DeepCopy(), gv.WithKind("Switch"), defaulted))
	}
	for i := range servers.Items {
		items = append(items, observe(servers.Items[i].DeepCopy(), gv.WithKind("Server"), defaulted))
	}
	for i := range connections.Items {
		items = append(items, observe(connections.Items[i].DeepCopy(), gv.WithKind("Connection"), defaulted))
	}
	if len(items) != 3 || !defaulted["Switch"] || !defaulted["Connection"] {
		fail("unexpected object set %d or missing typed Default: %v", len(items), defaulted)
	}
	observed, err := json.MarshalIndent(items, "", " ")
	if err != nil {
		fail("encode observed list: %v", err)
	}
	meta, _ := json.Marshal(map[string]any{"typedDefaultInvoked": defaulted})
	for name, data := range map[string][]byte{"expected.yaml": printed.Bytes(), "observed.json": observed, "meta.json": meta} {
		if err := os.WriteFile(filepath.Join(*out, name), data, 0o600); err != nil {
			fail("write %s: %v", name, err)
		}
	}
}
