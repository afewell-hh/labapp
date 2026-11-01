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
	"io"
	"os"
	"syscall"

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
kind: Switch
metadata:
  name: leaf-02
spec:
  role: server-leaf
  profile: vs
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
	if !ok {
		fail("missing typed Default for %s", gvk.Kind)
	}
	d.Default()
	defaulted[gvk.Kind] = ok
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	raw, err := json.Marshal(obj)
	if err != nil {
		fail("encode %s: %v", gvk.Kind, err)
	}
	return raw
}

func encode(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		fail("encode fixed public output: %v", err)
	}
	return raw
}

func outputRoot(path string) *os.Root {
	info, err := os.Lstat(path)
	if err != nil {
		fail("output directory: %v", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || owner.Mode&0o7777 != 0o700 || owner.Uid != uint32(os.Getuid()) {
		fail("output must be an owned mode0700 directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		fail("open output directory: %v", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		fail("output directory identity changed")
	}
	dir, err := root.Open(".")
	if err != nil {
		fail("open output listing: %v", err)
	}
	names, readErr := dir.Readdirnames(1)
	closeErr := dir.Close()
	if readErr != io.EOF || closeErr != nil || len(names) != 0 {
		fail("output directory must be empty")
	}
	return root
}

func main() {
	out := flag.String("out", "", "existing empty output directory")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		fail("-out is required")
	}
	root := outputRoot(*out)
	ctx := context.Background()

	first := apiutil.NewLoader()
	originals, err := first.Load(apiutil.FabricGatewayGVKs, []byte(input))
	if err != nil {
		fail("load input: %v", err)
	}
	originalBytes := encode(originals)
	// Add and printer may mutate metadata. Neither receives the original controls.
	for _, obj := range originals {
		if err := first.Add(ctx, obj.DeepCopyObject().(kclient.Object)); err != nil {
			fail("add copied input: %v", err)
		}
	}
	var printed bytes.Buffer
	if err := apiutil.PrintInclude(ctx, first.GetClient(), &printed); err != nil {
		fail("print include: %v", err)
	}
	if !bytes.Equal(originalBytes, encode(originals)) {
		fail("printer changed original controls")
	}

	second := apiutil.NewLoader()
	if err := second.LoadAdd(ctx, apiutil.FabricGatewayGVKs, printed.Bytes()); err != nil {
		fail("reload printed YAML: %v", err)
	}
	gv := wiringapi.GroupVersion
	defaulted := map[string]bool{}
	var items []json.RawMessage
	var before []json.RawMessage

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
		before = append(before, encode(&switches.Items[i]))
		items = append(items, observe(switches.Items[i].DeepCopy(), gv.WithKind("Switch"), defaulted))
	}
	for i := range servers.Items {
		before = append(before, encode(&servers.Items[i]))
		items = append(items, observe(servers.Items[i].DeepCopy(), gv.WithKind("Server"), defaulted))
	}
	for i := range connections.Items {
		before = append(before, encode(&connections.Items[i]))
		items = append(items, observe(connections.Items[i].DeepCopy(), gv.WithKind("Connection"), defaulted))
	}
	if len(switches.Items) != 2 || len(servers.Items) != 1 || len(connections.Items) != 1 || !defaulted["Switch"] || !defaulted["Server"] || !defaulted["Connection"] {
		fail("unexpected object set %d or missing typed Default: %v", len(items), defaulted)
	}
	// List items also remain untouched by Default on their separate deep copies.
	index := 0
	for _, obj := range []kclient.Object{&switches.Items[0], &switches.Items[1], &servers.Items[0], &connections.Items[0]} {
		if !bytes.Equal(before[index], encode(obj)) {
			fail("typed Default changed its source control")
		}
		index++
	}
	meta := encode(map[string]any{"typedDefaultInvoked": defaulted,
		"originals": originals, "beforeDefault": before, "originalsUnchanged": true})
	files := []struct {
		name string
		data []byte
	}{
		{"expected.yaml", printed.Bytes()}, {"observed.json", encode(items)}, {"meta.json", meta},
	}
	total := 0
	for _, file := range files {
		total += len(file.data)
		if len(file.data) == 0 || total > 1<<20 {
			fail("fixed public output exceeds total byte limit")
		}
	}
	for _, file := range files {
		f, err := root.OpenFile(file.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			fail("create %s: %v", file.name, err)
		}
		info, err := f.Stat()
		if err != nil {
			fail("stat %s: %v", file.name, err)
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ok || owner.Nlink != 1 || owner.Uid != uint32(os.Getuid()) {
			fail("output file identity refused")
		}
		n, writeErr := f.Write(file.data)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil || n != len(file.data) {
			fail("write %s failed", file.name)
		}
	}
	if err := root.Close(); err != nil {
		fail("close output directory: %v", err)
	}
}
