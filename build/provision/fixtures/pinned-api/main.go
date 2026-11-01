// Public, credential-free producer of independently generated sides (#394, #400).
//
// expected.yaml: public YAML -> actual apiutil loader -> (Fabricator/ControlNode:
//   fab.GetFabAndNodes -> apiutil.PrintFab; wiring: apiutil.PrintInclude), as the
//   pinned installer build prints it.
// observed.json: that printed YAML reloaded by fresh loaders -> typed objects ->
//   DeepCopy -> actual typed Default() -> ordinary encoding/json. It is never
//   passed through PrintKubeObject again.
//
// Pinned: fabricator v0.43.1 (pkg/util/apiutil, pkg/fab), fabric v0.96.2.
// Inputs: the unchanged canonical wiringd.yaml (fixed read-only path, fixed
// SHA-256), a hardcoded public synthetic control set, and a hardcoded public
// installer-shaped Fabricator/ControlNode set. No hhfab.Build, hydration,
// downloader, registry, envtest, cluster, network, environment or credentials.
// Not a live admission, OCI byte or canonical11 proof.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	vpcapi "go.githedgehog.com/fabric/api/vpc/v1beta1"
	wiringapi "go.githedgehog.com/fabric/api/wiring/v1beta1"
	fabapi "go.githedgehog.com/fabricator/api/fabricator/v1beta1"
	"go.githedgehog.com/fabricator/pkg/fab"
	"go.githedgehog.com/fabricator/pkg/util/apiutil"
	kmeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Fixed canonical source: mounted read-only by the hosted wrapper. No caller
// override exists; the bytes must match the repository's pinned SHA-256.
const (
	wiringPath   = "/repo/wiringd.yaml"
	wiringSHA256 = "c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a"
	maxInput     = 1 << 20
)

// Deliberately "raw" public synthetic controls: stale derived labels, the
// kubectl last-applied annotation, unsorted groups/namespaces, SPEED_ prefixes,
// a redundancy group missing from groups, omitted namespaces and unrelated
// label/annotation metadata that must survive on both sides.
const syntheticInput = `
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

// Installer-shaped public Fabricator/ControlNode. Same field shape as the
// production candidate renderer (vlab_trial.candidate_fab) but only hardcoded
// public synthetic, non-deployable values: no environment, .env or private
// configuration. Management/dummy IP hydration is deliberately not exercised.
const fabricatorTemplate = `
{"apiVersion":"fabricator.githedgehog.com/v1beta1","kind":"Fabricator","metadata":{"name":"default","namespace":"fab"},"spec":{"config":{"registry":{"mode":"airgap"},"control":{"joinToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","defaultUser":{"password":"@HASH@","authorizedKeys":["@KEY@"]},"managementSubnet":"172.30.0.0/21","controlVIP":"172.30.0.1/32","kubeClusterSubnet":"172.28.0.0/16","kubeServiceSubnet":"172.29.0.0/16","kubeClusterDNS":"172.29.0.10","dummySubnet":"172.30.90.0/24"},"fabric":{"mode":"spine-leaf","defaultSwitchUsers":{"admin":{"password":"@HASH@","authorizedKeys":["@KEY@"],"role":"admin"},"op":{"password":"@HASH@","authorizedKeys":["@KEY@"],"role":"operator"}},"managementDHCPStart":"172.30.4.0","managementDHCPEnd":"172.30.7.254","spineASN":65100,"leafASNStart":65101,"leafASNEnd":65533,"protocolSubnet":"172.30.8.0/22","vtepSubnet":"172.30.12.0/22","fabricSubnet":"172.30.128.0/17","mclagSessionSubnet":"172.30.95.0/31","vpcWorkaroundSubnet":"172.30.96.0/19"},"observability":{"defaults":""}}}}
---
{"apiVersion":"fabricator.githedgehog.com/v1beta1","kind":"ControlNode","metadata":{"name":"control-1","namespace":"fab"},"spec":{"bootstrap":{"disk":"/dev/sda"},"external":{"interface":"enp2s0","ip":"dhcp"},"management":{"interface":"enp2s1"}}}
`

// Fixed-shape public placeholders: a syntactically valid all-zero ed25519 key
// blob (4+11+4+32 bytes = 68 base64 chars) and a $5$ hash with a 43-char body.
// They are neither keys nor passwords for anything.
func fabricatorInput() []byte {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + strings.Repeat("A", 43)
	hash := "$5$publicfx$" + strings.Repeat("A", 43)
	return []byte(strings.NewReplacer("@KEY@", key, "@HASH@", hash).Replace(fabricatorTemplate))
}

// Separate public control: one non-default value outside the leaf ASN range
// must survive the DefaultConfig merge, proving mergo does not override set values.
func overrideInput() []byte {
	const from, to = `"spineASN":65100`, `"spineASN":65099`
	input := string(fabricatorInput())
	if strings.Count(input, from) != 1 {
		fail("override control source differs")
	}
	return []byte(strings.Replace(input, from, to, 1))
}

type defaulter interface{ Default() }

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pinned-api fixture: "+format+"\n", args...)
	os.Exit(1)
}

func encode(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		fail("encode fixed public output: %v", err)
	}
	return raw
}

func encodeEach(objs []kclient.Object) []json.RawMessage {
	res := []json.RawMessage{}
	for _, obj := range objs {
		res = append(res, encode(obj))
	}
	return res
}

// observe applies the actual typed Default() to an already separate copy.
func observe(obj kclient.Object, gvk schema.GroupVersionKind, invoked map[string]int) json.RawMessage {
	d, ok := obj.(defaulter)
	if !ok {
		fail("missing typed Default for %s", gvk.Kind)
	}
	d.Default()
	invoked[gvk.Kind]++
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	return encode(obj)
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

// readCanonicalWiring reads only the fixed mounted public canonical source.
func readCanonicalWiring() []byte {
	info, err := os.Lstat(wiringPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxInput {
		fail("canonical wiring source refused")
	}
	raw, err := os.ReadFile(wiringPath)
	if err != nil || int64(len(raw)) != info.Size() {
		fail("canonical wiring read failed")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != wiringSHA256 {
		fail("canonical wiring SHA-256 differs from the pinned value")
	}
	return raw
}

type kindList struct {
	kind string
	list kclient.ObjectList
	gv   schema.GroupVersion
}

func includeLists() []kindList {
	return []kindList{
		{"VLANNamespace", &wiringapi.VLANNamespaceList{}, wiringapi.GroupVersion},
		{"IPv4Namespace", &vpcapi.IPv4NamespaceList{}, vpcapi.GroupVersion},
		{"SwitchGroup", &wiringapi.SwitchGroupList{}, wiringapi.GroupVersion},
		{"Switch", &wiringapi.SwitchList{}, wiringapi.GroupVersion},
		{"Server", &wiringapi.ServerList{}, wiringapi.GroupVersion},
		{"Connection", &wiringapi.ConnectionList{}, wiringapi.GroupVersion},
	}
}

type includeRun struct {
	printed   []byte
	originals []json.RawMessage
	before    []json.RawMessage
	defaulted []json.RawMessage
	invoked   map[string]int
}

// runInclude: public YAML -> actual loader -> copies added -> PrintInclude ->
// fresh loader reload -> typed lists -> separate deep copies -> typed Default.
func runInclude(ctx context.Context, input []byte, want map[string]int) includeRun {
	first := apiutil.NewLoader()
	originals, err := first.Load(apiutil.FabricGatewayGVKs, input)
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
	run := includeRun{printed: printed.Bytes(), originals: encodeEach(originals), invoked: map[string]int{}}
	counts := map[string]int{}
	for _, k := range includeLists() {
		if err := second.List(ctx, k.list); err != nil {
			fail("list %s: %v", k.kind, err)
		}
		items, err := kmeta.ExtractList(k.list)
		if err != nil {
			fail("extract %s: %v", k.kind, err)
		}
		for _, item := range items {
			obj, ok := item.(kclient.Object)
			if !ok {
				fail("%s item is not a client object", k.kind)
			}
			beforeRaw := encode(obj)
			run.before = append(run.before, beforeRaw)
			cp, ok := obj.DeepCopyObject().(kclient.Object)
			if !ok {
				fail("%s copy is not a client object", k.kind)
			}
			run.defaulted = append(run.defaulted, observe(cp, k.gv.WithKind(k.kind), run.invoked))
			// Typed Default may mutate nested data; only the copy may change.
			if !bytes.Equal(beforeRaw, encode(obj)) {
				fail("typed Default changed its source control")
			}
			counts[k.kind]++
		}
	}
	if len(counts) != len(want) {
		fail("unexpected kind set %v, want %v", counts, want)
	}
	for kind, n := range want {
		if counts[kind] != n || run.invoked[kind] != n {
			fail("unexpected %s count %d or Default count %d, want %d", kind, counts[kind], run.invoked[kind], n)
		}
	}
	return run
}

func flatten(prefix string, value any, out map[string]string) {
	if m, ok := value.(map[string]any); ok && len(m) > 0 {
		for key, item := range m {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			flatten(path, item, out)
		}
		return
	}
	out[prefix] = string(encode(value))
}

func configPaths(config any) map[string]string {
	var decoded any
	if err := json.Unmarshal(encode(config), &decoded); err != nil {
		fail("decode config: %v", err)
	}
	out := map[string]string{}
	flatten("", decoded, out)
	return out
}

type fabRun struct {
	originals                []json.RawMessage
	fabricator               fabapi.Fabricator
	controls                 []fabapi.ControlNode
	nodes                    []fabapi.FabNode
	added, changed, removed  []string
}

// loadFab follows the pinned official path: apiutil loader (strict decode),
// fab.GetFabAndNodes (DefaultConfig merge, Validate -> Fabricator.Default,
// CalculateVersions, list/sort controls and nodes). No hydration, no downloader.
func loadFab(ctx context.Context, input []byte) fabRun {
	loader := apiutil.NewLoader()
	originals, err := loader.Load(apiutil.FabricatorGVKs, []byte(input))
	if err != nil {
		fail("load fabricator input: %v", err)
	}
	originalBytes := encode(originals)
	var preConfig any
	for _, obj := range originals {
		if f, ok := obj.(*fabapi.Fabricator); ok {
			preConfig = f.Spec.Config.DeepCopy()
		}
		if err := loader.Add(ctx, obj.DeepCopyObject().(kclient.Object)); err != nil {
			fail("add copied fabricator input: %v", err)
		}
	}
	if preConfig == nil {
		fail("fabricator input has no Fabricator")
	}
	f, controls, nodes, err := fab.GetFabAndNodes(ctx, loader.GetClient(), fab.GetFabAndNodesOpts{AllowNotHydrated: true})
	if err != nil {
		fail("get fabricator and nodes: %v", err)
	}
	if !bytes.Equal(originalBytes, encode(originals)) {
		fail("fabricator loading changed original controls")
	}
	run := fabRun{originals: encodeEach(originals), fabricator: f, controls: controls, nodes: nodes}
	pre, post := configPaths(preConfig), configPaths(f.Spec.Config)
	for path, value := range post {
		if old, ok := pre[path]; !ok {
			run.added = append(run.added, path)
		} else if old != value {
			run.changed = append(run.changed, path)
		}
	}
	for path := range pre {
		if _, ok := post[path]; !ok {
			run.removed = append(run.removed, path)
		}
	}
	sort.Strings(run.added)
	sort.Strings(run.changed)
	sort.Strings(run.removed)
	return run
}

// printFab prints deep copies, because the printer mutates label maps.
func printFab(run fabRun) []byte {
	controls := make([]fabapi.ControlNode, 0, len(run.controls))
	for i := range run.controls {
		controls = append(controls, *run.controls[i].DeepCopy())
	}
	nodes := make([]fabapi.FabNode, 0, len(run.nodes))
	for i := range run.nodes {
		nodes = append(nodes, *run.nodes[i].DeepCopy())
	}
	var buf bytes.Buffer
	if err := apiutil.PrintFab(*run.fabricator.DeepCopy(), controls, nodes, &buf); err != nil {
		fail("print fab: %v", err)
	}
	return buf.Bytes()
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func main() {
	out := flag.String("out", "", "existing empty output directory")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		fail("-out is required")
	}
	root := outputRoot(*out)
	ctx := context.Background()

	wiring := readCanonicalWiring()
	canonical := runInclude(ctx, wiring, map[string]int{"VLANNamespace": 1, "IPv4Namespace": 1,
		"SwitchGroup": 3, "Switch": 7, "Server": 10, "Connection": 21})
	synthetic := runInclude(ctx, []byte(syntheticInput), map[string]int{"Switch": 2, "Server": 1, "Connection": 1})

	// Generated Fabricator/ControlNode: load, merge, print, reload, merge, print.
	generated := loadFab(ctx, fabricatorInput())
	if len(generated.controls) != 1 || len(generated.nodes) != 0 {
		fail("unexpected control/fab node count %d/%d", len(generated.controls), len(generated.nodes))
	}
	printedFab := printFab(generated)
	reloaded := loadFab(ctx, printedFab)
	if len(reloaded.controls) != 1 || len(reloaded.nodes) != 0 {
		fail("unexpected reloaded control/fab node count")
	}
	reprinted := printFab(reloaded)
	fixedPoint := bytes.Equal(printedFab, reprinted)

	invoked := map[string]int{}
	fabBefore := []json.RawMessage{encode(&reloaded.fabricator)}
	cp := reloaded.fabricator.DeepCopy()
	fabObserved := []json.RawMessage{observe(cp, fabapi.GroupVersion.WithKind("Fabricator"), invoked)}
	if !bytes.Equal(fabBefore[0], encode(&reloaded.fabricator)) {
		fail("typed Default changed its Fabricator source control")
	}
	defaultUnchanged := bytes.Equal(encode(&reloaded.fabricator), encode(cp))
	for i := range reloaded.controls {
		before := encode(&reloaded.controls[i])
		fabBefore = append(fabBefore, before)
		cpc := reloaded.controls[i].DeepCopy()
		fabObserved = append(fabObserved, observe(cpc, fabapi.GroupVersion.WithKind("ControlNode"), invoked))
		if !bytes.Equal(before, encode(&reloaded.controls[i])) {
			fail("typed Default changed its ControlNode source control")
		}
		defaultUnchanged = defaultUnchanged && bytes.Equal(before, encode(cpc))
	}

	// Separate public controls prove consequential branches execute.
	override := loadFab(ctx, overrideInput())
	overridePaths := configPaths(override.fabricator.Spec.Config)
	loopback := generated.fabricator.DeepCopy()
	loopback.Spec.Config.Fabric.LoopbackWorkaroundDisable = true
	loopback.Default()
	loopbackReset := !loopback.Spec.Config.Fabric.LoopbackWorkaroundDisable

	meta := encode(map[string]any{
		"source": map[string]any{"wiringSHA256": wiringSHA256, "wiringBytes": len(wiring),
			"fabricator": "v0.43.1", "fabric": "v0.96.2"},
		"canonical": map[string]any{"originals": canonical.originals, "beforeDefault": canonical.before,
			"typedDefaultInvoked": canonical.invoked, "originalsUnchanged": true},
		"synthetic": map[string]any{"printed": string(synthetic.printed), "originals": synthetic.originals,
			"beforeDefault": synthetic.before, "defaulted": synthetic.defaulted,
			"typedDefaultInvoked": synthetic.invoked, "originalsUnchanged": true},
		"fabricator": map[string]any{
			"originals": generated.originals, "beforeDefault": fabBefore,
			"typedDefaultInvoked": invoked, "controlNodes": len(generated.controls), "fabNodes": len(generated.nodes),
			"mergeAdded": nonNil(generated.added), "mergeChanged": nonNil(generated.changed),
			"mergeRemoved": nonNil(generated.removed),
			"printFixedPoint": fixedPoint, "reloadMergeAdded": nonNil(reloaded.added),
			"reloadMergeChanged": nonNil(reloaded.changed), "typedDefaultFixedPoint": defaultUnchanged,
			"controlOverrideSpineASN": overridePaths["fabric.spineASN"],
			"controlOverrideChanged": nonNil(override.changed),
			"controlLoopbackDefaultReset": loopbackReset,
		},
	})
	canonicalExpected := append(append(append([]byte{}, printedFab...), []byte("---\n")...), canonical.printed...)
	observed := encode(map[string]any{
		"canonical": append(append([]json.RawMessage{}, fabObserved...), canonical.defaulted...),
		"synthetic": synthetic.defaulted,
	})
	files := []struct {
		name string
		data []byte
	}{
		{"expected.yaml", canonicalExpected}, {"observed.json", observed}, {"meta.json", meta},
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
		fmt.Printf("pinned-api output %s bytes=%d\n", file.name, len(file.data))
	}
	fmt.Printf("pinned-api output total=%d limit=%d\n", total, 1<<20)
	if err := root.Close(); err != nil {
		fail("close output directory: %v", err)
	}
}
