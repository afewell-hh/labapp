module labapp.invalid/pinned-api-fixture

go 1.25

// Exact pins copied from github.com/githedgehog/fabricator v0.43.1 go.mod
// (fabric v0.96.2 is the version that tag requires). go.sum is intentionally
// absent until a lead-reviewed public-only hosted step generates it (#394).
require (
	go.githedgehog.com/fabric v0.96.2
	go.githedgehog.com/fabricator v0.43.1
	k8s.io/apimachinery v0.33.4
	sigs.k8s.io/controller-runtime v0.21.0
)

// Replace directives are not inherited from a dependency's go.mod.
replace gopkg.in/natefinch/lumberjack.v2 v2.2.1 => github.com/githedgehog/lumberjack/v2 v2.2.1-hh

replace github.com/diskfs/go-diskfs => github.com/Frostman/go-diskfs v1.4.2-hh3
