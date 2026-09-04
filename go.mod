module github.com/rezen/smash

go 1.26.0

require (
	gopkg.in/yaml.v3 v3.0.1
	mvdan.cc/sh/v3 v3.14.0
)

require (
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
)

replace mvdan.cc/sh/v3 => ./third_party/sh
