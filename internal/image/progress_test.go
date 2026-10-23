package image

import (
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// sizelessLayer is a layer whose size is unknown.
type sizelessLayer struct{ v1.Layer }

func (sizelessLayer) Size() (int64, error) { return 0, errors.New("unknown") }

func TestLayerMessage(t *testing.T) {
	sized := static.NewLayer([]byte("ab"), types.OCIUncompressedLayer)
	sizeless := sizelessLayer{static.NewLayer([]byte("abc"), types.OCIUncompressedLayer)}
	tests := []struct {
		name  string
		i, n  int
		layer v1.Layer
		want  string
	}{
		{name: "top layer of several says it comes first", i: 2, n: 3, layer: sized, want: "reading layer 3/3 (2 B, top layer first)"},
		{name: "middle layer", i: 1, n: 3, layer: sized, want: "reading layer 2/3 (2 B)"},
		{name: "base layer of unknown size", i: 0, n: 3, layer: sizeless, want: "reading layer 1/3 (size unknown)"},
		{name: "only layer", i: 0, n: 1, layer: sized, want: "reading layer 1/1 (2 B)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := layerMessage(tc.i, tc.n, tc.layer); got != tc.want {
				t.Errorf("layerMessage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReporter(t *testing.T) {
	reporter(nil)("ignored") // must not panic
	var progress progressLog
	reporter(progress.add)("hello")
	assertStrings(t, "progress", progress.messages(), []string{"hello"})
}
