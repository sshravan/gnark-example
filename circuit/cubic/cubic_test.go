package cubic

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/test"
)

func TestCubicEquation(t *testing.T) {
	assert := test.NewAssert(t)

	var cubicCircuit cubic.Circuit

	assert.ProverFailed(&cubicCircuit, &Circuit{
		X: 42,
		Y: 42,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

	assert.ProverSucceeded(&cubicCircuit, &Circuit{
		X: 3,
		Y: 35,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
