package mimc

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/examples/mimc"
	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	var mimcCircuit mimc.Circuit

	assert.ProverFailed(&mimcCircuit, &Circuit{
		Hash:     42,
		PreImage: 42,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

	assert.ProverSucceeded(&mimcCircuit, &Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "8674594860895598770446879254410848023850744751986836044725552747672873438975",
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
