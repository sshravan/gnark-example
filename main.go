package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/sshravan/gnark-example/circuit/cubic"
	"github.com/sshravan/gnark-example/circuit/mimc"
)

func driverGroth16(circuit, assignment frontend.Circuit) bool {

	// Compiles the circuit into a R1CS
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assertNoError(err)

	// Groth16: Setup
	pk, vk, err := groth16.Setup(ccs)
	assertNoError(err)

	// Witness definition
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assertNoError(err)

	// Groth16: Prove
	proof, err := groth16.Prove(ccs, pk, witness)
	assertNoError(err)

	// Groth16: Verify
	publicWitness, _ := witness.Public()

	err = groth16.Verify(proof, vk, publicWitness)
	assertNoError(err)
	fmt.Println("Groth16 proof verified")
	return true
}

func driverPlonk(circuit, assignment frontend.Circuit) bool {
	// Compiles the circuit into an SCS (for Plonk)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	assertNoError(err)

	// Plonk: SRS and Setup (use same SRS for proving and verifying in this example)
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	assertNoError(err)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	assertNoError(err)

	// Witness definition
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assertNoError(err)

	// Plonk: Prove
	proof, err := plonk.Prove(ccs, pk, witness)
	assertNoError(err)

	// Plonk: Verify
	publicWitness, _ := witness.Public()

	err = plonk.Verify(proof, vk, publicWitness)
	assertNoError(err)
	fmt.Println("Plonk proof verified")
	return true
}

func main() {
	var cubic_circuit cubic.Circuit
	cubic_assignment := cubic.Circuit{X: 3, Y: 35}

	driverGroth16(&cubic_circuit, &cubic_assignment)
	driverPlonk(&cubic_circuit, &cubic_assignment)

	var mimc_circuit mimc.Circuit
	mimc_assignment := mimc.Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753"}

	driverGroth16(&mimc_circuit, &mimc_assignment)
	driverPlonk(&mimc_circuit, &mimc_assignment)
}

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
