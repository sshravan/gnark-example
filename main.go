package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/sshravan/gnark-example/circuit/cubic"
	"github.com/sshravan/gnark-example/circuit/mimc"
)

func cubic_main() {
	fmt.Println("Checks x**3 + x + 5 = y, where x is private and y is public")

	// Compiles the circuit into a R1CS
	var circuit cubic.Circuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	assertNoError(err)

	// Groth16: Setup
	pk, vk, err := groth16.Setup(ccs)
	assertNoError(err)

	// Witness definition
	assignment := cubic.Circuit{X: 3, Y: 35}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	assertNoError(err)

	// Groth16: Prove
	proof, err := groth16.Prove(ccs, pk, witness)
	assertNoError(err)

	// Groth16: Verify
	publicWitness, _ := witness.Public()

	err = groth16.Verify(proof, vk, publicWitness)
	assertNoError(err)
	fmt.Println("Proof verified")
}

func mimc_main() {
	fmt.Println("Checks mimc(private preImage) = public hash")

	// Compiles the circuit into a R1CS
	var circuit mimc.Circuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	assertNoError(err)

	// Groth16: Setup
	pk, vk, err := groth16.Setup(ccs)
	assertNoError(err)

	// Witness definition
	assignment := mimc.Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "8674594860895598770446879254410848023850744751986836044725552747672873438975"}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	assertNoError(err)

	// Groth16: Prove
	proof, err := groth16.Prove(ccs, pk, witness)
	assertNoError(err)

	// Groth16: Verify
	publicWitness, _ := witness.Public()

	err = groth16.Verify(proof, vk, publicWitness)
	assertNoError(err)
	fmt.Println("Proof verified")
}

func main() {
	mimc_main()
	cubic_main()
}

func assertNoError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
