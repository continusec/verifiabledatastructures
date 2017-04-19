package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/continusec/verifiabledatastructures"
	"github.com/continusec/verifiabledatastructures/pb"
)

func loadLog(acc *verifiabledatastructures.Account) {
	vlog := acc.VerifiableLog("test")

	count := 20000

	start := time.Now()
	var err error
	var lastLeaf verifiabledatastructures.LogUpdatePromise
	for i := 0; i < count; i++ {
		lastLeaf, err = vlog.Add(&pb.LeafData{LeafInput: []byte("v" + strconv.Itoa(i))})
		if err != nil {
			log.Fatal(err)
		}
		if i%10000 == 0 {
			log.Println(i)
			end := time.Now()
			fmt.Println("Objects per second:", float64(i)/end.Sub(start).Seconds())
		}
	}
	end := time.Now()
	fmt.Println("Objects per second:", float64(count)/end.Sub(start).Seconds())
	treeHead, err := lastLeaf.Wait()
	if err != nil {
		log.Fatal(err)
	}

	end = time.Now()

	fmt.Println("Actual objects per second:", float64(count)/end.Sub(start).Seconds())
	fmt.Println("Tree head:", treeHead)
}

func loadMap(acc *verifiabledatastructures.Account) {
	vmap := acc.VerifiableMap("maptest")

	count := 1000000

	start := time.Now()
	var err error
	for i := 0; i < count; i++ {
		_, err = vmap.Set([]byte("k"+strconv.Itoa(i)), &pb.LeafData{LeafInput: []byte("v" + strconv.Itoa(i))})
		if err != nil {
			log.Fatal(err)
		}
		if i%1000 == 0 {
			log.Println(i)
			end := time.Now()
			fmt.Println("Objects per second:", float64(i)/end.Sub(start).Seconds())
		}
	}
	end := time.Now()

	treeHead, err := vmap.TreeHead(0)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Objects per second:", float64(count)/end.Sub(start).Seconds())
	fmt.Println("Tree head:", treeHead)
}

func main() {
	db := &verifiabledatastructures.BoltBackedService{Path: "/Users/aeijdenberg/Documents/continusec/vdsdemo/data"}
	//db := &verifiabledatastructures.TransientHashMapStorage{}
	acc := (&verifiabledatastructures.Client{Service: (&verifiabledatastructures.LocalService{
		AccessPolicy: &verifiabledatastructures.AnythingGoesOracle{},
		Mutator: (&verifiabledatastructures.BatchMutator{
			Writer:     db,
			BatchSize:  1000,
			BufferSize: 100000,
			Timeout:    time.Millisecond * 10,
		}).MustCreate(),
		//Mutator:      &api.InstantMutator{Writer: db},
		Reader: db,
	}).MustCreate()}).Account("0", "")
	loadLog(acc)
}
