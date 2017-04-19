package main

import "github.com/continusec/verifiabledatastructures/pb"
import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/continusec/verifiabledatastructures/api"
	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/kvstore"
	
)

func loadLog(acc *client.Account) {
	vlog := acc.VerifiableLog("test")

	count := 20000

	start := time.Now()
	var err error
	var lastLeaf client.LogUpdatePromise
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

func loadMap(acc *client.Account) {
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
	db := &kvstore.BoltBackedService{Path: "/Users/aeijdenberg/Documents/continusec/vdsdemo/data"}
	//db := &kvstore.TransientHashMapStorage{}
	s := &api.LocalService{
		AccessPolicy: &api.AnythingGoesOracle{},
		Mutator: api.CreateBatchMutator(&api.BatchMutatorConfig{
			Writer:     db,
			BatchSize:  1000,
			BufferSize: 100000,
			Timeout:    time.Millisecond * 10,
		}),
		//Mutator:      &api.InstantMutator{Writer: db},
		Reader: db,
	}

	acc := (&client.VerifiableDataStructuresClient{Service: s}).Account("0", "")
	loadLog(acc)
}
