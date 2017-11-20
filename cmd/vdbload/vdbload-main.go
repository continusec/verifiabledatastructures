package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/continusec/verifiabledatastructures/mutator/batch"
	"github.com/continusec/verifiabledatastructures/oracle/policy"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/storage/memory"
	"github.com/continusec/verifiabledatastructures/verifiable"
)

func loadLog(acc *verifiable.Account) {
	vlog := acc.VerifiableLog("test")

	count := 100000

	ctx := context.Background()

	start := time.Now()
	var err error
	var lastLeaf verifiable.LogUpdatePromise
	for i := 0; i < count; i++ {
		lastLeaf, err = vlog.Add(ctx, &pb.LeafData{LeafInput: []byte("v" + strconv.Itoa(i))})
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
	treeHead, err := lastLeaf.Wait(ctx)
	if err != nil {
		log.Fatal(err)
	}

	end = time.Now()

	fmt.Println("Actual objects per second:", float64(count)/end.Sub(start).Seconds())
	fmt.Println("Tree head:", treeHead)
}

func loadMap(acc *verifiable.Account) {
	vmap := acc.VerifiableMap("maptest")

	count := 1000000

	ctx := context.Background()

	start := time.Now()
	var err error
	for i := 0; i < count; i++ {
		_, err = vmap.Set(ctx, []byte("k"+strconv.Itoa(i)), &pb.LeafData{LeafInput: []byte("v" + strconv.Itoa(i))})
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

	treeHead, err := vmap.TreeHead(ctx, 0)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Objects per second:", float64(count)/end.Sub(start).Seconds())
	fmt.Println("Tree head:", treeHead)
}

func main() {
	//db := &verifiabledatastructures.BoltBackedService{Path: "/tmp/data"}
	//defer db.Close()
	db := &memory.TransientStorage{}
	acc := (&verifiable.Client{Service: (&verifiable.Service{
		AccessPolicy: policy.Open,
		Mutator: (&batch.Mutator{
			Writer:     db,
			BatchSize:  1000,
			BufferSize: 100000,
			Timeout:    time.Millisecond * 10,
		}).MustCreate(),
		//Mutator: &instant.Mutator{Writer: db},
		Reader: db,
	}).MustCreate()}).Account("0", "")
	loadLog(acc)
}
