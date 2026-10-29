package main

import (
	"log"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// Структуры данных
type Visit struct {
	SwitchID  string    `json:"switch_id"`
	Port      string    `json:"port"`
	Timestamp time.Time `json:"timestamp"`
}

type MacRecord struct {
	MacAddress string  `json:"mac_address"`
	Current    Visit   `json:"current"`
	History    []Visit `json:"history"`
}

var (
	db         *bbolt.DB
	bucketName = []byte("MacHistory")
	isScanning bool       // Флаг, чтобы не запустить сканирование дважды одновременно
	scanMu     sync.Mutex // Мутекс для защиты флага сканирования
)

func main() {
	var err error
	db, err = bbolt.Open("macs.db", 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Ошибка открытия БД: %v", err)
	}
	defer db.Close()

	// Тут далее наш код
	collectDataAndSave()

}
