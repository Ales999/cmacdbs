package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// configData — структура настроек из файла конфигурации (cmacdb.yaml).
//
//	config:
//	  startsw:            — root-комутаторы, с которых начинаем обход сети (BFS).
//	    - switch1
//	    - switch2
//	  db: macs.db         — путь к файлу базы данных bbolt (пусто → «macs.db»).
//
// Новые настройки добавляются в тот же вложенный «config», чтобы не ломать
// структуру существующих файлов.
type configData struct {
	Config struct {
		// StartSwitches — список root-комутаторов для обхода сети.
		StartSwitches []string `yaml:"startsw"`
		// DbPath — путь к файлу базы данных bbolt. Пусто → «macs.db».
		DbPath string `yaml:"db"`
	} `yaml:"config"`
}

// loadConfig открывает и читает файл конфигурации по пути path, распарсивая его
// в configData. При ошибке открытия/чтения файла или некорректного YAML
// loadConfig возвращает ошибку, которую caller должен обработать (в main —
// закрыть программу через log.Fatalf).
func loadConfig(path string) (*configData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть файл конфигурации %q: %w", path, err)
	}
	var cfg configData
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("не удалось распарсить файл конфигурации %q: %w", path, err)
	}
	return &cfg, nil
}
