// Package gorm is an offline stand-in for gorm.io/gorm.
package gorm

type DB struct{}

func (db *DB) Create(value interface{}) *DB { return db }
func (db *DB) Save(value interface{}) *DB   { return db }
