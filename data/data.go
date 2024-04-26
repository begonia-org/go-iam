package data

import "github.com/spark-lence/tiga"

type Data interface{
	Insert()
	Select()
	Update()
	Delete()
}
type DataImpl struct {
	mongo *tiga.MongodbDao
}