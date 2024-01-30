package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	options "go.mongodb.org/mongo-driver/mongo/options"
)

type Options struct {
	Username   string
	Password   string
	Host       string
	Database   string
	Collection string
}

type Database struct {
	collection *mongo.Collection
}

// Opens a connection to the database.
func Create(databaseOptions *Options, ctx context.Context) (*Database, error) {
	mongodbUri := fmt.Sprintf("mongodb://%s", databaseOptions.Host)
	client, err := mongo.Connect(ctx, options.Client().
		ApplyURI(mongodbUri).
		SetAuth(options.Credential{
			AuthMechanism: "SCRAM-SHA-256",
			Username:      databaseOptions.Username,
			Password:      databaseOptions.Password,
		}))
	if err != nil {
		return nil, err
	}
	database := client.Database(databaseOptions.Database)
	return &Database{
		collection: database.Collection(databaseOptions.Collection),
	}, nil
}

// Queries the database and returns nil if the record was found, ErrNoDocuments
// if no record was found, or a different error if an error occured.
func (db *Database) Query(context context.Context, email string) error {
	result := db.collection.FindOne(context, bson.M{"email": email})
	return result.Err()
}
