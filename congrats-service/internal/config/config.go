package config

type Config struct {
	Port, MongoURI, MongoDB, AuthJWKSURL string
	JWKSCacheSeconds                     int
}
