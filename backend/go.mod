module github.com/rolledback/pwsafe-service/backend

go 1.25.5

require (
	github.com/tkuhlman/gopwsafe v0.0.0-20251218040702-a0467f589bea
	golang.org/x/time v0.14.0
)

require (
	github.com/google/uuid v1.0.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	golang.org/x/crypto v0.46.0 // indirect
)

replace github.com/tkuhlman/gopwsafe => github.com/rolledback/gopwsafe v0.0.0-20251225162716-77a49e70e7d9
