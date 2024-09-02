/*
Package auth manages the authentication process with the relay server.

Key Components:

Validator: The Validator interface defines the Validate method. Any type that provides this method can be used as a
Validator.

Methods:

Validate(func() hash.Hash, any): This method is defined in the Validator interface and is used to validate the authentication.

Usage:

To create a new AllowAllAuth validator, simply instantiate it:

	validator := &allow.Auth{}

To validate the authentication, use the Validate method:

	err := validator.Validate(sha256.New, any)

This package provides a simple and effective way to manage authentication with the relay server, ensuring that the
peers are authenticated properly.
*/
package auth
