package server

import "fmt"

// Create a dependency and add it to the BaseServer's container. A string key identifier will be based on its type definition.
func Create[T any](s Server, createFunc func() T) T {
	result, _ := maybeCreate(s, createFunc)

	return result
}

// CreateNamed is the same as Create but will suffix the dependency string key identifier with a custom name.
// Useful if you want to have multiple named instances of the same object type.
func CreateNamed[T any](s Server, name string, createFunc func() T) T {
	result, _ := maybeCreateNamed(s, name, createFunc)

	return result
}

// Inject lets you override a specific service from outside the BaseServer itself.
// This is useful for tests
func Inject[T any](c Server, thing T) {
	_, _ = maybeCreate(c, func() T {
		return thing
	})
}

// InjectNamed is like Inject() but with a custom name.
func InjectNamed[T any](c Server, name string, thing T) {
	_, _ = maybeCreateKeyed(c, name, func() T {
		return thing
	})
}

func maybeCreate[T any](s Server, createFunc func() T) (result T, isNew bool) {
	key := fmt.Sprintf("%T", (*T)(nil))[1:]
	return maybeCreateKeyed(s, key, createFunc)
}

func maybeCreateNamed[T any](s Server, name string, createFunc func() T) (result T, isNew bool) {
	key := fmt.Sprintf("%T:%s", (*T)(nil), name)[1:]
	return maybeCreateKeyed(s, key, createFunc)
}

func maybeCreateKeyed[T any](s Server, key string, createFunc func() T) (result T, isNew bool) {
	if t, ok := s.GetContainer(key); ok {
		if t == nil {
			return result, false
		}
		return t.(T), false
	}

	t := createFunc()

	s.SetContainer(key, t)

	return t, true
}
