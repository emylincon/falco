package context

import (
	"github.com/ysugimoto/falco/linter/types"
)

// addTestingFunctions registers testing-specific builtin functions
// in the linter context. These functions are available in .test.vcl files
// and are prefixed with "testing.".
func addTestingFunctions(c *Context) {
	// testing.call_subroutine accepts the subroutine name as the first
	// required STRING argument, plus zero or more subroutine arguments.
	// The Extra hook returns the *types.Subroutine for the given name so
	// the caller can validate the extra arguments against its parameters.
	allScopes := RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG
	c.AddFunction("testing.call_subroutine", &BuiltinFunction{
		Arguments: [][]types.Type{
			{types.StringType},
		},
		Return: types.NeverType,
		Extra: func(c *Context, name string) any {
			return c.Subroutines[name]
		},
		Scopes: allScopes,
	})
}
