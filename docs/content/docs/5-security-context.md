---
title: "5. Security Context"
weight: 5
---

# The Security Context

One of the biggest challenges in Go web development is accessing the authenticated user deep within your service layer. Often, developers resort to passing the user object or the HTTP Request context through dozens of function calls.

Rays Web Security solves this using `github.com/timandy/routine` to establish a **ThreadLocal SecurityContext** within its internal implementations.

## Accessing the Authenticated User

Whenever an authenticated request is being processed, the framework automatically binds the `Authentication` object to the current goroutine.

Because the interfaces are exposed in `pkg/core`, you can inject the `SecurityContextHolder` interface directly into any of your Beams and access the context from *anywhere* in your application without passing it down the call stack.

```go
package services

import (
    "fmt"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/lang"
)

type OrderService struct {
    Service
    orderRepo             *OrderRepository      `@:"Inject"`
    securityContextHolder SecurityContextHolder `@:"Inject"` // Properly injected interface
}

func (this *OrderService) PlaceOrder(cart Cart) Error {

    // Retrieve the context using the injected holder for the current thread
    auth := this.securityContextHolder.GetContext().GetAuthentication()

    if auth == nil || !auth.IsAuthenticated() {
        return NewError("Unauthorized", "You must be logged in to place an order")
    }

    // Safely cast the principal back to your domain model
    currentUser := auth.GetPrincipal().(*models.User)

    fmt.Printf("User %s is placing an order for %v\n", currentUser.Email, cart.Total)

    // ... process order ...
    return nil
}

```
