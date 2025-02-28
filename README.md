# Rust + Actix + Auth0
This project is a proof of concept that demonstrates how to integrate [Auth0](https://auth0.com/) with a Rust web server using the Actix framework. 

It's not much, but I did really struggle to find a working example, I hope this helps.

The project runs a webserver that offers:
* A single web page, only accessible after login, which allows to logout and see your token
* A single api endpoint that also requires authentication

You'll need to create a .env file with the values provided by Auth0 for your app:
```bash
AUTH0_CLIENT_ID=...
AUTH0_CLIENT_SECRET=...
AUTH0_DOMAIN=...
```

You can then run the project:
```bash
cargo run # localhost:8000
```

Please note callback and redirect urls might need to be adjusted to match your Auth0 app config.