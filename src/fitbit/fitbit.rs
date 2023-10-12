// TODO: implement a fibit api https://dev.fitbit.com/build/reference/web-api/
use oauth2::basic::BasicClient;

// Alternatively, this can be `oauth2::curl::http_client` or a custom client.
use dotenv::dotenv;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
    PkceCodeChallenge
};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

use crate::fitbit;

pub fn main() {
    dotenv().ok();
    println!("extern func call!");
    let fitbit_client_id = ClientId::new(
        env::var("FITBIT_CLIENT_ID").expect("Missing the GITHUB_CLIENT_ID environment variable."),
    );
    // let fitbit_client_secret = ClientSecret::new(
    //     env::var("FITBIT_CLIENT_SECRET")
    //         .expect("Missing the FITBIT_CLIENT_SECRET environment variable."),
    // );
        let fitbit_client_secret = env::var("FITBIT_CLIENT_SECRET")
            .expect("Missing the FITBIT_CLIENT_SECRET environment variable.");
    let auth_url = AuthUrl::new("https://www.fitbit.com/oauth2/authorize".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.fitbit.com/oauth2/authorize".to_string())
        .expect("Invalid token endpoint URL");

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = BasicClient::new(
        ClientId::new(fitbit_client_id.to_string()),
        Some(ClientSecret::new(fitbit_client_secret.to_string())),
        AuthUrl::new(auth_url.to_string()).unwrap(),
        Some(TokenUrl::new(token_url.to_string()).unwrap()),
    );
    // Set the URL the user will be redirected to after the authorization process.
    // .set_redirect_uri(RedirectUrl::new(" https://localhost:8080".to_string()).unwrap());

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("activity".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Browse to: {}", auth_url);

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

      // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                // let mut request_line = String::new();
                // originally tried using readline, but the tcp stream is not valid utf 8
                // reader.read_line(&mut request_line).unwrap();
                let mut buf = vec![];

                // this is temp workaround to read the buffer in a safe way, but it is outputting a bunch of garbage
                while let Ok(_) = reader.read_until(b'\n', &mut buf){
                    if buf.is_empty() {
                        break;
                    }
                    let line = String::from_utf8_lossy(&buf);
                    println!("{}", line);
                }

                // temp var for compilation
                let read_line = String::from("value");
                let redirect_url = read_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Google returned the following code:\n{}\n", code.secret());
            println!(
                "Google returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_token.secret()
            );

            // Exchange the code with a token.
            let token_response = client
                .exchange_code(code)
                .set_pkce_verifier(pkce_verifier)
                .request(http_client);

            println!(
                "Google returned the following token:\n{:?}\n",
                token_response
            );

            break;
        }
    }
}
