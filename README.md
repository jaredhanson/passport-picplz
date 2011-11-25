# Passport-picplz

[Passport](https://github.com/jaredhanson/passport) strategy for authenticating
with picplz using the OAuth 2.0 API.

## Installation

    $ npm install passport-picplz

## Usage

#### Configure Strategy

The picplz authentication strategy authenticates users using a picplz account
and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which accepts
these credentials and calls `done` providing a user, as well as `options`
specifying a client ID, client secret, and callback URL.

    passport.use(new PicplzStrategy({
        clientID: PICPLZ_OAUTH2_KEY,
        clientSecret: PICPLZ_OAUTH2_SECRET,
        callbackURL: "http://127.0.0.1:3000/auth/picplz/callback"
      },
      function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ picplzId: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'picplz'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/picplz',
      passport.authenticate('picplz'),
      function(req, res){
        // The request will be redirected to picplz for authentication, so this
        // function will not be called.
      });

    app.get('/auth/picplz/callback', 
      passport.authenticate('picplz', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

#### Examples

For a complete, working example, refer to the [login example](https://github.com/jaredhanson/passport-picplz/tree/master/examples/login).

## Credits

  - [Jared Hanson](http://github.com/jaredhanson)

## License

(The MIT License)

Copyright (c) 2011 Jared Hanson

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
