var connect   = require('connect');
var supertest = require('supertest');
var superagent = require('superagent');
var chai      = require('chai');
var assert    = chai.assert;

var headgear = require('../cov/headgear');


var testResponse = function(request, response, next) {
  response.end('This is a test');
};

var server;

var makeServer = function(fn) {
  if(server) {
    server.close();
    server = null;
  }

  var app = connect();
  server = app.listen(8000, function() {
    server.use(testResponse());
    fn(server);
  });
};


suite('Headgear', function() {

  suite('#removePoweredBy', function() {
    test('removes header value', function(done) {
       makeServer(function(app) {
         app.use(function(request, response, next) {
           response.setHeader('X-Powered-By', 'Headgear-test');
           next();
         });
         app.use(headgear.removePoweredBy());

         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.isUndefined(response.header['x-powered-by']);
             }
           });
       });
    });

    test('doesn\'t fail when header isn\'t present', function(done) {
      makeServer(function(app) {
        app.use(headgear.removePoweredBy());
        assert.doesNotThrow(function() {
          supertest(app)
            .get('/')
            .end(function(error) {
              if(error) {
                throw error;
              }
            });
        });
      });
    });
  });

  suite('#noSniff', function() {
    test('has no sniff header value', function(done) {
      // var app = connect();
      // app.use(headgear.noSniff);
      // app.use(function(res, req, next) {
      //   console.log('Test');
      //   next();
      // });
      // app.use(testResponse);
      // app.listen(8000);
      //
      // supertest.agent(app)
      //  .get('/')
      //  .end(function(error, response) {
      //    if(error) {
      //      done(error);
      //    }
      //    else {
      //      console.log(response.header);
      //      done(done);
      //    }
      //  });

       makeServer(function(app) {
         app.use(headgear.noSniff);
         app.use(function(res, req, next) {
           console.log('Test');
           next();
         });

         superagent
          .get('http://localhost:8000/')
          .end(function(error, response) {
            if(error) {
              done(error);
            }
            else {
              console.log(response);
              done();
            }
          })

        //  supertest.agent(app)
        //    .get('/')
        //    .end(function(error, response) {
        //      if(error) {
        //        done(error);
        //      }
        //      else {
        //        assert.strictEqual(response.header['x-content-type-options'], 'nosniff');
        //      }
        //    });
       });
    });
  });

  suite('#frameOption', function() {
    test('throws for unknown option', function(done) {
       makeServer(function(app) {
         app.use(headgear.frameOption('fake'));
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('throws for non-string allowed', function(done) {
       makeServer(function(app) {
         app.use(headgear.frameOption('allow-from', {}));
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('uses default value', function(done) {
       makeServer(function(app) {
         app.use(headgear.frameOption());
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['x-frame-options'], 'sameorigin');
             }
           });
       });
    });

    test('sets given value', function(done) {
       makeServer(function(app) {
         app.use(headgear.frameOption('deny'));
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['x-frame-options'], 'deny');
             }
           });
       });
    });

    test('sets allowed url', function(done) {
       makeServer(function(app) {
         app.use(headgear.frameOption('allow-from', 'http://*.fake.com'));
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['x-frame-options'], 'deny');
             }
           });
       });
    });

  });

  suite('#downloadOption', function() {
    test('has no open header', function(done) {
       makeServer(function(app) {
         app.use(headgear.downloadOption());
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['x-download-options'], 'noopen');
             }
           });
       });
    });
  });

  suite('#transportSecurity', function() {
    test('has sec transport header', function(done) {
      makeServer(function(app) {
        app.use(headgear.transportSecurity(20000));
        supertest(app)
          .get('/')
          .end(function(error, response) {
            if(error) {
              done(error);
            }
            else {
              assert.strictEqual(response.header['strict-transport-security'], 'max-age=20000');
            }
          });
      });
    });

    test('has sec transport header with subdomains', function(done) {
      makeServer(function(app) {
        app.use(headgear.transportSecurity(20000, true));
        supertest(app)
          .get('/')
          .end(function(error, response) {
            if(error) {
              done(error);
            }
            else {
              assert.strictEqual(response.header['strict-transport-security'], 'max-age=20000; includeSubDomains;');
            }
          });
      });
    });
  });

  suite('#xssProtect', function() {
    test('has xss protect header', function(done) {
       makeServer(function(app) {
         app.use(headgear.xssProtect());
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['x-xss-protection'], '1; mode=block;');
             }
           });
       });
    });
  });

  suite('#noCache', function() {
    test('has no cache header', function(done) {
       makeServer(function(app) {
         app.use(headgear.noCache());
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['cache-control'], 'no-cache');
             }
           });
       });
    });
  });

  suite('#contentSecurity', function() {
    test('throw for null options', function(done) {
       makeServer(function(app) {
         app.use(headgear.contentSecurity());
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('throw for non-object options', function(done) {
       makeServer(function(app) {
         app.use(headgear.contentSecurity('test'));
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('has normal header', function(done) {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({connectSrc: ['self', 'https:']}));
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.isDefined(response.header['content-security-policy']);
             }
           });
       });
    });

     test('has report only header', function(done) {
        makeServer(function(app) {
          app.use(headgear.contentSecurity({connectSrc: ['self', 'https:'], report: true}));
          supertest(app)
            .get('/')
            .end(function(error, response) {
              if(error) {
                done(error);
              }
              else {
                assert.isDefined(response.header['content-security-policy-report-only']);
              }
            });
        });
     });

    test('has given header value', function(done) {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({connectSrc: ['self', 'https:'], report: true}));
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['content-security-policy'], 'connect-src \'self\' https:;');
             }
           });
       });
    });

    test('correctly adds quotes to the needed values', function(done) {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({connectSrc: ['none', 'self', 'unsafe-inline', 'unsafe-eval'], report: true}));
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['content-security-policy'], 'connect-src \'none\' \'self\' \'unsafe-inline\' \'unsafe-eval\'');
             }
           });
       });
    });

    test('correctly adds upgrade-insecure-requests of 1', function(done) {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({upgradeInsecureRequests: true}));
         supertest(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               done(error);
             }
             else {
               assert.strictEqual(response.header['content-security-policy'], 'upgrade-insecure-requests 1');
             }
           });
       });
    });
  });

  suite('#keyPinning', function() {
    test('throw for null keys', function(done) {
       makeServer(function(app) {
         app.use(headgear.keyPinning(null, 3543513));
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('throw if keys aren\'t an array', function(done) {
       makeServer(function(app) {
         app.use(headgear.keyPinning({}, 3543513));
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('throw if keys have no elements', function(done) {
       makeServer(function(app) {
         app.use(headgear.keyPinning([], 3543513));
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('throw for null maxAge', function(done) {
       makeServer(function(app) {
         app.use(headgear.keyPinning(['GRAH5Ex+kB4cCQi5gMU82urf+6kEgbVtzfCSkw55AGk=']));
         assert.throws(function() {
           supertest(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('has correct header value', function(done) {
      makeServer(function(app) {
        app.use(headgear.keyPinning(['GRAH5Ex+kB4cCQi5gMU82urf+6kEgbVtzfCSkw55AGk='], 15768000));
        supertest(app)
          .get('/')
          .end(function(error, response) {
            if(error) {
              done(error);
            }
            else {
              var expected = 'pin-sha256="GRAH5Ex+kB4cCQi5gMU82urf+6kEgbVtzfCSkw55AGk=";max-age=15768000;';
              return assert.strictEqual(response.header['public-key-pins'], expected);
            }
          });
      });
    });

    test('has correct header value (2)', function(done) {
      makeServer(function(app) {
        app.use(headgear.keyPinning(
          ['GRAH5Ex+kB4cCQi5gMU82urf+6kEgbVtzfCSkw55AGk=', 'lERGk61FITjzyKHcJ89xpc6aDwtRkOPAU0jdnUqzW2s='],
          15768000,
          true,
          'google.com'
        ));

        supertest(app)
          .get('/')
          .end(function(error, response) {
            if(error) {
              done(error);
            }
            else {
              var expected = 'pin-sha256="GRAH5Ex+kB4cCQi5gMU82urf+6kEgbVtzfCSkw55AGk=";' +
                             'pin-sha256="lERGk61FITjzyKHcJ89xpc6aDwtRkOPAU0jdnUqzW2s=";' +
                             'max-age=15768000;includeSubdomains;report-uri="google.com";';
              // return assert.strictEqual(response.header['public-key-pins-report-only'], expected);
              return assert.strictEqual(true, false);
            }
          });
      });
    });

  });
//['GRAH5Ex+kB4cCQi5gMU82urf+6kEgbVtzfCSkw55AGk=']
//15768000
});
