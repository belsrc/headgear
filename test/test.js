var connect = require('connect');
var req     = require('supertest');
var chai    = require('chai');
var assert  = chai.assert;

var headgear = require('../cov/headgear');


var testResponse = function(request, response, next) {
  response.end('This is a test');
};

var makeServer = function(fn) {
  var app = connect();
  var server = app.listen(3000, function() {
    server.use(testResponse());
    fn(server);
  });
};


suite('Headgear', function() {

  suite('#removePoweredBy', function() {
    test('removes header value', function() {
       makeServer(function(app) {
         app.use(function(request, response, next) {
           response.setHeader('X-Powered-By', 'Headgear-test');
           next();
         });
         app.use(headgear.removePoweredBy());
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.isUndefined(response.header['x-powered-by']);
             }
           });
       });
    });

    test('doesn\'t fail when header isn\'t present', function() {
      makeServer(function(app) {
        app.use(headgear.removePoweredBy());
        assert.doesNotThrow(function() {
          req(app)
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
    test('has no sniff header value', function() {
       makeServer(function(app) {
         app.use(headgear.noSniff());
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['x-content-type-options'], 'nosniff');
             }
           });
       });
    });
  });

  suite('#frameOption', function() {
    test('throws for unknown option', function() {
       makeServer(function(app) {
         app.use(headgear.frameOption('fake'));
         assert.throws(function() {
           req(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('throws for non-string allowed', function() {
       makeServer(function(app) {
         app.use(headgear.frameOption('allow-from', {}));
         assert.throws(function() {
           req(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('uses default value', function() {
       makeServer(function(app) {
         app.use(headgear.frameOption());
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['x-frame-options'], 'sameorigin');
             }
           });
       });
    });

    test('sets given value', function() {
       makeServer(function(app) {
         app.use(headgear.frameOption('deny'));
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['x-frame-options'], 'deny');
             }
           });
       });
    });

    test('sets allowed url', function() {
       makeServer(function(app) {
         app.use(headgear.frameOption('allow-from', 'http://*.fake.com'));
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['x-frame-options'], 'deny');
             }
           });
       });
    });

  });

  suite('#downloadOption', function() {
    test('has no open header', function() {
       makeServer(function(app) {
         app.use(headgear.downloadOption());
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['x-download-options'], 'noopen');
             }
           });
       });
    });
  });

  suite('#transportSecurity', function() {
    test('has sec transport header', function() {
      makeServer(function(app) {
        app.use(headgear.transportSecurity(20000));
        req(app)
          .get('/')
          .end(function(error, response) {
            if(error) {
              console.log(error.stack);
            }
            else {
              assert.strictEqual(response.header['strict-transport-security'], 'max-age=20000');
            }
          });
      });
    });

    test('has sec transport header with subdomains', function() {
      makeServer(function(app) {
        app.use(headgear.transportSecurity(20000, true));
        req(app)
          .get('/')
          .end(function(error, response) {
            if(error) {
              console.log(error.stack);
            }
            else {
              assert.strictEqual(response.header['strict-transport-security'], 'max-age=20000; includeSubDomains;');
            }
          });
      });
    });
  });

  suite('#xssProtect', function() {
    test('has xss protect header', function() {
       makeServer(function(app) {
         app.use(headgear.xssProtect());
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['x-xss-protection'], '1; mode=block;');
             }
           });
       });
    });
  });

  suite('#noCache', function() {
    test('has no cache header', function() {
       makeServer(function(app) {
         app.use(headgear.noCache());
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['cache-control'], 'no-cache');
             }
           });
       });
    });
  });

  suite('#contentSecurity', function() {
    test('throw for null options', function() {
       makeServer(function(app) {
         app.use(headgear.contentSecurity());
         assert.throws(function() {
           req(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('throw for non-object options', function() {
       makeServer(function(app) {
         app.use(headgear.contentSecurity('test'));
         assert.throws(function() {
           req(app)
             .get('/')
             .end(function(error) {
               if(error) {
                 throw error;
               }
             });
         });
       });
    });

    test('has normal header', function() {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({connectSrc: ['self', 'https:']}));
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.isDefined(response.header['content-security-policy']);
             }
           });
       });
    });

     test('has report only header', function() {
        makeServer(function(app) {
          app.use(headgear.contentSecurity({connectSrc: ['self', 'https:'], report: true}));
          req(app)
            .get('/')
            .end(function(error, response) {
              if(error) {
                console.log(error.stack);
              }
              else {
                assert.isDefined(response.header['content-security-policy-report-only']);
              }
            });
        });
     });

    test('has given header value', function() {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({connectSrc: ['self', 'https:'], report: true}));
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['content-security-policy'], 'connect-src \'self\' https:;');
             }
           });
       });
    });

    test('correctly adds quotes to the needed values', function() {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({connectSrc: ['none', 'self', 'unsafe-inline', 'unsafe-eval'], report: true}));
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['content-security-policy'], 'connect-src \'none\' \'self\' \'unsafe-inline\' \'unsafe-eval\'');
             }
           });
       });
    });

    test('correctly adds upgrade-insecure-requests of 1', function() {
       makeServer(function(app) {
         app.use(headgear.contentSecurity({upgradeInsecureRequests: true}));
         req(app)
           .get('/')
           .end(function(error, response) {
             if(error) {
               console.log(error.stack);
             }
             else {
               assert.strictEqual(response.header['content-security-policy'], 'upgrade-insecure-requests 1');
             }
           });
       });
    });
  });

});
