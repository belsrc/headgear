var supertest = require('supertest');

var express = require('express');
var app = express();
var http = require('http').Server(app);
var headgear = require('../lib/headgear');

http.listen(8000);

app.use(headgear.noSniff());
app.use(headgear.removePoweredBy());
app.use(headgear.frameOption('deny'));
app.use(headgear.downloadOption());
app.use(headgear.transportSecurity(20000, true));
app.use(headgear.xssProtect());
app.use(headgear.noCache());
app.use(headgear.contentSecurity({
  connectSrc: ['self', 'https:'],
  scriptSrc: ['self', 'https:'],
  styleSrc: ['self', 'https:'],
  reflectedXss: 'block',
  reportUri: 'http://test.com',
  upgradeInsecureRequests: true,
  report: true
}));
app.use(headgear.keyPinning(
  ['cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=', 'M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE='],
  5184000,
  true,
  'google.com'
));

app.get('/', function(request, response){
  response.send('This is a test');
});


var agent = supertest.agent(app);

suite('Headgear', function() {

  suite('#removePoweredBy', function() {
    test('removes header value', function(done) {
      agent
        .get('/')
        .end(function(error, response) {
          if(error) {
            done(error);
          }
          else {
            if(response.header['x-powered-by']) {
              done(new Error('x-powered-by is ' + response.header['x-powered-by']));
            }
            else {
              done();
            }
          }
        });
    });
  });

  suite('#noSniff', function() {
    test('has no sniff header value', function(done) {
      agent
        .get('/')
        .expect('x-content-type-options', 'nosniff', done);
    });
  });

  suite('#frameOption', function() {
    test('has deny header value', function(done) {
      agent
        .get('/')
        .expect('frame-options', 'deny', done);
    });
  });

  suite('#downloadOption', function() {
    test('has no open header', function(done) {
      agent
        .get('/')
        .expect('x-download-options', 'noopen', done);
    });
  });

  suite('#transportSecurity', function() {
    test('has sec transport header with subdomains', function(done) {
      agent
        .get('/')
        .expect('strict-transport-security', 'max-age=20000; includeSubDomains;', done);
    });
  });

  suite('#xssProtect', function() {
    test('has xss protect header', function(done) {
      agent
        .get('/')
        .expect('x-xss-protection', '1; mode=block;', done);
    });
  });

  suite('#noCache', function() {
    test('has no cache header', function(done) {
      agent
        .get('/')
        .expect('cache-control', 'no-cache', done);
    });
  });

  suite('#contentSecurity', function() {
    test('has content security header value', function(done) {
      var expected = 'connect-src \'self\' https:; script-src \'self\' https:; ' +
                     'style-src \'self\' https:; reflected-xss block; report-uri http://test.com; ' +
                     'upgrade-insecure-requests 1; ';
      agent
        .get('/')
        .expect('content-security-policy-report-only', expected, done);
    });
  });

  suite('#keyPinning', function() {
    test('has key pins header value', function(done) {
      var expected = 'pin-sha256="cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs="; ' +
                     'pin-sha256="M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="; ' +
                     'max-age=5184000; includeSubdomains; report-uri="google.com"; ';
      agent
        .get('/')
        .expect('public-key-pins-report-only', expected, done);
    });
  });

});
