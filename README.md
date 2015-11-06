## Headgear
Sets various HTTP header values that **_help_** secure your Express.js application. This **WILL NOT** fully protect any application, this is merely some seriously low hanging fruit.

### Install
-----------------------------------------------------

Install the package
```bash
npm install headgear --save
```

Then simply include the module and add it into the application.
```javascript
var headgear = require('headgear');
var config = require('./headgear.json');

app.use(headgear.all(config));
```

### Available Middleware
-----------------------------------------------------

#### #removePoweredBy()
Removes the the ```X-Powered-By``` from the response headers.
```javascript
var headgear = require('headgear');
app.use(headgear.removePoweredBy());
```

#### #noSniff()
Adds ```X-Content-Type-Options: nosniff``` to the response header.
```javascript
var headgear = require('headgear');
app.use(headgear.noSniff());
```

#### #frameOption(option:String, allowed:String)
Adds ```X-Frame-Options: sameorigin``` to the response header. The ```allowed``` argument only needs to be supplied when using the option type of ```allow-from```.
```option``` can be any of ```[deny, sameorigin, allow-from, allowall]``` if no value is given it defaults to ```sameorigin```
```javascript
var headgear = require('headgear');
app.use(headgear.frameOption('sameorigin'));
```

#### #downloadOption()
Adds ```X-Download-Options: noopen``` to the response header.
```javascript
var headgear = require('headgear');
app.use(headgear.downloadOption());
```

#### #transportSecurity(seconds:Number, withSubdomains:Boolean)
Adds ```Strict-Transport-Security: max-age=31536000; includeSubDomains;``` to the response header if ```withSubdomains``` is ```true``` otherwise, ```Strict-Transport-Security:max-age=31536000```.
```javascript
var headgear = require('headgear');
app.use(headgear.transportSecurity(31536000, true));
```

#### #xssProtect()
Adds ```X-XSS-Protection:1; mode=block;``` to the response header.
```javascript
var headgear = require('headgear');
app.use(headgear.xssProtect());
```

#### #noCache()
Adds ```Cache-Control: no-cache``` to the response header.
```javascript
var headgear = require('headgear');
app.use(headgear.noCache());
```

#### #contentSecurity(options:Object)
Adds ```Content-Security-Policy-Report-Only: connect-src 'self' https:; ...``` or ```Content-Security-Policy: connect-src 'self' https:; ...``` to the response header.
```javascript
var headgear = require('headgear');
var options = {
  connectSrc: ['self', 'https:'],
  report: true
};
app.use(headgear.contentSecurity(options));
```
Available options are:
```
{
  baseUri: String,
  childSrc: String,
  defaultSrc: String|Array,
  connectSrc: String|Array,
  scriptSrc: String|Array,
  styleSrc: String|Array,
  fontSrc: String|Array,
  frameSrc: String|Array,
  imgSrc: String|Array,
  manifestSrc: String|Array,
  mediaSrc: String|Array,
  objectSrc: String|Array,
  formAction: String|Array,
  frameAncestors: String|Array,
  pluginTypes: String|Array,
  referrer: String [no-referrer, no-referrer-when-downgrade, origin, origin-when-cross-origin, unsafe-url],
  reflectedXss: String [allow, block, filter],
  reportUri: String,
  sandbox: String {allow-forms, allow-same-origin, allow-scripts and allow-top-navigation},
  upgradeInsecureRequests: Boolean,
  report: Boolean
}
```
More information on the accepted values can be found here: https://developer.mozilla.org/en-US/docs/Web/Security/CSP/CSP_policy_directives

#### #all(options:Object)
Adds the ```#removePoweredBy```, ```#noSniff```, ```#downloadOption```, ```#xssProtect```, ```#frameOption```, ```#transportSecurity``` middleware. The ```#noCache``` and ```#contentSecurity``` are NOT included. The ```options``` argument is an object that contains the settings for the ```#frameOption``` and ```#transportSecurity```.
```javascript
{
  frameOption: String,
  transportSecurity: {
    seconds:Number,
    hasSubdomains:Boolean
  }
}
```
```javascript
var headgear = require('headgear');
var options = {
  frameOption: 'sameorigin',
  transportSecurity: {
    seconds: 31536000,
    hasSubdomains: true
  }
};
app.use(headgear.all(options));
```

### Links
-----------------------------------------------------

* https://www.owasp.org/index.php/List_of_useful_HTTP_headers
* https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
* http://www.html5rocks.com/en/tutorials/security/content-security-policy/
* http://content-security-policy.com/
* https://developer.mozilla.org/en-US/docs/Web/Security/CSP/CSP_policy_directives
* https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning


### License
-----------------------------------------------------

Headgear is licensed under the MIT license.

Copyright (c) 2015 Bryan Kizer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
