'use strict';

var dashify = require('dashify');

// Taken from
// https://www.owasp.org/index.php/List_of_useful_HTTP_headers
// https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
// http://www.html5rocks.com/en/tutorials/security/content-security-policy/
// http://content-security-policy.com/
// https://developer.mozilla.org/en-US/docs/Web/Security/CSP/CSP_policy_directives

var Headgear = function() {};


/**
 * Removes the powered by header.
 */
Headgear.prototype.removePoweredBy = function() {
  return function(request, response, next) {
    response.removeHeader('X-Powered-By');
    next();
  };
};


/**
 * Sets the content type option to nosniff.
 */
Headgear.prototype.noSniff = function() {
  return function(request, response, next) {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  };
};


/**
 * Sets the frame option header.
 * @param  {String} option  The option string.
 * @param  {String} allowed The allowed from url.
 */
Headgear.prototype.frameOption = function(option, allowed) {
  var available = ['deny', 'sameorigin', 'allow-from', 'allowall'];
  option = option || 'sameorigin';

  if(!~available.indexOf(option)) {
    throw new Error('option can only be deny, sameorigin, allow-from or allowall');
  }

  if(option === 'allow-from') {
    if(typeof allowed !== 'string') {
      throw new Error('allowed must be a string');
    }
    else {
      option = option + ' ' + allowed;
      return function(request, response, next) {
        response.setHeader('X-Frame-Options', option);
        response.setHeader('Frame-Options', option);
        next();
      };
    }
  }
  else {
    return function(request, response, next) {
      response.setHeader('X-Frame-Options', option);
      response.setHeader('Frame-Options', option);
      next();
    };
  }
};


/**
 * Sets the download option to noopen.
 */
Headgear.prototype.downloadOption = function() {
  return function(request, response, next) {
    response.setHeader('X-Download-Options', 'noopen');
    next();
  };
};


/**
 * Sets the transport security header.
 * @param  {Number} seconds          The number of seconds to continue using HTTPS.
 * @param  {Boolean} withSubdomains  Whether or not to include subdomains.
 */
Headgear.prototype.transportSecurity = function(seconds, withSubdomains) {
  seconds = seconds || 31536000;
  withSubdomains = withSubdomains == null ? true : withSubdomains;

  return function(request, response, next) {
    var val = 'max-age=' + seconds;

    if(withSubdomains) {
      response.setHeader('Strict-Transport-Security', val + '; includeSubDomains;');
    }
    else {
      response.setHeader('Strict-Transport-Security',  val);
    }

    next();
  };
};


/**
 * Sets the xss protection header.
 */
Headgear.prototype.xssProtect = function() {
  return function(request, response, next) {
    response.setHeader('X-XSS-Protection', '1; mode=block;');
    next();
  };
};


/**
 * Sets the cache control header to no-cache.
 */
Headgear.prototype.noCache = function() {
  return function(request, response, next) {
    response.setHeader('Cache-Control', 'no-cache');
    next();
  };
};


/**
 * Sets the content security policy header.
 * @param  {Object} options The object containing the header options.
 */
Headgear.prototype.contentSecurity = function(options) {
  if(options === null) {
    throw new Error('options can not be null');
  }

  if(typeof options !== 'object') {
    throw new Error('options must be an object');
  }

  var needWrapped = ['none', 'self', 'unsafe-inline', 'unsafe-eval'];
  var reportOnly = options.report;
  delete options.report;

  var applied = {};
  var result = '';
  Object.keys(options).forEach(function(key) {
    if(!applied[key]) {
      applied[key] = true;
      var val = dashify(key) + ' ';

      if(key === 'upgradeInsecureRequests') {
        if(options[key]) {
          val += '1; ';
        }
        else {
          val += '0; ';
        }
      }
      else {
        if(Array.isArray(options[key])) {
          for(var i=0, len=options[key].length; i < len; i++) {
            if(~needWrapped.indexOf(options[key][i])) {
              options[key][i] = '\'' + options[key][i] + '\'';
            }
          }

          val += options[key].join(' ') + '; ';
        }
        else {
          val += options[key] + '; ';
        }
      }

      result += val;
    }
  });

  return function(request, response, next) {
    if(reportOnly) {
      response.setHeader('Content-Security-Policy-Report-Only', result);
    }
    else {
      response.setHeader('Content-Security-Policy', result);
    }

    next();
  };
};


/**
 * Sets several of the above headers.
 * @param  {Object} options The config object.
 */
Headgear.prototype.all = function(options) {
  if(options === null) {
    throw new Error('options can not be null');
  }

  var _this = this;
  var connect = require('connect');
  var con = connect();
  con.use(_this.removePoweredBy());
  con.use(_this.noSniff());
  con.use(_this.downloadOption());
  con.use(_this.xssProtect());
  con.use(_this.frameOption(options.frameOption));
  con.use(_this.transportSecurity(options.transportSecurity.seconds, options.transportSecurity.hasSubdomains));

  return con;
};



module.exports = new Headgear();
