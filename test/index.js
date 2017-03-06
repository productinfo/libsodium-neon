var Jasmine = require('jasmine');
var jasmine = new Jasmine();

jasmine.loadConfigFile('test/support/jasmine.json');
jasmine.execute();
